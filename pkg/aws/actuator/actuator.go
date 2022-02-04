/*
Copyright 2018 The OpenShift Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package actuator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"

	log "github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	ccaws "github.com/openshift/cloud-credential-operator/pkg/aws"
	minteraws "github.com/openshift/cloud-credential-operator/pkg/aws"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	actuatoriface "github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/actuator"
	awsannotator "github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/aws"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
	awsutils "github.com/openshift/cloud-credential-operator/pkg/operator/utils/aws"
)

const (
	roAWSCredsSecretNamespace = "openshift-cloud-credential-operator"
	roAWSCredsSecret          = "cloud-credential-operator-iam-ro-creds"
	openshiftClusterIDKey     = "openshiftClusterID"
	clusterVersionObjectName  = "version"

	secretDataAccessKey = "aws_access_key_id"
	secretDataSecretKey = "aws_secret_access_key"
)

var _ actuatoriface.Actuator = (*AWSActuator)(nil)

// AWSActuator implements the CredentialsRequest Actuator interface to create credentials in AWS.
type AWSActuator struct {
	Client           client.Client
	Codec            *minterv1.ProviderCodec
	AWSClientBuilder func(accessKeyID, secretAccessKey []byte, c client.Client) (ccaws.Client, error)
	Scheme           *runtime.Scheme
}

// NewAWSActuator creates a new AWSActuator.
func NewAWSActuator(client client.Client, scheme *runtime.Scheme) (*AWSActuator, error) {
	codec, err := minterv1.NewCodec()
	if err != nil {
		log.WithError(err).Error("error creating AWS codec")
		return nil, fmt.Errorf("error creating AWS codec: %v", err)
	}

	return &AWSActuator{
		Codec:            codec,
		Client:           client,
		AWSClientBuilder: awsutils.ClientBuilder,
		Scheme:           scheme,
	}, nil
}

func DecodeProviderStatus(codec *minterv1.ProviderCodec, cr *minterv1.CredentialsRequest) (*minterv1.AWSProviderStatus, error) {
	awsStatus := minterv1.AWSProviderStatus{}
	var err error
	if cr.Status.ProviderStatus == nil {
		return &awsStatus, nil
	}

	err = codec.DecodeProviderStatus(cr.Status.ProviderStatus, &awsStatus)
	if err != nil {
		return nil, fmt.Errorf("error decoding v1 provider status: %v", err)
	}
	return &awsStatus, nil
}

func DecodeProviderSpec(codec *minterv1.ProviderCodec, cr *minterv1.CredentialsRequest) (*minterv1.AWSProviderSpec, error) {
	if cr.Spec.ProviderSpec != nil {
		awsSpec := minterv1.AWSProviderSpec{}
		err := codec.DecodeProviderSpec(cr.Spec.ProviderSpec, &awsSpec)
		if err != nil {
			return nil, fmt.Errorf("error decoding provider v1 spec: %v", err)
		}
		return &awsSpec, nil
	}

	return nil, fmt.Errorf("no providerSpec defined")
}

// Checks if the credentials currently exist.
//
// To do this we will check if the target secret exists. This call is only used to determine
// if we're doing a Create or an Update, but in the context of this acutator it makes no
// difference. As such we will not check if the user exists in AWS and is correctly configured
// as this will all be handled in both Create and Update.
func (a *AWSActuator) Exists(ctx context.Context, cr *minterv1.CredentialsRequest) (bool, error) {
	logger := a.getLogger(cr)
	logger.Debug("running Exists")
	var err error
	if isAWS, err := isAWSCredentials(cr.Spec.ProviderSpec); !isAWS {
		return false, err
	}

	existingSecret := &corev1.Secret{}
	err = a.Client.Get(context.TODO(), types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, existingSecret)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Debug("target secret does not exist")
			return false, nil
		}
		return false, err
	}

	logger.Debug("target secret exists")
	return true, nil

}

// needsUpdate will return whether the current credentials satisfy what's being requested
// in the CredentialsRequest
func (a *AWSActuator) needsUpdate(ctx context.Context, cr *minterv1.CredentialsRequest) (bool, error) {
	logger := a.getLogger(cr)
	// If the secret simply doesn't exist, we definitely need an update
	exists, err := a.Exists(ctx, cr)
	if err != nil {
		return true, err
	}
	if !exists {
		return true, nil
	}

	// Various checks for the kinds of reasons that would trigger a needed update
	_, existingAccessKey, existingSecretKey, existingCredentialsKey := a.loadExistingSecret(cr)
	awsClient, err := a.AWSClientBuilder([]byte(existingAccessKey), []byte(existingSecretKey), a.Client)
	if err != nil {
		return true, err
	}

	// Make sure we update old Secrets that don't have the new "credentials" field
	if existingCredentialsKey == "" || existingCredentialsKey != string(generateAWSCredentialsConfig(existingAccessKey, existingSecretKey)) {
		logger.Infof("Secret %s key needs updating, will update Secret contents", constants.AWSSecretDataCredentialsKey)
		return true, nil
	}

	awsSpec, err := DecodeProviderSpec(a.Codec, cr)
	if err != nil {
		return true, err
	}

	awsStatus, err := DecodeProviderStatus(a.Codec, cr)
	if err != nil {
		return true, fmt.Errorf("unable to decode ProviderStatus: %v", err)
	}

	// Minted-user-specific checks
	if awsStatus.User != "" {
		readAWSClient, err := a.buildReadAWSClient(cr)
		if err != nil {
			log.WithError(err).Error("error creating read-only AWS client")
			return true, fmt.Errorf("unable to check whether AWS user is properly tagged")
		}

		// If AWS user defined (ie minted creds instead of passthrough) check whether user is tagged
		user, err := readAWSClient.GetUser(&iam.GetUserInput{
			UserName: aws.String(awsStatus.User),
		})
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case iam.ErrCodeNoSuchEntityException:
					// Current user does not exist, we unset the user in the status and create a new one
					logger.Errorf("user %s does not exist, creating a new user", awsStatus.User)
					awsStatus.User = ""
					return true, nil
				default:
					return true, formatAWSErr(aerr)
				}
			}
			logger.WithError(err).Errorf("unknown error getting user: %s", user)
			return true, fmt.Errorf("unable to read info for username %v: %v", user, err)
		}

		clusterUUID, err := a.loadClusterUUID(logger)
		if err != nil {
			return true, err
		}

		infra, err := utils.GetInfrastructure(a.Client)
		if err != nil {
			return true, err
		}

		if !userHasExpectedTags(logger, user.User, string(clusterUUID), infra) {
			return true, nil
		}

		// Does the access key in the secret still exist?
		logger.Debug("NeedsUpdate ListAccessKeys")
		allUserKeys, err := readAWSClient.ListAccessKeys(&iam.ListAccessKeysInput{UserName: aws.String(awsStatus.User)})
		if err != nil {
			logger.WithError(err).Error("error listing all access keys for user")
			return false, err
		}
		accessKeyExists, err := a.accessKeyExists(logger, allUserKeys, existingAccessKey)
		if err != nil {
			logger.WithError(err).Error("error querying whether access key still valid")
		}
		if !accessKeyExists {
			// then we need an update
			return true, nil
		}

		// Check whether the current policy attached to the creds match what is being requested
		desiredUserPolicy, err := a.getDesiredUserPolicy(awsSpec.StatementEntries, *user.User.Arn)
		if err != nil {
			return false, err
		}

		policyEqual, err := a.awsPolicyEqualsDesiredPolicy(desiredUserPolicy, awsSpec, awsStatus, user.User, readAWSClient, logger)
		if err != nil {
			return true, err
		}
		if !policyEqual {
			return true, nil
		}

	} else {
		// for passthrough creds, just see if root cloud creds have not changed and
		// we have the permissions requested in the credentials request

		// but for the case where the operator mode is non-default, then we will avoid performing any
		// policy simulations and assume that the passthrough creds must be good enough

		credentialsRootSecret, err := a.GetCredentialsRootSecret(ctx, cr)
		if err != nil {
			log.WithError(err).Debug("error retrieving cloud credentials secret")
			return false, err
		}
		// If the cloud credentials secret has been updated in passthrough mode, we need an update
		if credentialsRootSecret != nil && credentialsRootSecret.ResourceVersion != cr.Status.LastSyncCloudCredsSecretResourceVersion {
			logger.Debug("root cloud creds have changed, update is needed")
			return true, nil
		}

		mode, _, err := utils.GetOperatorConfiguration(a.Client, logger)
		if err != nil {
			return true, err
		}
		if mode == operatorv1.CloudCredentialsModePassthrough {
			logger.Debug("will not perform permissions simulation because operator in mode %q", mode)
		} else {
			region, err := awsutils.LoadInfrastructureRegion(a.Client, logger)
			if err != nil {
				return true, err
			}
			simParams := &ccaws.SimulateParams{
				Region: region,
			}

			goodEnough, err := ccaws.CheckPermissionsAgainstStatementList(awsClient, awsSpec.StatementEntries, simParams, logger)
			if err != nil {
				return true, fmt.Errorf("error validating whether current creds are good enough: %v", err)
			}
			if !goodEnough {
				return true, nil
			}
		}
	}

	// If we've made it this far, then there are no updates needed
	return false, nil
}

// Create the credentials.
func (a *AWSActuator) Create(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	return a.sync(ctx, cr)
}

// Update the credentials to the provided definition.
func (a *AWSActuator) Update(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	return a.sync(ctx, cr)
}

func (a *AWSActuator) sync(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	if isAWS, err := isAWSCredentials(cr.Spec.ProviderSpec); !isAWS {
		return err
	}
	logger := a.getLogger(cr)
	logger.Debug("running sync")

	// Should we update anything
	needsUpdate, err := a.needsUpdate(ctx, cr)
	if err != nil {
		logger.WithError(err).Error("error determining whether a credentials update is needed")
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   "error determining whether a credentials update is needed",
		}
	}

	if !needsUpdate {
		logger.Debug("credentials already up to date")
		return nil
	}

	credentialsRootSecret, err := a.GetCredentialsRootSecret(ctx, cr)
	if err != nil {
		logger.WithError(err).Error("issue with cloud credentials secret")
		return err
	}

	switch credentialsRootSecret.Annotations[constants.AnnotationKey] {
	case constants.InsufficientAnnotation:
		msg := "cloud credentials insufficient to satisfy credentials request"
		logger.Error(msg)
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.InsufficientCloudCredentials,
			Message:   msg,
		}
	case constants.PassthroughAnnotation:
		logger.Debugf("provisioning with passthrough")
		err := a.syncPassthrough(ctx, cr, credentialsRootSecret, logger)
		if err != nil {
			return err
		}
	case constants.MintAnnotation:
		logger.Debugf("provisioning with cred minting")
		err := a.syncMint(ctx, cr, logger)
		if err != nil {
			msg := "error syncing creds in mint-mode"
			logger.WithError(err).Error(msg)
			return &actuatoriface.ActuatorError{
				ErrReason: minterv1.CredentialsProvisionFailure,
				Message:   fmt.Sprintf("%v: %v", msg, err),
			}
		}
	default:
		msg := fmt.Sprintf("unexpected value or missing %s annotation on admin credentials Secret", constants.AnnotationKey)
		logger.Info(msg)
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   msg,
		}
	}

	return nil
}

func (a *AWSActuator) syncPassthrough(ctx context.Context, cr *minterv1.CredentialsRequest, cloudCredsSecret *corev1.Secret, logger log.FieldLogger) error {
	existingSecret, _, _, _ := a.loadExistingSecret(cr)
	accessKeyID := string(cloudCredsSecret.Data[awsannotator.AwsAccessKeyName])
	secretAccessKey := string(cloudCredsSecret.Data[awsannotator.AwsSecretAccessKeyName])

	mode, _, err := utils.GetOperatorConfiguration(a.Client, logger)
	if err != nil {
		msg := "error getting operator configuration"
		logger.WithError(err).Error(msg)
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   fmt.Sprintf("%v: %v", msg, err),
		}
	}
	if mode == operatorv1.CloudCredentialsModePassthrough {
		logger.Debug("will not perform permissions simulation because operator in mode %q", mode)
	} else {
		region, err := awsutils.LoadInfrastructureRegion(a.Client, logger)
		if err != nil {
			msg := "error reading region from Infrastructure CR"
			logger.WithError(err).Error(msg)
			return &actuatoriface.ActuatorError{
				ErrReason: minterv1.CredentialsProvisionFailure,
				Message:   fmt.Sprintf("%v: %v", msg, err),
			}
		}

		simParams := &ccaws.SimulateParams{
			Region: region,
		}

		// build client with root secret and verify that the creds are good enough to pass through
		awsClient, err := a.AWSClientBuilder([]byte(accessKeyID), []byte(secretAccessKey), a.Client)
		if err != nil {
			msg := "error building AWS client"
			logger.WithError(err).Error(msg)
			return &actuatoriface.ActuatorError{
				ErrReason: minterv1.CredentialsProvisionFailure,
				Message:   fmt.Sprintf("%v: %v", msg, err),
			}
		}

		awsSpec, err := DecodeProviderSpec(a.Codec, cr)
		if err != nil {
			msg := "error decoding AWS ProviderSpec"
			logger.WithError(err).Error(msg)
			return &actuatoriface.ActuatorError{
				ErrReason: minterv1.CredentialsProvisionFailure,
				Message:   fmt.Sprintf("%v: %v", msg, err),
			}
		}
		goodEnough, err := ccaws.CheckPermissionsAgainstStatementList(awsClient, awsSpec.StatementEntries, simParams, logger)
		if err != nil {
			msg := "error validating whether root creds are good enough"
			logger.WithError(err).Error(msg)
			return &actuatoriface.ActuatorError{
				ErrReason: minterv1.CredentialsProvisionFailure,
				Message:   fmt.Sprintf("%v: %v", msg, err),
			}
		}
		if !goodEnough {
			msg := "root creds are not sufficient"
			logger.Info(msg)
			return &actuatoriface.ActuatorError{
				ErrReason: minterv1.CredentialsProvisionFailure,
				Message:   fmt.Sprintf("%v", msg),
			}
		}
	}

	// userPolicy param empty because in passthrough mode this doesn't really have any meaning
	err = a.syncAccessKeySecret(cr, accessKeyID, secretAccessKey, existingSecret, "", logger)
	if err != nil {
		msg := "error creating/updating secret"
		logger.WithError(err).Error(msg)
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   fmt.Sprintf("%v: %v", msg, err),
		}
	}

	return nil
}

// syncMint handles both create and update idempotently.
func (a *AWSActuator) syncMint(ctx context.Context, cr *minterv1.CredentialsRequest, logger log.FieldLogger) error {
	var err error

	awsSpec, err := DecodeProviderSpec(a.Codec, cr)
	if err != nil {
		return err
	}

	awsStatus, err := DecodeProviderStatus(a.Codec, cr)
	if err != nil {
		return err
	}

	// checking if the infrastructure resource can be fetched.
	infra, err := utils.GetInfrastructure(a.Client)
	if err != nil {
		return err
	}

	// Generate a randomized User for the credentials:
	// TODO: check if the generated name is free
	if awsStatus.User == "" {
		username, err := generateUserName(infra.Status.InfrastructureName, cr.Name)
		if err != nil {
			return err
		}
		awsStatus.User = username
		awsStatus.Policy = getPolicyName(username)
		logger.WithField("user", awsStatus.User).Debug("generated random name for AWS user and policy")
		err = a.updateProviderStatus(ctx, logger, cr, awsStatus)
		if err != nil {
			return err
		}

	}

	if awsStatus.Policy == "" && awsStatus.User != "" {
		awsStatus.Policy = getPolicyName(awsStatus.User)
		err = a.updateProviderStatus(ctx, logger, cr, awsStatus)
		if err != nil {
			return err
		}
	}

	rootAWSClient, err := a.buildRootAWSClient(cr)
	if err != nil {
		logger.WithError(err).Warn("error building root AWS client, will error if one must be used")
	}

	readAWSClient, err := a.buildReadAWSClient(cr)
	if err != nil {
		logger.WithError(err).Error("error building read-only AWS client")
		return err
	}

	// Check if the user already exists:
	var userOut *iam.User
	getUserOut, err := readAWSClient.GetUser(&iam.GetUserInput{UserName: aws.String(awsStatus.User)})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				logger.WithField("userName", awsStatus.User).Debug("user does not exist, creating")
				if rootAWSClient == nil {
					return fmt.Errorf("no root AWS client available, cred secret may not exist: %s/%s", constants.CloudCredSecretNamespace, constants.AWSCloudCredSecretName)
				}

				createOut, err := a.createUser(logger, rootAWSClient, awsStatus.User)
				if err != nil {
					return err
				}
				logger.WithField("userName", awsStatus.User).Info("user created successfully")
				userOut = createOut.User

			default:
				return formatAWSErr(aerr)
			}
		} else {
			return fmt.Errorf("unknown error getting user from AWS: %v", err)
		}
	} else {
		logger.WithField("userName", awsStatus.User).Info("user exists")
		userOut = getUserOut.User
	}

	clusterUUID, err := a.loadClusterUUID(logger)
	if err != nil {
		return err
	}

	// Check if the user has the expected tags:
	if !userHasExpectedTags(logger, userOut, string(clusterUUID), infra) {
		if rootAWSClient == nil {
			return fmt.Errorf("no root AWS client available, cred secret may not exist: %s/%s", constants.CloudCredSecretNamespace, constants.AWSCloudCredSecretName)
		}

		err = a.tagUser(logger, rootAWSClient, awsStatus.User, string(clusterUUID), infra)
		if err != nil {
			return err
		}
	}

	// TODO: check if user policy needs to be set? user generation and last set time.
	desiredUserPolicy, err := a.getDesiredUserPolicy(awsSpec.StatementEntries, *userOut.Arn)
	if err != nil {
		return err
	}

	policyEqual, err := a.awsPolicyEqualsDesiredPolicy(desiredUserPolicy, awsSpec, awsStatus, userOut, readAWSClient, logger)
	if !policyEqual {
		if rootAWSClient == nil {
			return fmt.Errorf("no root AWS client available, cred secret may not exist: %s/%s", constants.CloudCredSecretNamespace, constants.AWSCloudCredSecretName)
		}
		err = a.setUserPolicy(logger, rootAWSClient, awsStatus.User, awsStatus.Policy, desiredUserPolicy)
		if err != nil {
			return err
		}
		logger.Info("successfully set user policy")
	}

	logger.Debug("sync ListAccessKeys")
	allUserKeys, err := readAWSClient.ListAccessKeys(&iam.ListAccessKeysInput{UserName: aws.String(awsStatus.User)})
	if err != nil {
		logger.WithError(err).Error("error listing all access keys for user")
		return err
	}

	existingSecret, existingAccessKeyID, _, _ := a.loadExistingSecret(cr)

	var accessKey *iam.AccessKey
	// TODO: also check if the access key ID on the request is still valid in AWS
	accessKeyExists, err := a.accessKeyExists(logger, allUserKeys, existingAccessKeyID)
	if err != nil {
		return err
	}
	logger.WithField("accessKeyID", existingAccessKeyID).Debugf("access key exists? %v", accessKeyExists)

	if existingSecret != nil && existingSecret.Name != "" {
		_, ok := existingSecret.Annotations[minterv1.AnnotationAWSPolicyLastApplied]
		if !ok {
			logger.Warnf("target secret missing policy annotation: %s", minterv1.AnnotationAWSPolicyLastApplied)
		}
	}

	genNewAccessKey := existingSecret == nil || existingSecret.Name == "" || existingAccessKeyID == "" || !accessKeyExists
	if genNewAccessKey {
		logger.Info("generating new AWS access key")

		// Users are allowed a max of two keys, if we decided we need to generate one,
		// we should cleanup all pre-existing access keys. This will allow deleting the
		// secret in Kubernetes to revoke old credentials and create new.
		if rootAWSClient == nil {
			return fmt.Errorf("no root AWS client available, cred secret may not exist: %s/%s", constants.CloudCredSecretNamespace, constants.AWSCloudCredSecretName)
		}
		err := a.deleteAllAccessKeys(logger, rootAWSClient, awsStatus.User, allUserKeys)
		if err != nil {
			return err
		}

		accessKey, err = a.createAccessKey(logger, rootAWSClient, awsStatus.User)
		if err != nil {
			logger.WithError(err).Error("error creating AWS access key")
			return err
		}
	}

	accessKeyString := ""
	secretAccessKeyString := ""
	if accessKey != nil {
		accessKeyString = *accessKey.AccessKeyId
		secretAccessKeyString = *accessKey.SecretAccessKey
	}
	err = a.syncAccessKeySecret(cr, accessKeyString, secretAccessKeyString, existingSecret, desiredUserPolicy, logger)
	if err != nil {
		log.WithError(err).Error("error saving access key to secret")
		return err
	}

	return nil
}

func (a *AWSActuator) awsPolicyEqualsDesiredPolicy(desiredUserPolicy string, awsSpec *minterv1.AWSProviderSpec, awsStatus *minterv1.AWSProviderStatus, awsUser *iam.User, readAWSClient ccaws.Client, logger log.FieldLogger) (bool, error) {

	currentUserPolicy, err := a.getCurrentUserPolicy(logger, readAWSClient, awsStatus.User, awsStatus.Policy)
	if err != nil {
		return false, err
	}
	logger.Debugf("desired user policy: %s", desiredUserPolicy)
	logger.Debugf("current user policy: %s", currentUserPolicy)
	if currentUserPolicy != desiredUserPolicy {
		logger.Debug("policy differences detected")
		return false, nil
	}
	logger.Debug("no changes to user policy")
	return true, nil
}

func userHasExpectedTags(logger log.FieldLogger, user *iam.User, clusterUUID string, infraResource *configv1.Infrastructure) bool {
	// Check if the user has the expected tags:
	if user == nil {
		return false
	}

	// Check if the user has the expected tags from the Infrastructure resource
	if infraResource != nil {
		if infraResource.Spec.PlatformSpec.AWS != nil {
			if len(infraResource.Spec.PlatformSpec.AWS.ResourceTags) != 0 {
				for _, userTag := range infraResource.Spec.PlatformSpec.AWS.ResourceTags {
					if !userHasTag(user, userTag.Key, userTag.Value) {
						log.Infof("user missing tag: %s=%s", userTag.Key, userTag.Value)
						return false
					}
				}
			}
		}
	}

	if infraResource.Status.InfrastructureName != "" {
		clusterTag := fmt.Sprintf("kubernetes.io/cluster/%s", infraResource.Status.InfrastructureName)
		if !userHasTag(user, clusterTag, "owned") {
			log.Warnf("user missing tag: %s=%s", clusterTag, "owned")
			return false
		}
	} else {
		logger.Warn("Infrastructure 'cluster' has no status.infrastructureName set. (likely beta3 cluster)")
		// This is a legacy tag being kept for compatability with beta3, which would not have
		// had any infrastructure name set. Deprovision code still searches for anything with this
		// tag, so if no infra name is set we skip that tag and rely on this one for cleanup.
		if !userHasTag(user, openshiftClusterIDKey, clusterUUID) {
			log.Warnf("user missing tag: %s=%s", openshiftClusterIDKey, clusterUUID)
			return false
		}

	}

	return true
}
func (a *AWSActuator) updateProviderStatus(ctx context.Context, logger log.FieldLogger, cr *minterv1.CredentialsRequest, awsStatus *minterv1.AWSProviderStatus) error {

	var err error
	cr.Status.ProviderStatus, err = a.Codec.EncodeProviderStatus(awsStatus)
	if err != nil {
		logger.WithError(err).Error("error encoding provider status")
		return err
	}

	if cr.Status.Conditions == nil {
		cr.Status.Conditions = []minterv1.CredentialsRequestCondition{}
	}

	err = a.Client.Status().Update(ctx, cr)
	if err != nil {
		logger.WithError(err).Error("error updating credentials request status")
		return err
	}
	return nil
}

// Delete the credentials. If no error is returned, it is assumed that all dependent resources have been cleaned up.
func (a *AWSActuator) Delete(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	if isAWS, err := isAWSCredentials(cr.Spec.ProviderSpec); !isAWS {
		return err
	}
	logger := a.getLogger(cr)
	logger.Debug("running Delete")
	var err error
	awsStatus, err := DecodeProviderStatus(a.Codec, cr)
	if err != nil {
		return err
	}

	if awsStatus.User == "" {
		logger.Warn("no user name set on credentials being deleted, most likely were never provisioned or using passthrough creds")
		return nil
	}
	logger = logger.WithField("userName", awsStatus.User)

	logger.Info("deleting credential from AWS")

	awsClient, err := a.buildRootAWSClient(cr)
	if err != nil {
		return err
	}
	_, err = awsClient.DeleteUserPolicy(&iam.DeleteUserPolicyInput{
		UserName:   aws.String(awsStatus.User),
		PolicyName: aws.String(awsStatus.Policy),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				logger.Warn("user policy does not exist, ignoring error")
			default:
				return formatAWSErr(aerr)
			}
		} else {
			return fmt.Errorf("unknown error deleting user policy from AWS: %v", err)
		}
	}
	logger.Info("user policy deleted")

	logger.Debug("Delete ListAccessKeys")
	allUserKeys, err := awsClient.ListAccessKeys(&iam.ListAccessKeysInput{UserName: aws.String(awsStatus.User)})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				logger.Warn("error listing access keys, user does not exist, returning success")
				return nil
			default:
				logger.WithError(err).Error("error listing all access keys for user")
				return formatAWSErr(aerr)
			}
		}
		logger.WithError(err).Error("error listing all access keys for user")
		return err
	}

	err = a.deleteAllAccessKeys(logger, awsClient, awsStatus.User, allUserKeys)
	if err != nil {
		return err
	}

	_, err = awsClient.DeleteUser(&iam.DeleteUserInput{
		UserName: aws.String(awsStatus.User),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				logger.Warn("user does not exist, returning success")
			default:
				return formatAWSErr(aerr)
			}
		} else {
			return fmt.Errorf("unknown error deleting user from AWS: %v", err)
		}
	}
	logger.Info("user deleted")

	return nil
}

func (a *AWSActuator) loadExistingSecret(cr *minterv1.CredentialsRequest) (*corev1.Secret, string, string, string) {
	logger := a.getLogger(cr)
	var existingAccessKeyID string
	var existingSecretAccessKey string
	var existingCredentialsKey string

	// Check if the credentials secret exists, if not we need to inform the syncer to generate a new one:
	existingSecret := &corev1.Secret{}
	err := a.Client.Get(context.TODO(), types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, existingSecret)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Debug("secret does not exist")
		}
	} else {
		keyBytes, ok := existingSecret.Data[secretDataAccessKey]
		if !ok {
			// Warn, but this will trigger generation of a new key and updating the secret.
			logger.Warningf("secret did not have expected key: %s, will be regenerated", secretDataAccessKey)
		} else {
			decoded := string(keyBytes)
			existingAccessKeyID = string(decoded)
			logger.WithField("accessKeyID", existingAccessKeyID).Debug("found access key ID in target secret")

		}

		secretBytes, ok := existingSecret.Data[secretDataSecretKey]
		if !ok {
			logger.Warningf("secret did not have expected key: %s", secretDataSecretKey)
		} else {
			existingSecretAccessKey = string(secretBytes)
		}

		credentialsKey, ok := existingSecret.Data[constants.AWSSecretDataCredentialsKey]
		if !ok {
			logger.Warningf("secret did not have expected key: %s, will be updated", constants.AWSSecretDataCredentialsKey)
		} else {
			existingCredentialsKey = string(credentialsKey)
		}
	}
	return existingSecret, existingAccessKeyID, existingSecretAccessKey, existingCredentialsKey
}

func (a *AWSActuator) tagUser(logger log.FieldLogger, awsClient minteraws.Client, username, clusterUUID string, infra *configv1.Infrastructure) error {
	logger.WithField("infraName", infra.Status.InfrastructureName).Info("tagging user with infrastructure name")
	tags := []*iam.Tag{}
	if infra.Status.InfrastructureName != "" {
		tags = append(tags, &iam.Tag{
			Key:   aws.String(fmt.Sprintf("kubernetes.io/cluster/%s", infra.Status.InfrastructureName)),
			Value: aws.String("owned"),
		})
	} else {
		tags = append(tags, &iam.Tag{
			Key:   aws.String(openshiftClusterIDKey),
			Value: aws.String(clusterUUID),
		})
	}

	// appending the tags present in the Infrastructure CR
	if infra.Spec.PlatformSpec.AWS != nil {
		if len(infra.Spec.PlatformSpec.AWS.ResourceTags) != 0 {
			logger.WithField("userTags", infra.Spec.PlatformSpec.AWS.ResourceTags).Info("tagging the user with the tags present in the infrastructure object")
			for _, userTag := range infra.Spec.PlatformSpec.AWS.ResourceTags {
				tags = append(tags, &iam.Tag{
					Key:   aws.String(userTag.Key),
					Value: aws.String(userTag.Value),
				})
			}
		}
	}
	_, err := awsClient.TagUser(&iam.TagUserInput{
		UserName: aws.String(username),
		Tags:     tags,
	})
	if err != nil {
		logger.WithError(err).Error("unable to tag user")
		return err
	}
	return nil
}

// buildRootAWSClient will return an AWS client using the "root" AWS creds which are expected to
// live in kube-system/aws-creds.
func (a *AWSActuator) buildRootAWSClient(cr *minterv1.CredentialsRequest) (minteraws.Client, error) {
	logger := a.getLogger(cr).WithField("secret", fmt.Sprintf("%s/%s", constants.CloudCredSecretNamespace, constants.AWSCloudCredSecretName))

	logger.Debug("loading AWS credentials from secret")
	// TODO: Running in a 4.0 cluster we expect this secret to exist. When we run in a Hive
	// cluster, we need to load different secrets for each cluster.
	accessKeyID, secretAccessKey, err := utils.LoadCredsFromSecret(a.Client, constants.CloudCredSecretNamespace, constants.AWSCloudCredSecretName)
	if err != nil {
		return nil, err
	}

	logger.Debug("creating root AWS client")
	return a.AWSClientBuilder(accessKeyID, secretAccessKey, a.Client)
}

// buildReadAWSClient will return an AWS client using the the scaled down read only AWS creds
// for cred minter, which are expected to live in openshift-cloud-credential-operator/cloud-credential-operator-iam-ro-creds.
// These creds would normally be created by cred minter itself, via a CredentialsRequest created
// by the cred minter operator.
//
// If these are not available but root creds are, we will use the root creds instead.
// This allows us to create the read creds initially.
func (a *AWSActuator) buildReadAWSClient(cr *minterv1.CredentialsRequest) (minteraws.Client, error) {
	logger := a.getLogger(cr).WithField("secret", fmt.Sprintf("%s/%s", roAWSCredsSecretNamespace, roAWSCredsSecret))
	logger.Debug("loading AWS credentials from secret")

	var accessKeyID, secretAccessKey []byte
	var err error

	// TODO: Running in a 4.0 cluster we expect this secret to exist. When we run in a Hive
	// cluster, we need to load different secrets for each cluster.
	accessKeyID, secretAccessKey, err = utils.LoadCredsFromSecret(a.Client, roAWSCredsSecretNamespace, roAWSCredsSecret)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Warn("read-only creds not found, using root creds client")
			return a.buildRootAWSClient(cr)
		}
		logger.WithError(err).Error("unexpected error while trying to load in read-only creds Secret")
		return nil, err
	}

	logger.Debug("creating read AWS client")
	client, err := a.AWSClientBuilder(accessKeyID, secretAccessKey, a.Client)
	if err != nil {
		return nil, err
	}

	// Test if the read-only client is working, if any error here we will fall back to using
	// the root client.
	// and if our RO user is not yet live, we should just fall back to using the root user
	// if possible.
	awsStatus, err := DecodeProviderStatus(a.Codec, cr)
	if err != nil {
		return nil, err
	}
	_, err = client.GetUser(&iam.GetUserInput{UserName: aws.String(awsStatus.User)})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "InvalidClientTokenId":
				logger.Warn("InvalidClientTokenId for read-only AWS account, likely a propagation delay, falling back to root AWS client")
				return a.buildRootAWSClient(cr)
			}
			// Any other error we just let following code sort out.
		}
	}
	return client, nil
}

func (a *AWSActuator) getLogger(cr *minterv1.CredentialsRequest) log.FieldLogger {
	return log.WithFields(log.Fields{
		"actuator": "aws",
		"cr":       fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
	})
}

func (a *AWSActuator) syncAccessKeySecret(cr *minterv1.CredentialsRequest, accessKeyID, secretAccessKey string, existingSecret *corev1.Secret, userPolicy string, logger log.FieldLogger) error {
	sLog := logger.WithFields(log.Fields{
		"targetSecret": fmt.Sprintf("%s/%s", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name),
		"cr":           fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
	})

	if existingSecret == nil || existingSecret.Name == "" {
		if accessKeyID == "" || secretAccessKey == "" {
			msg := "new access key secret needed but no key data provided"
			sLog.Error(msg)
			return &actuatoriface.ActuatorError{
				ErrReason: minterv1.CredentialsProvisionFailure,
				Message:   msg,
			}
		}
		sLog.Info("creating secret")
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cr.Spec.SecretRef.Name,
				Namespace: cr.Spec.SecretRef.Namespace,
				Annotations: map[string]string{
					minterv1.AnnotationCredentialsRequest:   fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
					minterv1.AnnotationAWSPolicyLastApplied: userPolicy,
				},
			},
			Data: map[string][]byte{
				secretDataAccessKey:                   []byte(accessKeyID),
				secretDataSecretKey:                   []byte(secretAccessKey),
				constants.AWSSecretDataCredentialsKey: generateAWSCredentialsConfig(accessKeyID, secretAccessKey),
			},
		}

		err := a.Client.Create(context.TODO(), secret)
		if err != nil {
			sLog.WithError(err).Error("error creating secret")
			return err
		}
		sLog.Info("secret created successfully")
		return nil
	}

	// Update the existing secret:
	sLog.Debug("updating secret")
	origSecret := existingSecret.DeepCopy()
	if existingSecret.Annotations == nil {
		existingSecret.Annotations = map[string]string{}
	}
	existingSecret.Annotations[minterv1.AnnotationCredentialsRequest] = fmt.Sprintf("%s/%s", cr.Namespace, cr.Name)
	existingSecret.Annotations[minterv1.AnnotationAWSPolicyLastApplied] = userPolicy
	if accessKeyID != "" && secretAccessKey != "" {
		existingSecret.Data[secretDataAccessKey] = []byte(accessKeyID)
		existingSecret.Data[secretDataSecretKey] = []byte(secretAccessKey)
	}

	// Make sure credentials config data is synced with the stored access key / secret key
	existingSecret.Data[constants.AWSSecretDataCredentialsKey] = generateAWSCredentialsConfig(string(existingSecret.Data[secretDataAccessKey]), string(existingSecret.Data[secretDataSecretKey]))

	if !reflect.DeepEqual(existingSecret, origSecret) {
		sLog.Info("target secret has changed, updating")
		err := a.Client.Update(context.TODO(), existingSecret)
		if err != nil {
			msg := "error updating secret"
			sLog.WithError(err).Error(msg)
			return &actuatoriface.ActuatorError{
				ErrReason: minterv1.CredentialsProvisionFailure,
				Message:   msg,
			}
		}
	} else {
		sLog.Debug("target secret unchanged")
	}

	return nil
}

func (a *AWSActuator) getDesiredUserPolicy(entries []minterv1.StatementEntry, userARN string) (string, error) {

	policyDoc := PolicyDocument{
		Version:   "2012-10-17",
		Statement: []StatementEntry{},
	}
	for _, se := range entries {
		policyDoc.Statement = append(policyDoc.Statement,
			StatementEntry{
				Effect:    se.Effect,
				Action:    se.Action,
				Resource:  se.Resource,
				Condition: se.PolicyCondition,
			})
	}

	// Always allow a statment that enables iam:GetUser on yourself (to allow access_key/awsClient to username lookups)
	addGetUserStatement(&policyDoc, userARN)

	b, err := json.Marshal(&policyDoc)
	if err != nil {
		return "", fmt.Errorf("error marshalling user policy: %v", err)
	}
	return string(b), nil
}

// GetCredentialsRootSecretLocation returns the namespace and name where the parent credentials secret is stored.
func (a *AWSActuator) GetCredentialsRootSecretLocation() types.NamespacedName {
	return types.NamespacedName{Namespace: constants.CloudCredSecretNamespace, Name: constants.AWSCloudCredSecretName}
}

func (a *AWSActuator) GetCredentialsRootSecret(ctx context.Context, cr *minterv1.CredentialsRequest) (*corev1.Secret, error) {
	logger := a.getLogger(cr)
	cloudCredSecret := &corev1.Secret{}
	if err := a.Client.Get(ctx, a.GetCredentialsRootSecretLocation(), cloudCredSecret); err != nil {
		msg := "unable to fetch root cloud cred secret"
		logger.WithError(err).Error(msg)
		return nil, &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   fmt.Sprintf("%v: %v", msg, err),
		}
	}

	if !isSecretAnnotated(cloudCredSecret) {
		logger.WithField("secret", fmt.Sprintf("%s/%s", constants.CloudCredSecretNamespace, constants.AWSCloudCredSecretName)).Error("cloud cred secret not yet annotated")
		return nil, &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   fmt.Sprintf("cannot proceed without cloud cred secret annotation"),
		}
	}

	return cloudCredSecret, nil
}

func isSecretAnnotated(secret *corev1.Secret) bool {
	if secret.ObjectMeta.Annotations == nil {
		return false
	}

	if _, ok := secret.ObjectMeta.Annotations[constants.AnnotationKey]; !ok {
		return false
	}

	return true
}

func addGetUserStatement(policyDoc *PolicyDocument, userARN string) {

	policyDoc.Statement = append(policyDoc.Statement, StatementEntry{
		Effect:   "Allow",
		Action:   []string{"iam:GetUser"},
		Resource: userARN,
	})
}

func (a *AWSActuator) getCurrentUserPolicy(logger log.FieldLogger, awsReadClient minteraws.Client, userName, policyName string) (string, error) {
	cupOut, err := awsReadClient.GetUserPolicy(&iam.GetUserPolicyInput{
		UserName:   aws.String(userName),
		PolicyName: aws.String(policyName),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				logger.Warn("policy does not exist, creating")
				// Policy doesn't exist, it needs to be created so we will just return empty string.
				// This will not match the desired policy triggering an update.
				return "", nil
			default:
				err = formatAWSErr(aerr)
				logger.WithError(err).Errorf("AWS error getting user policy")
				return "", err
			}
		} else {
			logger.WithError(err).Error("error getting current user policy")
			return "", err
		}
	}
	urlEncoded := *cupOut.PolicyDocument
	currentUserPolicy, err := url.QueryUnescape(urlEncoded)
	if err != nil {
		logger.WithError(err).Error("error URL decoding policy doc")
	}
	return currentUserPolicy, err
}

func (a *AWSActuator) setUserPolicy(logger log.FieldLogger, awsClient minteraws.Client, userName, policyName, userPolicy string) error {

	// This call appears to be idempotent:
	_, err := awsClient.PutUserPolicy(&iam.PutUserPolicyInput{
		UserName:       aws.String(userName),
		PolicyDocument: aws.String(userPolicy),
		PolicyName:     aws.String(policyName),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return formatAWSErr(aerr)
		}
		return fmt.Errorf("unknown error setting user policy in AWS: %v", err)
	}

	return nil
}

func (a *AWSActuator) accessKeyExists(logger log.FieldLogger, allUserKeys *iam.ListAccessKeysOutput, existingAccessKey string) (bool, error) {
	if existingAccessKey == "" {
		return false, nil
	}

	for _, key := range allUserKeys.AccessKeyMetadata {
		if *key.AccessKeyId == existingAccessKey {
			return true, nil
		}
	}
	logger.WithField("accessKeyID", existingAccessKey).Warn("access key no longer exists")
	return false, nil
}

func (a *AWSActuator) deleteAllAccessKeys(logger log.FieldLogger, awsClient minteraws.Client, username string, allUserKeys *iam.ListAccessKeysOutput) error {
	logger.Info("deleting all AWS access keys")
	for _, kmd := range allUserKeys.AccessKeyMetadata {
		akLog := logger.WithFields(log.Fields{
			"accessKeyID": *kmd.AccessKeyId,
		})
		akLog.Info("deleting access key")
		_, err := awsClient.DeleteAccessKey(&iam.DeleteAccessKeyInput{AccessKeyId: kmd.AccessKeyId, UserName: aws.String(username)})
		if err != nil {
			akLog.WithError(err).Error("error deleting access key")
			return err
		}
	}
	logger.Info("all access keys deleted")
	return nil
}

func (a *AWSActuator) createAccessKey(logger log.FieldLogger, awsClient minteraws.Client, username string) (*iam.AccessKey, error) {
	// Check if we need to generate an access key:
	// Create secret and access key for user:
	accessKeyResult, err := awsClient.CreateAccessKey(&iam.CreateAccessKeyInput{
		UserName: &username,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating access key for user %s: %v", username, err)
	}
	logger.WithField("accessKeyID", *accessKeyResult.AccessKey.AccessKeyId).Info("access key created")
	return accessKeyResult.AccessKey, err
}

func userHasTag(user *iam.User, key, val string) bool {
	for _, t := range user.Tags {
		if *t.Key == key && *t.Value == val {
			return true
		}
	}
	return false
}

func (a *AWSActuator) createUser(logger log.FieldLogger, awsClient minteraws.Client, username string) (*iam.CreateUserOutput, error) {
	userInput := &iam.GetUserInput{}
	currentUser, err := awsClient.GetUser(userInput)

	var input *iam.CreateUserInput
	if currentUser != nil && currentUser.User.PermissionsBoundary != nil {
		input = &iam.CreateUserInput{
			UserName:            aws.String(username),
			PermissionsBoundary: currentUser.User.PermissionsBoundary.PermissionsBoundaryArn,
		}
	} else {
		input = &iam.CreateUserInput{
			UserName: aws.String(username),
		}
	}

	uLog := logger.WithField("userName", username)
	uLog.Info("creating user")
	userOut, err := awsClient.CreateUser(input)

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeEntityAlreadyExistsException:
				uLog.Warn("user already exist")
				return nil, nil
			default:
				err = formatAWSErr(aerr)
				uLog.WithError(err).Errorf("AWS error creating user")
				return nil, err
			}
		}
		uLog.WithError(err).Errorf("unknown error creating user in AWS")
		return nil, fmt.Errorf("unknown error creating user in AWS: %v", err)
	} else {
		uLog.Debug("user created successfully")
	}

	return userOut, nil
}

func formatAWSErr(aerr awserr.Error) error {
	switch aerr.Code() {
	case iam.ErrCodeLimitExceededException:
		log.Error(iam.ErrCodeLimitExceededException, aerr.Error())
		return fmt.Errorf("AWS Error: %s - %s", iam.ErrCodeLimitExceededException, aerr.Error())
	case iam.ErrCodeEntityAlreadyExistsException:
		return fmt.Errorf("AWS Error: %s - %s", iam.ErrCodeEntityAlreadyExistsException, aerr.Error())
	case iam.ErrCodeNoSuchEntityException:
		return fmt.Errorf("AWS Error: %s - %s", iam.ErrCodeNoSuchEntityException, aerr.Error())
	case iam.ErrCodeServiceFailureException:
		return fmt.Errorf("AWS Error: %s - %s", iam.ErrCodeServiceFailureException, aerr.Error())
	default:
		log.Error(aerr.Error())
		return fmt.Errorf("AWS Error: %v", aerr)
	}
}

// generateUserName generates a unique user name for AWS and will truncate the credential name
// to fit within the AWS limit of 64 chars if necessary.
func generateUserName(infraName, credentialName string) (string, error) {
	if credentialName == "" {
		return "", fmt.Errorf("empty credential name")
	}
	infraPrefix := ""
	if infraName != "" {
		if len(infraName) > 20 {
			infraName = infraName[0:20]
		}
		infraPrefix = infraName + "-"
	}
	if len(credentialName) > 37 {
		credentialName = credentialName[0:37]
	}
	return fmt.Sprintf("%s%s-%s", infraPrefix, credentialName, utilrand.String(5)), nil
}

func getPolicyName(userName string) string {
	// User names are limited to 64 chars, but policy names are 128, so appending policy
	// to user name is safe here.
	return userName + "-policy"
}

// PolicyDocument is a simple type used to serialize to AWS' PolicyDocument format.
type PolicyDocument struct {
	Version   string
	Statement []StatementEntry
}

// StatementEntry is a simple type used to serialize to AWS' PolicyDocument format. We cannot
// re-use minterv1.StatementEntry due to different conventions for the serialization keys. (caps)
type StatementEntry struct {
	Effect   string
	Action   []string
	Resource string
	// Must "omitempty" otherwise we send unacceptable JSON to the AWS API when no
	// condition is defined.
	Condition minterv1.IAMPolicyCondition `json:",omitempty"`
}

func (a *AWSActuator) loadClusterUUID(logger log.FieldLogger) (configv1.ClusterID, error) {
	logger.Debug("loading cluster version to read clusterID")
	// TODO: this process will need to change if running this controller in a root hive cluster
	clusterVer := &configv1.ClusterVersion{}
	err := a.Client.Get(context.Background(),
		types.NamespacedName{Name: clusterVersionObjectName},
		clusterVer)
	if err != nil {
		logger.WithError(err).Error("error fetching clusterversion object")
		return "", err
	}
	logger.WithField("clusterID", clusterVer.Spec.ClusterID).Debug("found cluster ID")
	return clusterVer.Spec.ClusterID, nil
}

func isAWSCredentials(providerSpec *runtime.RawExtension) (bool, error) {
	codec, err := minterv1.NewCodec()
	if err != nil {
		return false, err
	}
	unknown := runtime.Unknown{}
	err = codec.DecodeProviderSpec(providerSpec, &unknown)
	if err != nil {
		return false, err
	}
	isAWS := unknown.Kind == reflect.TypeOf(minterv1.AWSProviderSpec{}).Name()
	if !isAWS {
		log.WithField("kind", unknown.Kind).
			Info("actuator handles only aws credentials")
	}
	return isAWS, nil
}

// Upgradeable returns a ClusterOperator status condition for the upgradeable type
// if the system is considered not upgradeable. Otherwise, return nil as the default
// value is for things to be upgradeable.
func (a *AWSActuator) Upgradeable(mode operatorv1.CloudCredentialsMode) *configv1.ClusterOperatorStatusCondition {
	return utils.UpgradeableCheck(a.Client, mode, a.GetCredentialsRootSecretLocation())
}

func generateAWSCredentialsConfig(accessKeyID, secretAccessKey string) []byte {
	awsConfig := fmt.Sprintf(`[default]
%s = %s
%s = %s`, secretDataAccessKey, accessKeyID, secretDataSecretKey, secretAccessKey)

	return []byte(awsConfig)
}
