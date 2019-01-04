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

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1beta1"
	ccaws "github.com/openshift/cloud-credential-operator/pkg/aws"
	minteraws "github.com/openshift/cloud-credential-operator/pkg/aws"
	actuatoriface "github.com/openshift/cloud-credential-operator/pkg/controller/credentialsrequest/actuator"

	openshiftapiv1 "github.com/openshift/api/config/v1"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	rootAWSCredsSecretNamespace = "kube-system"
	rootAWSCredsSecret          = "aws-creds"
	roAWSCredsSecretNamespace   = "openshift-cloud-credential-operator"
	roAWSCredsSecret            = "cloud-credential-operator-iam-ro-creds"
	clusterVersionObjectName    = "version"
	openshiftClusterIDKey       = "openshiftClusterID"
)

var _ actuatoriface.Actuator = (*AWSActuator)(nil)

// AWSActuator implements the CredentialsRequest Actuator interface to create credentials in AWS.
type AWSActuator struct {
	Client           client.Client
	Codec            *minterv1.AWSProviderCodec
	AWSClientBuilder func(accessKeyID, secretAccessKey []byte) (ccaws.Client, error)
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
		AWSClientBuilder: ccaws.NewClient,
		Scheme:           scheme,
	}, nil
}

func (a *AWSActuator) decodeProviderStatus(cr *minterv1.CredentialsRequest) (*minterv1.AWSProviderStatus, error) {
	logger := a.getLogger(cr)
	awsStatus := &minterv1.AWSProviderStatus{}
	var err error
	if cr.Status.ProviderStatus != nil {
		awsStatus, err = a.Codec.DecodeProviderStatus(cr.Status.ProviderStatus, &minterv1.AWSProviderStatus{})
		if err != nil {
			logger.WithError(err).Error("error decoding provider status")
			return nil, fmt.Errorf("error decoding provider status: %v", err)
		}
	}
	return awsStatus, nil
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
	awsStatus, err := a.decodeProviderStatus(cr)
	if err != nil {
		return false, err
	}
	if awsStatus.User == "" {
		logger.Debug("username unset")
		return false, nil
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

// Create the credentials.
func (a *AWSActuator) Create(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	return a.sync(ctx, cr)
}

// Update the credentials to the provided definition.
func (a *AWSActuator) Update(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	return a.sync(ctx, cr)
}

// sync handles both create and update idempotently.
func (a *AWSActuator) sync(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	logger := a.getLogger(cr)
	logger.Debug("running sync")
	awsSpec := &minterv1.AWSProviderSpec{}
	var err error
	if cr.Spec.ProviderSpec != nil {
		awsSpec, err = a.Codec.DecodeProviderSpec(cr.Spec.ProviderSpec, &minterv1.AWSProviderSpec{})
		if err != nil {
			logger.WithError(err).Error("error decoding provider spec")
			return fmt.Errorf("error decoding provider spec: %v", err)
		}
	} else {
		return fmt.Errorf("no providerSpec defined")
	}

	awsStatus, err := a.decodeProviderStatus(cr)
	if err != nil {
		return err
	}

	// Generate a randomized User for the credentials:
	// TODO: check if the generated name is free
	if awsStatus.User == "" {
		username, err := generateUserName(cr.Name)
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
		return err
	}

	clusterUUID, err := a.loadClusterUUID(logger)
	if err != nil {
		return err
	}

	// Check if the user already exists:
	userOut, err := readAWSClient.GetUser(&iam.GetUserInput{UserName: aws.String(awsStatus.User)})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				logger.WithField("userName", awsStatus.User).Debug("user does not exist, creating")
				if rootAWSClient == nil {
					return fmt.Errorf("no root AWS client available, cred secret may not exist: %s/%s", rootAWSCredsSecretNamespace, rootAWSCredsSecret)
				}

				err = a.createUser(logger, rootAWSClient, awsStatus.User)
				if err != nil {
					return err
				}
				logger.WithField("userName", awsStatus.User).Info("user created successfully")

				err = a.tagUser(logger, rootAWSClient, awsStatus.User, string(clusterUUID))
				if err != nil {
					return err
				}

			default:
				return formatAWSErr(aerr)
			}
		} else {
			return fmt.Errorf("unknown error getting user from AWS: %v", err)
		}
	} else {
		logger.WithField("userName", awsStatus.User).Info("user exists")
	}

	// Check if the user has the expected tags:
	if userOut != nil && userOut.User != nil && !userHasTag(userOut.User, openshiftClusterIDKey, string(clusterUUID)) {
		if rootAWSClient == nil {
			return fmt.Errorf("no root AWS client available, cred secret may not exist: %s/%s", rootAWSCredsSecretNamespace, rootAWSCredsSecret)
		}

		err = a.tagUser(logger, rootAWSClient, awsStatus.User, string(clusterUUID))
		if err != nil {
			return err
		}
	}

	// TODO: check if user policy needs to be set? user generation and last set time.
	desiredUserPolicy, err := a.getDesiredUserPolicy(awsSpec.StatementEntries)
	if err != nil {
		return err
	}
	currentUserPolicy, err := a.getCurrentUserPolicy(logger, readAWSClient, awsStatus.User, awsStatus.Policy)
	if err != nil {
		return err
	}
	logger.Debugf("desired user policy: %s", desiredUserPolicy)
	logger.Debugf("current user policy: %s", currentUserPolicy)
	if currentUserPolicy != desiredUserPolicy {
		if rootAWSClient == nil {
			return fmt.Errorf("no root AWS client available, cred secret may not exist: %s/%s", rootAWSCredsSecretNamespace, rootAWSCredsSecret)
		}
		err = a.setUserPolicy(logger, rootAWSClient, awsStatus.User, awsStatus.Policy, desiredUserPolicy)
		if err != nil {
			return err
		}
		logger.Info("successfully set user policy")
	} else {
		logger.Debug("no changes to user policy")
	}

	allUserKeys, err := readAWSClient.ListAccessKeys(&iam.ListAccessKeysInput{UserName: aws.String(awsStatus.User)})
	if err != nil {
		logger.WithError(err).Error("error listing all access keys for user")
		return err
	}

	existingSecret, existingAccessKeyID := a.loadExistingSecret(cr)

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
			return fmt.Errorf("no root AWS client available, cred secret may not exist: %s/%s", rootAWSCredsSecretNamespace, rootAWSCredsSecret)
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

	err = a.syncAccessKeySecret(cr, accessKey, existingSecret, desiredUserPolicy, logger)
	if err != nil {
		log.WithError(err).Error("error saving access key to secret")
		return err
	}

	return nil
}

func (a *AWSActuator) updateProviderStatus(ctx context.Context, logger log.FieldLogger, cr *minterv1.CredentialsRequest, awsStatus *minterv1.AWSProviderStatus) error {

	var err error
	cr.Status.ProviderStatus, err = a.Codec.EncodeProviderStatus(awsStatus)
	if err != nil {
		logger.WithError(err).Error("error encoding provider status")
		return err
	}

	err = a.Client.Status().Update(ctx, cr)
	if err != nil {
		logger.WithError(err).Error("error updating credentials request")
		return err
	}
	return nil
}

// Delete the credentials. If no error is returned, it is assumed that all dependent resources have been cleaned up.
func (a *AWSActuator) Delete(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	logger := a.getLogger(cr)
	logger.Debug("running Delete")
	var err error
	awsStatus, err := a.decodeProviderStatus(cr)
	if err != nil {
		return err
	}

	if awsStatus.User == "" {
		logger.Warn("no user name set on credentials being deleted, most likely were never provisioned")
		return nil
	}

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

	allUserKeys, err := awsClient.ListAccessKeys(&iam.ListAccessKeysInput{UserName: aws.String(awsStatus.User)})
	if err != nil {
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

func (a *AWSActuator) loadExistingSecret(cr *minterv1.CredentialsRequest) (*corev1.Secret, string) {
	logger := a.getLogger(cr)
	var existingAccessKeyID string

	// Check if the credentials secret exists, if not we need to inform the syncer to generate a new one:
	existingSecret := &corev1.Secret{}
	err := a.Client.Get(context.TODO(), types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, existingSecret)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Debug("secret does not exist")
		}
	} else {
		keyBytes, ok := existingSecret.Data["aws_access_key_id"]
		if !ok {
			// Warn, but this will trigger generation of a new key and updating the secret.
			logger.Warning("secret did not have expected key: aws_access_key_id, will be regenerated")
		} else {
			decoded := string(keyBytes)
			existingAccessKeyID = string(decoded)
			logger.WithField("accessKeyID", existingAccessKeyID).Debug("found access key ID in target secret")

		}
	}
	return existingSecret, existingAccessKeyID
}

func (a *AWSActuator) tagUser(logger log.FieldLogger, awsClient minteraws.Client, username, clusterUUID string) error {
	logger.WithField("clusterID", clusterUUID).Info("tagging user with cluster UUID")
	_, err := awsClient.TagUser(&iam.TagUserInput{
		UserName: aws.String(username),
		Tags: []*iam.Tag{
			{
				Key:   aws.String("openshiftClusterID"),
				Value: aws.String(clusterUUID),
			},
		},
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
	logger := a.getLogger(cr).WithField("secret", fmt.Sprintf("%s/%s", rootAWSCredsSecretNamespace, rootAWSCredsSecret))

	logger.Debug("loading AWS credentials from secret")
	// TODO: Running in a 4.0 cluster we expect this secret to exist. When we run in a Hive
	// cluster, we need to load different secrets for each cluster.
	accessKeyID, secretAccessKey, err := minteraws.LoadCredsFromSecret(a.Client, rootAWSCredsSecretNamespace, rootAWSCredsSecret)
	if err != nil {
		return nil, err
	}

	logger.Debug("creating root AWS client")
	return a.AWSClientBuilder(accessKeyID, secretAccessKey)
}

// buildReadAWSCreds will return an AWS client using the the scaled down read only AWS creds
// for cred minter, which are expected to live in openshift-cloud-credential-operator/cloud-credential-operator-iam-ro-creds.
// These creds would normally be created by cred minter itself, via a CredentialsRequest created
// by the cred minter operator.
//
// If these are not available but root creds are, we will use the root creds instead.
// This allows us to create the read creds initially.
func (a *AWSActuator) buildReadAWSClient(cr *minterv1.CredentialsRequest) (minteraws.Client, error) {
	logger := a.getLogger(cr).WithField("secret", fmt.Sprintf("%s/%s", roAWSCredsSecretNamespace, roAWSCredsSecret))
	logger.Debug("loading AWS credentials from secret")
	// TODO: Running in a 4.0 cluster we expect this secret to exist. When we run in a Hive
	// cluster, we need to load different secrets for each cluster.
	accessKeyID, secretAccessKey, err := minteraws.LoadCredsFromSecret(a.Client, roAWSCredsSecretNamespace, roAWSCredsSecret)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Warn("read-only creds not found, checking if root creds exist")
			accessKeyID, secretAccessKey, err = minteraws.LoadCredsFromSecret(a.Client, rootAWSCredsSecretNamespace, rootAWSCredsSecret)
			if err != nil {
				// We've failed to find either set of creds for this client.
				return nil, err
			}
		}
	}

	logger.Debug("creating read AWS client")
	return a.AWSClientBuilder(accessKeyID, secretAccessKey)
}

func (a *AWSActuator) getLogger(cr *minterv1.CredentialsRequest) log.FieldLogger {
	return log.WithFields(log.Fields{
		"actuator": "aws",
		"cr":       fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
	})
}

func (a *AWSActuator) loadClusterUUID(logger log.FieldLogger) (openshiftapiv1.ClusterID, error) {
	logger.Debug("loading cluster version to read clusterID")
	// TODO: this process will need to change if running this controller in a root hive cluster
	clusterVer := &openshiftapiv1.ClusterVersion{}
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

func (a *AWSActuator) syncAccessKeySecret(cr *minterv1.CredentialsRequest, accessKey *iam.AccessKey, existingSecret *corev1.Secret, userPolicy string, logger log.FieldLogger) error {
	sLog := logger.WithFields(log.Fields{
		"targetSecret": fmt.Sprintf("%s/%s", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name),
		"cr":           fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
	})

	if existingSecret == nil || existingSecret.Name == "" {
		if accessKey == nil {
			return fmt.Errorf("new access key secret needed but no key data provided")
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
				"aws_access_key_id":     []byte(*accessKey.AccessKeyId),
				"aws_secret_access_key": []byte(*accessKey.SecretAccessKey),
			},
		}
		// Ensure secrets are "owned" by the credentials request that created or adopted them:
		if err := controllerutil.SetControllerReference(cr, secret, a.Scheme); err != nil {
			sLog.WithError(err).Error("error setting controller reference on secret")
			return err
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
	if accessKey != nil {
		existingSecret.Data["aws_access_key_id"] = []byte(*accessKey.AccessKeyId)
		existingSecret.Data["aws_secret_access_key"] = []byte(*accessKey.SecretAccessKey)
	}
	// Ensure secrets are "owned" by the credentials request that created or adopted them:
	if err := controllerutil.SetControllerReference(cr, existingSecret, a.Scheme); err != nil {
		sLog.WithError(err).Error("error setting controller reference on secret")
		return err
	}

	if !reflect.DeepEqual(existingSecret, origSecret) {
		sLog.Info("target secret has changed, updating")
		err := a.Client.Update(context.TODO(), existingSecret)
		if err != nil {
			sLog.WithError(err).Error("error updating secret")
			return err
		}
	} else {
		sLog.Debug("target secret unchanged")
	}

	return nil
}

func (a *AWSActuator) getDesiredUserPolicy(entries []minterv1.StatementEntry) (string, error) {

	policyDoc := PolicyDocument{
		Version:   "2012-10-17",
		Statement: []StatementEntry{},
	}
	for _, se := range entries {
		policyDoc.Statement = append(policyDoc.Statement, StatementEntry{
			Effect:   se.Effect,
			Action:   se.Action,
			Resource: se.Resource,
		})
	}
	b, err := json.Marshal(&policyDoc)
	if err != nil {
		return "", fmt.Errorf("error marshalling user policy: %v", err)
	}
	return string(b), nil
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

func (a *AWSActuator) createUser(logger log.FieldLogger, awsClient minteraws.Client, username string) error {
	input := &iam.CreateUserInput{
		UserName: aws.String(username),
	}

	uLog := logger.WithField("userName", username)
	uLog.Info("creating user")
	_, err := awsClient.CreateUser(input)

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeEntityAlreadyExistsException:
				uLog.Warn("user already exist")
				return nil
			default:
				err = formatAWSErr(aerr)
				uLog.WithError(err).Errorf("AWS error creating user")
				return err
			}
		}
		uLog.WithError(err).Errorf("unknown error creating user in AWS")
		return fmt.Errorf("unknown error creating user in AWS: %v", err)
	} else {
		uLog.Debug("user created successfully")
	}

	return nil
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
func generateUserName(credentialName string) (string, error) {
	// TODO: it would be nice to include the cluster name in the username, may be added to a openshiftapi type in future. (Infrastructure mentioned)
	if credentialName == "" {
		return "", fmt.Errorf("empty credential name")
	}
	if len(credentialName) > 58 {
		credentialName = credentialName[0:58]
	}
	return fmt.Sprintf("%s-%s", credentialName, utilrand.String(5)), nil
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
}
