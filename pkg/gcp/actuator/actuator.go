/*
Copyright 2019 The OpenShift Authors.

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
	"bytes"
	"context"
	"fmt"
	"reflect"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	// GCP packages
	iamadminpb "google.golang.org/genproto/googleapis/iam/admin/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	ccgcp "github.com/openshift/cloud-credential-operator/pkg/gcp"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	actuatoriface "github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/actuator"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
	gcputils "github.com/openshift/cloud-credential-operator/pkg/operator/utils/gcp"
)

const (
	roGCPCredsSecretNamespace = "openshift-cloud-credential-operator"
	roGCPCredsSecret          = "cloud-credential-operator-gcp-ro-creds"

	gcpSecretJSONKey = "service_account.json"
)

var _ actuatoriface.Actuator = (*Actuator)(nil)

// Actuator implements the CredentialsRequest Actuator interface to create credentials for GCP.
type Actuator struct {
	ProjectName      string
	Client           client.Client
	RootCredClient   client.Client
	GCPClientBuilder func(string, []byte) (ccgcp.Client, error)
}

func (a *Actuator) STSFeatureGateEnabled() bool {
	return false
}

// NewActuator initializes and returns a new Actuator for GCP.
func NewActuator(c, rootCredClient client.Client, projectName string) (*Actuator, error) {
	return &Actuator{
		ProjectName:      projectName,
		Client:           c,
		RootCredClient:   rootCredClient,
		GCPClientBuilder: ccgcp.NewClientFromJSON,
	}, nil
}

// Create the credentials.
func (a *Actuator) Create(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	return a.sync(ctx, cr)
}

// Delete the credentials. If no error returned, it is assumed that all dependent resources have been cleaned up.
func (a *Actuator) Delete(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	if isGCP, err := isGCPCredentials(cr.Spec.ProviderSpec); !isGCP {
		return err
	}
	logger := a.getLogger(cr)
	logger.Debug("running Delete")

	gcpStatus, err := decodeProviderStatus(minterv1.Codec, cr)
	if err != nil {
		return err
	}

	if gcpStatus.ServiceAccountID == "" {
		logger.Warn("no service account ID set on credentialsRequest, provisioned via passthrough")
		return nil
	}
	logger = logger.WithField("serviceAccountID", gcpStatus.ServiceAccountID)

	logger.Info("deleting service account from GCP")

	gcpClient, err := a.buildRootGCPClient(cr)
	if err != nil {
		return err
	}

	if gcpStatus.RoleID != "" {
		logger.Infof("deleting custom role %s from GCP", gcpStatus.RoleID)
		roleName := fmt.Sprintf("projects/%s/roles/%s", a.ProjectName, gcpStatus.RoleID)
		_, err := DeleteRole(gcpClient, roleName)
		if err != nil {
			return fmt.Errorf("failed to delete custom role %s: %v", gcpStatus.RoleID, err)
		}
	}

	svcAcct, err := GetServiceAccount(gcpClient, gcpStatus.ServiceAccountID)
	if err != nil {
		return fmt.Errorf("error getting service account details: %v", err)
	}

	svcAcctBindingName := ServiceAccountBindingName(svcAcct)
	if err := RemovePolicyBindingsForProject(gcpClient, svcAcctBindingName); err != nil {
		return fmt.Errorf("error removing service account policy bindings: %v", err)
	}

	if err := DeleteServiceAccount(gcpClient, svcAcct); err != nil {
		return fmt.Errorf("error deleting service account: %v", err)
	}

	return nil
}

// Exists checks if the credentials currently exist.
//
// To do this we will check if the target secret exists. This call is only used to determine
// if we're doing a Create or an Update, but in the context of this acutator it makes no
// difference. As such we will not check if the service account exists in GCP and is correctly configured
// as this will all be handled in both Create and Update.
func (a *Actuator) Exists(ctx context.Context, cr *minterv1.CredentialsRequest) (bool, error) {
	logger := a.getLogger(cr)

	var err error
	if isGCP, err := isGCPCredentials(cr.Spec.ProviderSpec); !isGCP {
		return false, err
	}

	existingSecret := &corev1.Secret{}
	err = a.Client.Get(ctx, types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, existingSecret)
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

// Update the credentials to the provided definition.
func (a *Actuator) Update(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	return a.sync(ctx, cr)
}

func (a *Actuator) sync(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	if isGCP, err := isGCPCredentials(cr.Spec.ProviderSpec); !isGCP || err != nil {
		return err
	}
	logger := a.getLogger(cr)
	logger.Debug("running sync")

	infraName, err := utils.LoadInfrastructureName(a.Client, logger)
	if err != nil {
		return err
	}

	// Now, should we proceed
	servicesAPIsEnabled, needsUpdate, err := a.needsUpdate(ctx, cr)
	if err != nil {
		logger.WithError(err).Error("error determining whether a credentials update is needed")
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   "error determining whether a credentials update is needed",
		}
	}

	if !servicesAPIsEnabled {
		msg := "not all required service APIs are enabled"
		logger.Error(msg)
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   msg,
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
		logger.Debug("provisioning with passthrough")
		err := a.syncPassthrough(ctx, cr, credentialsRootSecret, logger)
		if err != nil {
			return err
		}
	case constants.MintAnnotation:
		logger.Debug("provisioning with cred minting")
		err := a.syncMint(ctx, cr, infraName, logger)
		if err != nil {
			msg := "error syncing creds in mint-mode"
			logger.WithError(err).Error(msg)
			return &actuatoriface.ActuatorError{
				ErrReason: minterv1.CredentialsProvisionFailure,
				Message:   fmt.Sprintf("%s: %v", msg, err),
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

func (a *Actuator) syncPassthrough(ctx context.Context, cr *minterv1.CredentialsRequest, cloudCredsSecret *corev1.Secret, logger log.FieldLogger) error {

	rootAuthJSONByes := cloudCredsSecret.Data[gcpSecretJSONKey]
	rootClient, err := a.buildRootGCPClient(cr)
	if err != nil {
		return err
	}

	provSpec, err := decodeProviderSpec(minterv1.Codec, cr)
	if err != nil {
		return err
	}

	permList, err := getPermissionsFromRoles(rootClient, provSpec.PredefinedRoles)
	if err != nil {
		return fmt.Errorf("error gathering permissions for each role: %v", err)
	}
	if len(provSpec.Permissions) > 0 {
		permList = append(permList, provSpec.Permissions...)
	}

	enoughPerms, err := gcputils.CheckPermissionsAgainstPermissionList(rootClient, permList, logger)
	if err != nil {
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   fmt.Sprintf("error while validating permissions: %s", err.Error()),
		}
	}

	if !enoughPerms {
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   "cloud root creds do not have enough permissions to be used as-is",
		}
	}

	err = a.syncSecret(ctx, cr, rootAuthJSONByes, logger)
	if err != nil {
		msg := "error creating/updating secret"
		logger.WithError(err).Error(msg)
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   fmt.Sprintf("%s: %v", msg, err),
		}
	}

	return nil
}

// syncMint handles both create and update idempotently.
func (a *Actuator) syncMint(ctx context.Context, cr *minterv1.CredentialsRequest, infraName string, logger log.FieldLogger) error {
	gcpSpec, err := decodeProviderSpec(minterv1.Codec, cr)
	if err != nil {
		return err
	}

	gcpStatus, err := decodeProviderStatus(minterv1.Codec, cr)
	if err != nil {
		return err
	}

	if gcpStatus.ServiceAccountID == "" {
		// The service account id has a max length of 30 chars
		// split it into 12-11-5 where the resuling string becomes:
		// <infraName chopped to 12 chars>-<crName chopped to 11 chars>-<random 5 chars>
		svcAcctID, err := utils.GenerateUniqueNameWithFieldLimits(infraName, 12, cr.Name, 11)
		if err != nil {
			return fmt.Errorf("error generating service account ID: %v", err)
		}
		gcpStatus.ServiceAccountID = svcAcctID
		logger.WithField("serviceaccount", gcpStatus.ServiceAccountID).Info("generated random name for GCP service account")
	}

	if gcpStatus.RoleID == "" && len(gcpSpec.Permissions) > 0 {
		// The role ID has a max length of 64 chars and can include only letters, numbers, period and underscores
		// we sanitize infraName and crName to make them alphanumeric and then
		// split role ID into 29_28_5 where the resulting string becomes:
		// <infraName chopped to 29 chars>_<crName chopped to 28 chars>_<random 5 chars>
		roleID, err := GenerateRoleID(infraName, cr.Name)
		if err != nil {
			return fmt.Errorf("error generating role ID: %v", err)
		}
		gcpStatus.RoleID = roleID
		logger.WithField("role", gcpStatus.RoleID).Info("generated random ID for GCP custom role")

	}

	err = a.updateProviderStatus(ctx, logger, cr, gcpStatus)
	if err != nil {
		return err
	}

	rootGCPClient, err := a.buildRootGCPClient(cr)
	if err != nil {
		logger.WithError(err).Error("error building root GCP client")
		return err
	}
	// This should be impossible if err == nil
	if rootGCPClient == nil {
		return fmt.Errorf("no root GCP client available")
	}

	permList, err := getPermissionsFromRoles(rootGCPClient, gcpSpec.PredefinedRoles)
	if err != nil {
		return fmt.Errorf("error gathering permissions for each role: %v", err)
	}
	if len(gcpSpec.Permissions) > 0 {
		permList = append(permList, gcpSpec.Permissions...)
	}

	var serviceAPIsEnabled bool
	if gcpSpec.SkipServiceCheck {
		// Since we are skipping the checks, we will assume that the APIS are enabled.
		serviceAPIsEnabled = true
	} else {
		// check that service APIs are enabled before we bother to make a
		// new serviceaccount
		var err error
		serviceAPIsEnabled, err = checkServicesEnabled(rootGCPClient, permList, logger)
		if err != nil {
			return err
		}
	}

	if !serviceAPIsEnabled {
		return fmt.Errorf("not all required service APIs are enabled")
	}

	// Create service account if necessary
	var serviceAccount *iamadminpb.ServiceAccount
	projectName := rootGCPClient.GetProjectName()
	getServiceAccount, err := GetServiceAccount(rootGCPClient, gcpStatus.ServiceAccountID)
	if err != nil {
		if status.Code(err) != codes.NotFound {
			return fmt.Errorf("error checking for existing service account: %v", err)
		}

		logger.WithField("serviceaccount", gcpStatus.ServiceAccountID).Debug("service account does not exist, creating")

		// The service account name field has a 100 char max, so generate a name consisting of the
		// infraName chopped to 50 chars + the crName chopped to 49 chars (separated by a '-').
		svcAcctName, err := utils.GenerateNameWithFieldLimits(infraName, 50, cr.Name, 49)
		if err != nil {
			return fmt.Errorf("error generating service acocunt name: %v", err)
		}
		svcAcctName = svcAcctName[:len(svcAcctName)-6] // chop off the trailing random chars
		svcAcct, err := CreateServiceAccount(rootGCPClient, gcpStatus.ServiceAccountID, svcAcctName, "", projectName)
		if err != nil {
			return fmt.Errorf("error creating service account: %v", err)
		}
		serviceAccount = svcAcct
	} else {
		logger.WithField("svcAcctID", gcpStatus.ServiceAccountID).Info("user exists")
		serviceAccount = getServiceAccount
	}

	// TODO: set service account labels once we come up with a scheme for GCP

	roles := gcpSpec.PredefinedRoles
	// Create custom role for all the specific permissions defined in credentials request spec.permissions field
	if len(gcpSpec.Permissions) > 0 {
		role, err := GetRole(rootGCPClient, gcpStatus.RoleID, projectName)
		if err != nil {
			if status.Code(err) != codes.NotFound {
				return fmt.Errorf("error checking for existing custom role: %v", err)
			}

			logger.WithField("role", gcpStatus.RoleID).Debug("custom role does not exist, creating")

			// The role name field has a 100 char max, so generate a name consisting of the
			// infraName chopped to 50 chars + the crName chopped to 49 chars (separated by a '-').
			roleName, err := utils.GenerateNameWithFieldLimits(infraName, 50, cr.Name, 49)
			if err != nil {
				return fmt.Errorf("error generating custom role name: %v", err)
			}

			role, err := CreateRole(rootGCPClient, gcpSpec.Permissions, roleName, gcpStatus.RoleID, "", projectName)
			if err != nil {
				return fmt.Errorf("error creating custom role: %v", err)
			}
			roles = append(roles, role.Name)
		} else {
			if !AreSlicesEqualWithoutOrder(role.IncludedPermissions, gcpSpec.Permissions) {
				logger.WithField("role", gcpStatus.RoleID).Info("custom role exists, updating the permissions")
				role.IncludedPermissions = gcpSpec.Permissions
				_, err := UpdateRole(rootGCPClient, role, role.Name)
				if err != nil {
					return fmt.Errorf("error updating custom role %s: %v", role.Name, err)
				}
			}
			roles = append(roles, role.Name)
		}
	}

	// Set policy/role binding to the service account
	svcAcctBindingName := ServiceAccountBindingName(serviceAccount)
	err = EnsurePolicyBindingsForProject(rootGCPClient, roles, svcAcctBindingName)
	if err != nil {
		return err
	}

	// Create keys  for service account and save to secret
	keyID, err := a.loadExistingSecretKeyAuthID(cr)
	if err != nil {
		return err
	}
	key, err := ensureServiceAccountKeys(rootGCPClient, serviceAccount, projectName, keyID, logger)
	if err != nil {
		return err
	}

	// Save key into secret
	if key != nil {
		err = a.syncSecret(ctx, cr, key.PrivateKeyData, logger)
	}

	return err
}

// needsUpdate will return a bool indicated that all the applicable service APIs are enabled,
// a bool indicating whether any update to existing perms are needed, and any error encountered.
func (a *Actuator) needsUpdate(ctx context.Context, cr *minterv1.CredentialsRequest) (bool, bool, error) {
	logger := a.getLogger(cr)

	gcpSpec, err := decodeProviderSpec(minterv1.Codec, cr)
	if err != nil {
		return true, false, fmt.Errorf("unable to decode ProviderSpec: %v", err)
	}

	gcpStatus, err := decodeProviderStatus(minterv1.Codec, cr)
	if err != nil {
		return true, false, fmt.Errorf("unable to decode ProviderStatus: %v", err)
	}

	readClient, err := a.buildReadGCPClient(cr)
	if err != nil {
		log.WithError(err).Error("error creating GCP client")
		return false, true, fmt.Errorf("unable to check whether credentialsRequest needs update")
	}

	// gather the individual permissions from each pre-defined role
	permList, err := getPermissionsFromRoles(readClient, gcpSpec.PredefinedRoles)
	if err != nil {
		return false, true, fmt.Errorf("error gathering permissions for each role: %v", err)
	}
	// gather individual permissions if specified
	if len(gcpSpec.Permissions) > 0 {
		permList = append(permList, gcpSpec.Permissions...)
	}

	var serviceAPIsEnabled bool
	// Are the service APIs enabled
	if gcpSpec.SkipServiceCheck {
		// Since we are skipping the checks, we will assume that the APIs are enabled.
		serviceAPIsEnabled = true
	} else {
		var err error
		serviceAPIsEnabled, err = checkServicesEnabled(readClient, permList, logger)
		if err != nil {
			return false, true, fmt.Errorf("error checking whether service APIs are enabled: %v", err)
		}
	}

	if !serviceAPIsEnabled {
		return serviceAPIsEnabled, true, nil
	}

	// If the secret simply doesn't exist, we definitely need an update
	exists, err := a.Exists(ctx, cr)
	if err != nil {
		return serviceAPIsEnabled, true, err
	}
	if !exists {
		return serviceAPIsEnabled, true, nil
	}

	if gcpStatus.ServiceAccountID != "" {
		// serviceAccountID non-"" means we're in mint-mode

		_, err := GetServiceAccount(readClient, gcpStatus.ServiceAccountID)
		if err != nil {
			if status.Code(err) == codes.NotFound {
				logger.WithField("serviceaccount", gcpStatus.ServiceAccountID).Debug("service account does not exist, creating a new one")
				return serviceAPIsEnabled, true, nil
			} else {
				return serviceAPIsEnabled, true, fmt.Errorf("error checking for existing service account: %v", err)
			}
		}
		// check if service account key in secret is still available
		keyID, err := a.loadExistingSecretKeyAuthID(cr)
		if err != nil {
			return serviceAPIsEnabled, true, err
		}

		keyExists, err := serviceAccountKeyExists(readClient, gcpStatus.ServiceAccountID, keyID, logger)
		if err != nil {
			logger.WithError(err).Error("error checking whether service account keys exists")
			return serviceAPIsEnabled, true, err
		}
		if !keyExists {
			return serviceAPIsEnabled, true, nil
		}

		// TODO: add tagging check once we decide on tagging scheme

		// check that the current permissions match what is being requested
		needPermissionsUpdate, err := serviceAccountNeedsPermissionsUpdate(readClient, gcpStatus.ServiceAccountID, gcpStatus.RoleID, gcpSpec.PredefinedRoles, gcpSpec.Permissions)
		if err != nil {
			return serviceAPIsEnabled, true, fmt.Errorf("error determining whether policy binding update is needed: %v", err)
		}
		if needPermissionsUpdate {
			logger.Debug("detected need for policy update")
			return serviceAPIsEnabled, true, nil
		}

	} else {
		// passthrough-specifc check here

		credentialsRootSecret, err := a.GetCredentialsRootSecret(ctx, cr)
		if err != nil {
			log.WithError(err).Debug("error retrieving cloud credentials secret")
			return serviceAPIsEnabled, false, err
		}
		// If the cloud credentials secret has been updated in passthrough mode, we need an update
		if credentialsRootSecret != nil && credentialsRootSecret.ResourceVersion != cr.Status.LastSyncCloudCredsSecretResourceVersion {
			logger.Debug("root cloud creds have changed, update is needed")
			return serviceAPIsEnabled, true, nil
		}

		allowed, err := gcputils.CheckPermissionsAgainstPermissionList(readClient, permList, logger)
		if err != nil {
			return serviceAPIsEnabled, true, fmt.Errorf("error checking whether GCP client has sufficient permissions: %v", err)
		}
		if !allowed {
			return serviceAPIsEnabled, true, nil
		}

		// is the target secret synced with the latest content
		secretSynced, err := a.secretAlreadySynced(cr)
		if err != nil {
			logger.WithError(err).Error("error checking if target secret content already up-to-date")
			return serviceAPIsEnabled, true, err
		}
		if !secretSynced {
			return serviceAPIsEnabled, true, nil
		}

	}

	// If we've made it this far, then there are no updates needed
	return serviceAPIsEnabled, false, nil
}

// buildReadGCPClient will return a GCP client using the scaled down read only GCP creds
// for CCO, which are expected to live in openshift-cloud-credential-perator/cloud-credential-operator-gcp-ro-creds.
// These creds would normally be created by CCO itself, via a CredentialsRequest created
// while installing CCO.
//
// If these are not available but root creds are, we will use the root creds instead.
// This allows us to create the read creds initially.
func (a *Actuator) buildReadGCPClient(cr *minterv1.CredentialsRequest) (ccgcp.Client, error) {
	logger := a.getLogger(cr).WithField("secret", fmt.Sprintf("%s/%s", roGCPCredsSecretNamespace, roGCPCredsSecret))
	logger.Debug("loading GCP read-only credentials from secret")

	jsonBytes, err := loadCredsFromSecret(a.Client, roGCPCredsSecretNamespace, roGCPCredsSecret)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Warn("read-only creds not found, using root creds client")
			return a.buildRootGCPClient(cr)
		}
		logger.WithError(err).Error("failed to load in read-only creds Secret")
		return nil, err
	}

	logger.Debug("creating read GCP client")
	client, err := a.GCPClientBuilder(a.ProjectName, jsonBytes)

	// Test if the read-only client is working, if any error here we will fall back to using
	// the root client.
	gcpStatus, err := decodeProviderStatus(minterv1.Codec, cr)
	if err != nil {
		return nil, err
	}
	_, err = GetServiceAccount(client, gcpStatus.ServiceAccountID)
	if err != nil {
		logger.Warn("could not find read-only service account, falling back to root GCP client")
		return a.buildRootGCPClient(cr)
	}
	return client, nil
}

func (a *Actuator) buildRootGCPClient(cr *minterv1.CredentialsRequest) (ccgcp.Client, error) {
	logger := a.getLogger(cr).WithField("secret", fmt.Sprintf("%s/%s", constants.CloudCredSecretNamespace, constants.GCPCloudCredSecretName))

	logger.Debug("loading GCP credentials from secret")
	jsonBytes, err := loadCredsFromSecret(a.RootCredClient, constants.CloudCredSecretNamespace, constants.GCPCloudCredSecretName)
	if err != nil {
		return nil, err
	}

	logger.Debug("creating root GCP client")
	return a.GCPClientBuilder(a.ProjectName, jsonBytes)
}

func (a *Actuator) updateProviderStatus(ctx context.Context, logger log.FieldLogger, cr *minterv1.CredentialsRequest, gcpStatus *minterv1.GCPProviderStatus) error {
	var err error
	cr.Status.ProviderStatus, err = minterv1.Codec.EncodeProviderStatus(gcpStatus)
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

// GetCredentialsRootSecretLocation returns the namespace and name where the parent credentials secret is stored.
func (a *Actuator) GetCredentialsRootSecretLocation() types.NamespacedName {
	return types.NamespacedName{Namespace: constants.CloudCredSecretNamespace, Name: constants.GCPCloudCredSecretName}
}

// GetCredentialsRootSecret will return the cluster's root GCP cloud cred secret if it exists and is properly annotated
func (a *Actuator) GetCredentialsRootSecret(ctx context.Context, cr *minterv1.CredentialsRequest) (*corev1.Secret, error) {
	logger := a.getLogger(cr)
	cloudCredSecret := &corev1.Secret{}
	if err := a.RootCredClient.Get(ctx, a.GetCredentialsRootSecretLocation(), cloudCredSecret); err != nil {
		msg := "unable to fetch root cloud cred secret"
		logger.WithError(err).Error(msg)
		return nil, &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   fmt.Sprintf("%s: %v", msg, err),
		}
	}

	if !isSecretAnnotated(cloudCredSecret) {
		logger.WithField("secret", fmt.Sprintf("%s/%s", constants.CloudCredSecretNamespace, constants.GCPCloudCredSecretName)).Error("cloud cred secret not yet annotated")
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

func isGCPCredentials(providerSpec *runtime.RawExtension) (bool, error) {
	unknown := runtime.Unknown{}
	err := minterv1.Codec.DecodeProviderSpec(providerSpec, &unknown)
	if err != nil {
		return false, err
	}
	isGCP := unknown.Kind == reflect.TypeOf(minterv1.GCPProviderSpec{}).Name()
	if !isGCP {
		log.WithField("kind", unknown.Kind).
			Debug("actuator handles only gcp credentials")
	}
	return isGCP, nil
}

func (a *Actuator) getLogger(cr *minterv1.CredentialsRequest) log.FieldLogger {
	return log.WithFields(log.Fields{
		"actuator": "gcp",
		"cr":       fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
	})
}

func (a *Actuator) secretAlreadySynced(cr *minterv1.CredentialsRequest) (bool, error) {
	logger := log.WithFields(log.Fields{
		"targetSecret": fmt.Sprintf("%s/%s", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name),
		"cr":           fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
	})

	targetSecret := &corev1.Secret{}
	err := a.Client.Get(context.TODO(), types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, targetSecret)
	if err != nil {
		logger.WithError(err).Error("error retrieving existing secret")
		return false, err
	}

	rootSecret, err := a.GetCredentialsRootSecret(context.TODO(), cr)
	if err != nil {
		logger.WithError(err).Error("error retrieving cluster cloud creds")
		return false, err
	}

	rootJSON, ok := rootSecret.Data[gcpSecretJSONKey]
	if !ok {
		return false, fmt.Errorf("did not find expected key in cloud cred secret")
	}

	targetJSON := targetSecret.Data[gcpSecretJSONKey]
	if !bytes.Equal(targetJSON, rootJSON) {
		return false, nil
	}

	return true, nil
}

func (a *Actuator) syncSecret(ctx context.Context, cr *minterv1.CredentialsRequest, privateKeyData []byte, logger log.FieldLogger) error {
	sLog := logger.WithFields(log.Fields{
		"targetSecret": fmt.Sprintf("%s/%s", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name),
		"cr":           fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
	})
	sLog.Infof("processing secret")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.SecretRef.Name,
			Namespace: cr.Spec.SecretRef.Namespace,
		},
	}
	op, err := controllerutil.CreateOrPatch(ctx, a.Client, secret, func() error {
		if secret.Labels == nil {
			secret.Labels = map[string]string{}
		}
		secret.Labels[minterv1.LabelCredentialsRequest] = minterv1.LabelCredentialsRequestValue
		if secret.Annotations == nil {
			secret.Annotations = map[string]string{}
		}
		secret.Annotations[minterv1.AnnotationCredentialsRequest] = fmt.Sprintf("%s/%s", cr.Namespace, cr.Name)
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		secret.Data[gcpSecretJSONKey] = privateKeyData
		return nil
	})
	sLog.WithField("operation", op).Info("processed secret")
	if err != nil {
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   "error processing secret",
		}
	}
	return nil
}

// loadExistingSecretKeyAuthID will return the GCP json auth string from the secret pointed to
// by the CredentialsRequest
func (a *Actuator) loadExistingSecretKeyAuthID(cr *minterv1.CredentialsRequest) (string, error) {
	logger := a.getLogger(cr)
	var authJSON *gcpAuthJSON

	existingSecret, err := a.loadExistingSecret(cr)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Debug("secret does not exist")
			return "", nil
		}
		return "", err
	} else {
		authJSONBytes, ok := existingSecret.Data[gcpSecretJSONKey]
		if !ok {
			// Warn, but this will trigger generation of a new key and updating of the secret.
			logger.Warningf("secret exists but did not have expected key: %s, will create new key", gcpSecretJSONKey)
			return "", nil
		} else {
			authJSON, err = decodeGCPAuthStringToJSON(authJSONBytes)
			if err != nil {
				logger.Warning("secret data could not be unmarshalled, will create new key")
				return "", nil
			}
		}
	}

	return authJSON.PrivateKeyID, nil
}

func (a *Actuator) loadExistingSecret(cr *minterv1.CredentialsRequest) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	err := a.Client.Get(context.TODO(), types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, err
		}
		return nil, fmt.Errorf("error checking if secret already exists: %v", err)
	}
	return secret, nil
}

func checkServicesEnabled(gcpClient ccgcp.Client, permList []string, logger log.FieldLogger) (bool, error) {
	serviceAPIsEnabled, err := gcputils.CheckServicesEnabled(gcpClient, permList, logger)
	if err != nil {
		return false, fmt.Errorf("error checking whether service APIs are enabled: %v", err)
	}

	return serviceAPIsEnabled, nil
}

// Upgradeable returns a ClusterOperator status condition for the upgradeable type
// if the system is considered not upgradeable. Otherwise, return nil as the default
// value is for things to be upgradeable.
func (a *Actuator) Upgradeable(mode operatorv1.CloudCredentialsMode) *configv1.ClusterOperatorStatusCondition {
	return utils.UpgradeableCheck(a.RootCredClient, mode, a.GetCredentialsRootSecretLocation())
}
