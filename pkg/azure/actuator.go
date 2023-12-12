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

package azure

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	actuatoriface "github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/actuator"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

var _ actuatoriface.Actuator = (*Actuator)(nil)

// Actuator implements the CredentialsRequest Actuator interface to create credentials for Azure.
type Actuator struct {
	client                  *clientWrapper
	credentialMinterBuilder credentialMinterBuilder
}

func NewActuator(c, rootCredClient client.Client, cloudName configv1.AzureCloudEnvironment) (*Actuator, error) {
	client := newClientWrapper(c, rootCredClient)
	return &Actuator{
		client: client,
		credentialMinterBuilder: func(logger log.FieldLogger, clientID, clientSecret, tenantID, subscriptionID string) (*AzureCredentialsMinter, error) {
			return NewAzureCredentialsMinter(logger, clientID, clientSecret, cloudName, tenantID, subscriptionID)
		},
	}, nil
}

func NewFakeActuator(c, rootCredClient client.Client,
	credentialMinterBuilder credentialMinterBuilder,
) *Actuator {
	return &Actuator{
		client:                  newClientWrapper(c, rootCredClient),
		credentialMinterBuilder: credentialMinterBuilder,
	}
}

func isAzureCredentials(providerSpec *runtime.RawExtension) (bool, error) {
	var err error
	unknown := runtime.Unknown{}
	err = minterv1.Codec.DecodeProviderSpec(providerSpec, &unknown)
	if err != nil {
		return false, err
	}
	isAzure := unknown.Kind == reflect.TypeOf(minterv1.AzureProviderSpec{}).Name()
	if !isAzure {
		log.WithField("kind", unknown.Kind).
			Info("actuator handles only azure credentials")
	}
	return isAzure, nil
}

// needsUpdate will return whether the current credentials are outdated
func (a *Actuator) needsUpdate(ctx context.Context, cr *minterv1.CredentialsRequest) (bool, error) {
	logger := a.getLogger(cr)
	// If the secret simply doesn't exist, we definitely need an update
	exists, err := a.Exists(ctx, cr)
	if err != nil {
		return true, err
	}
	if !exists {
		return true, nil
	}

	// Manual mode just update
	credentialsMode, _, err := utils.GetOperatorConfiguration(a.client, logger)
	if err != nil {
		logger.WithError(err).Error("error loading CCO configuration to determine valid mode")
		return true, err
	}
	if credentialsMode == operatorv1.CloudCredentialsModeManual {
		return true, nil
	}
	if credentialsMode == operatorv1.CloudCredentialsModeMint {
		return false, errors.New("mint mode is invalid")
	}
	// passthrough-specifc checks here (now the only kind of checks...)

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

	// If the target Secret data doesn't match the cloud credentials secret (we haven't yet pivoted to passthrough from mint)
	// then we need an update
	targetSecretKey := types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}
	targetSecret := &corev1.Secret{}
	if err := a.client.Get(ctx, targetSecretKey, targetSecret); err != nil {
		logger.WithError(err).Error("failed to fetch target secret")
		return true, err
	}

	if string(targetSecret.Data[AzureClientID]) != string(credentialsRootSecret.Data[AzureClientID]) ||
		string(targetSecret.Data[AzureClientSecret]) != string(credentialsRootSecret.Data[AzureClientSecret]) {
		return true, nil
	}

	// If we still have lingering App Registration info, we should try to clean it up if possible
	azureStatus, err := decodeProviderStatus(minterv1.Codec, cr)
	if err != nil {
		return true, err
	}

	if azureStatus.ServicePrincipalName != "" {
		return true, nil
	}

	return false, nil
}

func (a *Actuator) Create(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	return a.sync(ctx, cr)
}

func (a *Actuator) Update(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	return a.sync(ctx, cr)
}

func (a *Actuator) Delete(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	if isAzure, err := isAzureCredentials(cr.Spec.ProviderSpec); !isAzure {
		return err
	}
	logger := a.getLogger(cr)
	credentialsMode, _, err := utils.GetOperatorConfiguration(a.client, logger)
	if err != nil {
		logger.WithError(err).Error("error loading CCO configuration to determine valid mode")
		return err
	}
	if credentialsMode == operatorv1.CloudCredentialsModeManual {
		logger.Debug("running delete in manual mode")
		return nil
	}

	logger.Debug("running delete")

	credentialsRootSecret, err := a.GetCredentialsRootSecret(ctx, cr)
	if err != nil {
		logger.WithError(err).Error("issue with cloud credentials secret")
		return err
	}

	azureStatus, err := decodeProviderStatus(minterv1.Codec, cr)
	if err != nil {
		return err
	}

	if azureStatus.ServicePrincipalName == "" {
		// Nothing to clean up, or even to check whether we should clean up.
		return nil
	}

	azureCredentialsMinter, err := a.credentialMinterBuilder(
		logger,
		string(credentialsRootSecret.Data[AzureClientID]),
		string(credentialsRootSecret.Data[AzureClientSecret]),
		string(credentialsRootSecret.Data[AzureTenantID]),
		string(credentialsRootSecret.Data[AzureSubscriptionID]),
	)
	if err != nil {
		// TODO: Is it okay to treat this as an error worthy of retrying?
		return fmt.Errorf("unable to create azure cred minter: %v", err)
	}

	// Deleting AAD application results in deleting its service principal
	// and all roles assigned
	if err := azureCredentialsMinter.DeleteAADApplication(ctx, azureStatus.ServicePrincipalName); err != nil {
		// Can't be a fatal error if Azure AD Graph API stops working, we can never succesfully clean up.
		// Just log and move on, the App Registration is properly tagged so some Service Principal with the
		// new Microsoft Graph API permissions can find/delete the orphaned resources.
		// TODO: log to ClusterOperator???
		logger.WithError(err).Error("failed to delete App Registration / Service Principal")
	}

	return nil
}

func (a *Actuator) sync(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	if isAzure, err := isAzureCredentials(cr.Spec.ProviderSpec); !isAzure {
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
	stsDetected, err := utils.IsTimedTokenCluster(a.client, ctx, logger)
	if err != nil {
		return err
	}
	if stsDetected {
		logger.Debug("actuator detected Azure AD Workload Identity enabled cluster, enabling Workload Identity secret brokering for CredentialsRequests providing a Managed Identity")
		azureProviderSpec, err := decodeProviderSpec(minterv1.Codec, cr)
		if err != nil {
			return err
		}
		azureFederatedTokenFile := cr.Spec.CloudTokenPath
		if cr.Spec.CloudTokenPath == "" {
			logger.Debugf("CredentialsRequest has no cloudTokenPath, defaulting azure_federated_token_file to %s", provisioning.OidcTokenPath)
			azureFederatedTokenFile = provisioning.OidcTokenPath
		}
		// Check for old Manual Mode where all 4 fields are empty - defaulting to old behavior
		// where CCO exists and the secret is created manually
		if azureProviderSpec.AzureClientID == "" && azureProviderSpec.AzureTenantID == "" && azureProviderSpec.AzureSubscriptionID == "" && azureProviderSpec.AzureRegion == "" {
			return nil
		}
		err = validateAzureProviderSpec(*azureProviderSpec)
		if err != nil {
			// At least one of the fields was set indicating that the new workload identity
			// behavior of creating the secret is desired but not all fields required were
			// provided.
			msg := "error validating credentials request Azure AD Workload Identity fields"
			return &actuatoriface.ActuatorError{
				ErrReason: minterv1.CredentialsProvisionFailure,
				Message:   fmt.Sprintf("%v: %v", msg, err),
			}
		}
		desiredSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cr.Spec.SecretRef.Name,
				Namespace: cr.Spec.SecretRef.Namespace,
			},
			StringData: map[string]string{
				AzureClientID:           azureProviderSpec.AzureClientID,
				AzureTenantID:           azureProviderSpec.AzureTenantID,
				AzureRegion:             azureProviderSpec.AzureRegion,
				AzureSubscriptionID:     azureProviderSpec.AzureSubscriptionID,
				AzureFederatedTokenFile: azureFederatedTokenFile,
			},
		}
		return a.syncCredentialSecrets(ctx, cr, desiredSecret, logger)
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

func decodeProviderStatus(codec *minterv1.ProviderCodec, cr *minterv1.CredentialsRequest) (*minterv1.AzureProviderStatus, error) {
	azureStatus := minterv1.AzureProviderStatus{}
	var err error
	if cr.Status.ProviderStatus == nil {
		return &azureStatus, nil
	}

	err = codec.DecodeProviderStatus(cr.Status.ProviderStatus, &azureStatus)
	if err != nil {
		return nil, fmt.Errorf("error decoding v1 provider status: %v", err)
	}
	return &azureStatus, nil
}

func decodeProviderSpec(codec *minterv1.ProviderCodec, cr *minterv1.CredentialsRequest) (*minterv1.AzureProviderSpec, error) {
	if cr.Spec.ProviderSpec != nil {
		azureSpec := minterv1.AzureProviderSpec{}
		err := codec.DecodeProviderSpec(cr.Spec.ProviderSpec, &azureSpec)
		if err != nil {
			return nil, fmt.Errorf("error decoding provider v1 spec: %v", err)
		}
		return &azureSpec, nil
	}

	return nil, fmt.Errorf("no providerSpec defined")
}

func (a *Actuator) updateProviderStatus(ctx context.Context, logger log.FieldLogger, cr *minterv1.CredentialsRequest, azureStatus *minterv1.AzureProviderStatus) error {
	var err error
	cr.Status.ProviderStatus, err = minterv1.Codec.EncodeProviderStatus(azureStatus)
	if err != nil {
		logger.WithError(err).Error("error encoding provider status")
		return err
	}

	if cr.Status.Conditions == nil {
		cr.Status.Conditions = []minterv1.CredentialsRequestCondition{}
	}

	err = a.client.Status().Update(ctx, cr)
	if err != nil {
		logger.WithError(err).Error("error updating credentials request status")
		return err
	}
	return nil
}

func (a *Actuator) syncPassthrough(ctx context.Context, cr *minterv1.CredentialsRequest, cloudCredsSecret *corev1.Secret, logger log.FieldLogger) error {
	syncErr := a.syncCredentialSecrets(ctx, cr, cloudCredsSecret, logger)
	if syncErr != nil {
		// Don't bother a cleanup attempt if we somehow failed to update the target secret
		// as that would remove (presumably) working creds.
		return syncErr
	}

	// Since we are live pivoting from Mint to Passthrough, try to clean up the old App Registration
	cleanupErr := a.cleanupAfterPassthroughPivot(ctx, cr, cloudCredsSecret, logger)
	if cleanupErr != nil {
		logger.WithError(cleanupErr).Warn("unable to clean up previously minted App Regisration/Service Principal")
	}
	return cleanupErr
}

func (a *Actuator) cleanupAfterPassthroughPivot(ctx context.Context, cr *minterv1.CredentialsRequest, cloudCredsSecret *corev1.Secret, logger log.FieldLogger) error {
	azureStatus, err := decodeProviderStatus(minterv1.Codec, cr)
	if err != nil {
		return err
	}

	if azureStatus.ServicePrincipalName == "" {
		// If there is no ServicePrincipal saved, we were always in passthrough mode,
		// or we've already cleaned up after the pivot to passthrough.
		return nil
	}

	azureCredentialsMinter, err := a.credentialMinterBuilder(
		logger,
		string(cloudCredsSecret.Data[AzureClientID]),
		string(cloudCredsSecret.Data[AzureClientSecret]),
		string(cloudCredsSecret.Data[AzureTenantID]),
		string(cloudCredsSecret.Data[AzureSubscriptionID]),
	)
	if err != nil {
		return fmt.Errorf("unable to create azure cred minter: %v", err)
	}

	if err := azureCredentialsMinter.DeleteAADApplication(ctx, azureStatus.ServicePrincipalName); err != nil {
		logger.WithError(err).Warn("was not able to clean up previously generated App Registration/Service Principal while pivoting to passthrough mode")
		// Bubble up an error that indicates we have leaked a cloud resource. This will be treated as a non-serious error
		// as it is possible the Azure AD Graph API has been sunset and there is no hope to ever successfully clean up.
		msg := fmt.Sprintf("unable to clean up App Registration / Service Principal: %s", azureStatus.ServicePrincipalName)
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.OrphanedCloudResource,
			Message:   msg,
		}
	} else {
		// update CR status so it never looks like we minted anything
		azureStatus.AppID = ""
		azureStatus.ServicePrincipalName = ""
		azureStatus.SecretLastResourceVersion = ""
		if err := a.updateProviderStatus(ctx, logger, cr, azureStatus); err != nil {
			return err
		}
	}

	return nil
}

// For Azure Workload Identity, the generated Secret needs to look like this:
/*
	apiVersion: v1
	stringData:
	  azure_client_id: 0420bfd1-ab26-4b80-a9ac-deadbeeff1f9
	  azure_tenant_id: 6047c7e9-b2ad-488d-a54e-deadbeefa7ee
	  azure_region: centralus
	  azure_subscription_id: 8c20ec23-8478-4f46-96f4-deadbeeff185
	  azure_federated_token_file: /var/run/secrets/openshift/serviceaccount/token
	kind: Secret
	metadata:
	  name: azure-cloud-credentials
	  namespace: openshift-machine-api
	type: Opaque
*/
// The first 4 fields need to come from `spec.ProviderSpec` in the CredentialsRequest with
// spec.cloudTokenPath matching up to: `azure_federated_token_file`
func (a *Actuator) syncCredentialSecrets(ctx context.Context, cr *minterv1.CredentialsRequest, desiredSecret *corev1.Secret, logger log.FieldLogger) error {
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
	op, err := controllerutil.CreateOrPatch(ctx, a.client, secret, func() error {
		if secret.Labels == nil {
			secret.Labels = map[string]string{}
		}
		secret.Labels[minterv1.LabelCredentialsRequest] = minterv1.LabelCredentialsRequestValue
		if secret.Annotations == nil {
			secret.Annotations = map[string]string{}
		}
		secret.Annotations[minterv1.AnnotationCredentialsRequest] = fmt.Sprintf("%s/%s", cr.Namespace, cr.Name)
		if desiredSecret.Data == nil {
			if secret.StringData == nil {
				secret.StringData = map[string]string{}
			}
			secret.StringData = desiredSecret.StringData
			secret.Type = corev1.SecretTypeOpaque
			return nil
		}
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		secret.Data[AzureClientID] = desiredSecret.Data[AzureClientID]
		secret.Data[AzureClientSecret] = desiredSecret.Data[AzureClientSecret]
		secret.Data[AzureRegion] = desiredSecret.Data[AzureRegion]
		secret.Data[AzureResourceGroup] = desiredSecret.Data[AzureResourceGroup]
		secret.Data[AzureResourcePrefix] = desiredSecret.Data[AzureResourcePrefix]
		secret.Data[AzureSubscriptionID] = desiredSecret.Data[AzureSubscriptionID]
		secret.Data[AzureTenantID] = desiredSecret.Data[AzureTenantID]
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

// GetCredentialsRootSecretLocation returns the namespace and name where the parent credentials secret is stored.
func (a *Actuator) GetCredentialsRootSecretLocation() types.NamespacedName {
	return types.NamespacedName{Namespace: constants.CloudCredSecretNamespace, Name: constants.AzureCloudCredSecretName}
}

func (a *Actuator) GetCredentialsRootSecret(ctx context.Context, cr *minterv1.CredentialsRequest) (*corev1.Secret, error) {
	logger := a.getLogger(cr)
	cloudCredSecret := &corev1.Secret{}
	if err := a.client.RootCredClient.Get(ctx, a.GetCredentialsRootSecretLocation(), cloudCredSecret); err != nil {
		msg := "unable to fetch root cloud cred secret"
		logger.WithError(err).Error(msg)
		return nil, &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   fmt.Sprintf("%v: %v", msg, err),
		}
	}

	if !isSecretAnnotated(cloudCredSecret) {
		logger.WithField("secret", fmt.Sprintf("%s/%s", constants.CloudCredSecretNamespace, constants.AzureCloudCredSecretName)).Error("cloud cred secret not yet annotated")
		return nil, &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   "cannot proceed without cloud cred secret annotation",
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

// Checks if the credentials currently exist.
//
// To do this we will check if the target secret exists. This call is only used to determine
// if we're doing a Create or an Update, but in the context of this acutator it makes no
// difference. As such we will not check if the SP exists in Azure and is correctly configured
// as this will all be handled in both Create and Update.
func (a *Actuator) Exists(ctx context.Context, cr *minterv1.CredentialsRequest) (bool, error) {
	if isAzure, err := isAzureCredentials(cr.Spec.ProviderSpec); !isAzure {
		return false, err
	}

	existingSecret := &corev1.Secret{}
	err := a.client.Get(ctx, types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, existingSecret)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (a *Actuator) getLogger(cr *minterv1.CredentialsRequest) log.FieldLogger {
	return log.WithFields(log.Fields{
		"actuator": "azure",
		"cr":       fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
	})
}

// Upgradeable returns a ClusterOperator status condition for the upgradeable type
// if the system is considered not upgradeable. Otherwise, return nil as the default
// value is for things to be upgradeable.
func (a *Actuator) Upgradeable(mode operatorv1.CloudCredentialsMode) *configv1.ClusterOperatorStatusCondition {
	return utils.UpgradeableCheck(a.client.RootCredClient, mode, a.GetCredentialsRootSecretLocation())
}

func validateAzureProviderSpec(azureProviderSpec minterv1.AzureProviderSpec) error {
	var errors []error
	isEmptyAzureClientID := azureProviderSpec.AzureClientID == ""
	isEmptyAzureTenantID := azureProviderSpec.AzureTenantID == ""
	isEmptyAzureSubscriptionID := azureProviderSpec.AzureSubscriptionID == ""
	isEmptyAzureRegion := azureProviderSpec.AzureRegion == ""

	if isEmptyAzureClientID {
		errors = append(errors, fmt.Errorf("AzureClientID must not be empty"))
	}
	if isEmptyAzureTenantID {
		errors = append(errors, fmt.Errorf("AzureTenantID must not be empty"))
	}
	if isEmptyAzureRegion {
		errors = append(errors, fmt.Errorf("AzureRegion must not be empty"))
	}
	if isEmptyAzureSubscriptionID {
		errors = append(errors, fmt.Errorf("AzureSubscriptionID must not be empty"))
	}
	if len(errors) > 0 {
		return fmt.Errorf("AzureProviderSpec validation failed: %v", errors)
	}
	return nil
}
