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
	"time"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/openshift/cloud-credential-operator/pkg/controller/credentialsrequest/actuator"
	actuatoriface "github.com/openshift/cloud-credential-operator/pkg/controller/credentialsrequest/actuator"
	annotatorconst "github.com/openshift/cloud-credential-operator/pkg/controller/secretannotator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/controller/utils"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1 "github.com/openshift/api/config/v1"
)

var _ actuator.Actuator = (*Actuator)(nil)

// Actuator implements the CredentialsRequest Actuator interface to create credentials for Azure.
type Actuator struct {
	client                  *clientWrapper
	codec                   *minterv1.ProviderCodec
	credentialMinterBuilder credentialMinterBuilder
}

func NewActuator(c client.Client) (*Actuator, error) {
	codec, err := minterv1.NewCodec()
	if err != nil {
		log.WithError(err).Error("error creating Azure codec")
		return nil, fmt.Errorf("error creating Azure codec: %v", err)
	}

	client := newClientWrapper(c)
	return &Actuator{
		client: client,
		codec:  codec,
		credentialMinterBuilder: NewAzureCredentialsMinter,
	}, nil
}

func NewFakeActuator(c client.Client, codec *minterv1.ProviderCodec, credentialMinterBuilder credentialMinterBuilder) *Actuator {
	return &Actuator{
		client: newClientWrapper(c),
		codec:  codec,
		credentialMinterBuilder: credentialMinterBuilder,
	}
}

func (a *Actuator) IsValidMode() error {
	mode, err := a.client.Mode(context.Background())
	if err != nil {
		return err
	}

	switch mode {
	case annotatorconst.MintAnnotation:
		return nil
	case annotatorconst.PassthroughAnnotation:
		return nil
	}

	return errors.New("invalid mode")
}

func isAzureCredentials(providerSpec *runtime.RawExtension) (bool, error) {
	codec, err := minterv1.NewCodec()
	if err != nil {
		return false, err
	}
	unknown := runtime.Unknown{}
	err = codec.DecodeProviderSpec(providerSpec, &unknown)
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
	if err := a.IsValidMode(); err != nil {
		return err
	}

	logger := a.getLogger(cr)
	logger.Debug("running delete")

	cloudCredsSecret, err := a.getRootCloudCredentialsSecret(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("issue with cloud credentials secret")
		return err
	}

	if cloudCredsSecret.Annotations[annotatorconst.AnnotationKey] == annotatorconst.PassthroughAnnotation {
		return nil
	}

	azureStatus, err := decodeProviderStatus(a.codec, cr)
	if err != nil {
		return err
	}

	infraName, err := utils.LoadInfrastructureName(a.client.Client, logger)
	if err != nil {
		return err
	}

	spName := azureStatus.ServicePrincipalName
	if spName == "" {
		spName, err = generateServicePrincipalName(infraName, cr.Name)
		if err != nil {
			return err
		}
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

	// Deleting AAD application results in deleting its service principal
	// and all roles assigned
	if err := azureCredentialsMinter.DeleteAADApplication(ctx, spName); err != nil {
		return err
	}

	return nil
}

func (a *Actuator) sync(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	if isAzure, err := isAzureCredentials(cr.Spec.ProviderSpec); !isAzure {
		return err
	}

	logger := a.getLogger(cr)
	logger.Debug("running sync")

	infraName, err := utils.LoadInfrastructureName(a.client.Client, logger)
	if err != nil {
		return err
	}

	infraResourceGroups, err := loadAzureInfrastructureResourceGroups(a.client.Client, logger)
	if err != nil {
		return err
	}

	cloudCredsSecret, err := a.getRootCloudCredentialsSecret(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("issue with cloud credentials secret")
		return err
	}

	if cloudCredsSecret.Annotations[annotatorconst.AnnotationKey] == annotatorconst.InsufficientAnnotation {
		msg := "cloud credentials insufficient to satisfy credentials request"
		logger.Error(msg)
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.InsufficientCloudCredentials,
			Message:   msg,
		}
	}

	if cloudCredsSecret.Annotations[annotatorconst.AnnotationKey] == annotatorconst.PassthroughAnnotation {
		logger.Debugf("provisioning with passthrough")
		err := a.syncPassthrough(ctx, cr, cloudCredsSecret, logger)
		if err != nil {
			return err
		}
	} else if cloudCredsSecret.Annotations[annotatorconst.AnnotationKey] == annotatorconst.MintAnnotation {
		logger.Debugf("provisioning with cred minting")
		err := a.syncMint(ctx, cr, cloudCredsSecret, infraName, infraResourceGroups, logger)
		if err != nil {
			msg := "error syncing creds in mint-mode"
			logger.WithError(err).Error(msg)
			return &actuatoriface.ActuatorError{
				ErrReason: minterv1.CredentialsProvisionFailure,
				Message:   fmt.Sprintf("%v: %v", msg, err),
			}
		}
	}

	return nil
}

// loadAzureInfrastructureResourceGroups loads the cluster Infrastructure config and returns
// resource group reported in its status
func loadAzureInfrastructureResourceGroups(c client.Client, logger log.FieldLogger) ([]string, error) {
	infra := &configv1.Infrastructure{}
	err := c.Get(context.Background(), types.NamespacedName{Name: "cluster"}, infra)
	if err != nil {
		logger.Error("error loading Infrastructure config 'cluster'")
		return nil, err
	}

	if infra.Status.PlatformStatus == nil {
		err := fmt.Errorf("Error loading infrastructure status: platform status is empty")
		logger.Error(err)
		return nil, err
	}

	if infra.Status.PlatformStatus.Azure == nil {
		err := fmt.Errorf("Error loading infrastructure status: azure platform status is empty")
		logger.Error(err)
		return nil, err
	}

	resourceGroups := []string{infra.Status.PlatformStatus.Azure.ResourceGroupName}

	logger.Infof("Loaded azure infrastructure resource groups: %s", resourceGroups)
	return resourceGroups, nil

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
	cr.Status.ProviderStatus, err = a.codec.EncodeProviderStatus(azureStatus)
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

func (a *Actuator) syncMint(ctx context.Context, cr *minterv1.CredentialsRequest, cloudCredsSecret *corev1.Secret, infraName string, infraResourceGroups []string, logger log.FieldLogger) error {
	azureStatus, err := decodeProviderStatus(a.codec, cr)
	if err != nil {
		return err
	}

	azureSpec, err := decodeProviderSpec(a.codec, cr)
	if err != nil {
		return err
	}

	if len(azureSpec.RoleBindings) == 0 {
		msg := "No role specified in role bindings"
		logger.Error(msg)
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   msg,
		}
	}

	spName := azureStatus.ServicePrincipalName
	if spName == "" {
		spName, err = generateServicePrincipalName(infraName, cr.Name)
		if err != nil {
			return err
		}
		azureStatus.ServicePrincipalName = spName
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

	// Client secret can not be retrieved from Azure, it can be only re-generated.
	// Thus, either use already existing (if it can be found) or generate new one.
	clientSecret := ""
	existingSecret := &corev1.Secret{}
	if err := a.client.Get(ctx, client.ObjectKey{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, existingSecret); err == nil {
		if existingSecret.ResourceVersion == azureStatus.SecretLastResourceVersion {
			clientSecret = string(existingSecret.Data[AzureClientSecret])
		}
	}

	aadApp, newClientSecret, err := azureCredentialsMinter.CreateOrUpdateAADApplication(ctx, spName, clientSecret == "")
	if err != nil {
		return err
	}

	if clientSecret == "" {
		clientSecret = newClientSecret
	}

	if aadApp.AppID == nil {
		return fmt.Errorf("service principal %q application ID is empty", spName)
	}

	azureStatus.AppID = *aadApp.AppID
	err = a.updateProviderStatus(ctx, logger, cr, azureStatus)
	if err != nil {
		return err
	}

	servicePrincipal, err := azureCredentialsMinter.CreateOrGetServicePrincipal(ctx, *aadApp.AppID)
	if err != nil {
		return err
	}

	if servicePrincipal.DisplayName == nil {
		return fmt.Errorf("service principal %q display name is empty", spName)
	}

	if azureStatus.ServicePrincipalName != *servicePrincipal.DisplayName {
		return fmt.Errorf("service principal name %q retrieved from Azure is different from the name %q that was requested", *servicePrincipal.DisplayName, spName)
	}

	err = a.updateProviderStatus(ctx, logger, cr, azureStatus)
	if err != nil {
		return err
	}

	for _, role := range azureSpec.RoleBindings {
		if err := azureCredentialsMinter.AssignResourceScopedRole(ctx, infraResourceGroups, *servicePrincipal.ObjectID, *servicePrincipal.DisplayName, role.Role); err != nil {
			return err
		}
	}

	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.SecretRef.Name,
			Namespace: cr.Spec.SecretRef.Namespace,
			Annotations: map[string]string{
				minterv1.AnnotationCredentialsRequest: fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
			},
		},
		Data: map[string][]byte{
			AzureClientID:       []byte(*servicePrincipal.AppID),
			AzureClientSecret:   []byte(clientSecret),
			AzureRegion:         cloudCredsSecret.Data[AzureRegion],
			AzureResourceGroup:  cloudCredsSecret.Data[AzureResourceGroup],
			AzureResourcePrefix: cloudCredsSecret.Data[AzureResourcePrefix],
			AzureSubscriptionID: cloudCredsSecret.Data[AzureSubscriptionID],
			AzureTenantID:       cloudCredsSecret.Data[AzureTenantID],
		},
	}

	if err := a.syncCredentialSecrets(ctx, cr, newSecret, logger); err != nil {
		return fmt.Errorf("unable to sync credential secret: %v", err)
	}

	updatedSecret := &corev1.Secret{}
	// When the credential secret is created, it is not available right away.
	// Waiting for the secret to manifests so we can get the secret resource version.
	if err := wait.PollImmediate(2*time.Second, 10*time.Second, func() (bool, error) {
		if err := a.client.Get(ctx, client.ObjectKey{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, updatedSecret); err != nil {
			if kerrors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}); err != nil {
		return err
	}

	azureStatus.SecretLastResourceVersion = updatedSecret.ResourceVersion
	err = a.updateProviderStatus(ctx, logger, cr, azureStatus)
	if err != nil {
		return err
	}

	return nil
}

// generateServicePrincipalName generates a unique service principal name for Azure
func generateServicePrincipalName(infraName, credentialName string) (string, error) {
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
	return fmt.Sprintf("%s%s", infraPrefix, credentialName), nil
}

func copyCredentialsSecret(cr *minterv1.CredentialsRequest, src, dest *corev1.Secret) {
	dest.ObjectMeta = metav1.ObjectMeta{
		Name:      cr.Spec.SecretRef.Name,
		Namespace: cr.Spec.SecretRef.Namespace,
		Annotations: map[string]string{
			minterv1.AnnotationCredentialsRequest: fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
		},
	}
	dest.Data = map[string][]byte{
		AzureClientID:       src.Data[AzureClientID],
		AzureClientSecret:   src.Data[AzureClientSecret],
		AzureRegion:         src.Data[AzureRegion],
		AzureResourceGroup:  src.Data[AzureResourceGroup],
		AzureResourcePrefix: src.Data[AzureResourcePrefix],
		AzureSubscriptionID: src.Data[AzureSubscriptionID],
		AzureTenantID:       src.Data[AzureTenantID],
	}
}

func (a *Actuator) syncPassthrough(ctx context.Context, cr *minterv1.CredentialsRequest, cloudCredsSecret *corev1.Secret, logger log.FieldLogger) error {
	return a.syncCredentialSecrets(ctx, cr, cloudCredsSecret, logger)
}

func (a *Actuator) syncCredentialSecrets(ctx context.Context, cr *minterv1.CredentialsRequest, cloudCredsSecret *corev1.Secret, logger log.FieldLogger) error {
	existing := &corev1.Secret{}
	key := client.ObjectKey{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}
	err := a.client.Get(ctx, key, existing)
	if err != nil && kerrors.IsNotFound(err) {
		s := &corev1.Secret{}
		copyCredentialsSecret(cr, cloudCredsSecret, s)
		return a.client.Create(ctx, s)
	} else if err != nil {
		return err
	}

	updated := existing.DeepCopy()
	copyCredentialsSecret(cr, cloudCredsSecret, updated)
	if !reflect.DeepEqual(existing, updated) {
		err := a.client.Update(ctx, updated)
		if err != nil {
			return &actuatoriface.ActuatorError{
				ErrReason: minterv1.CredentialsProvisionFailure,
				Message:   "error updating secret",
			}
		}
	}
	return nil
}

func (a *Actuator) getRootCloudCredentialsSecret(ctx context.Context, logger log.FieldLogger) (*corev1.Secret, error) {
	cloudCredSecret := &corev1.Secret{}
	if err := a.client.Client.Get(ctx, types.NamespacedName{Name: RootSecretName, Namespace: RootSecretNamespace}, cloudCredSecret); err != nil {
		msg := "unable to fetch root cloud cred secret"
		logger.WithError(err).Error(msg)
		return nil, &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   fmt.Sprintf("%v: %v", msg, err),
		}
	}

	if !isSecretAnnotated(cloudCredSecret) {
		logger.WithField("secret", fmt.Sprintf("%s/%s", RootSecretNamespace, RootSecretName)).Error("cloud cred secret not yet annotated")
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

	if _, ok := secret.ObjectMeta.Annotations[annotatorconst.AnnotationKey]; !ok {
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
	if err := a.IsValidMode(); err != nil {
		return false, err
	}

	azureStatus, err := decodeProviderStatus(a.codec, cr)
	if err != nil {
		return false, err
	}

	if azureStatus.ServicePrincipalName == "" || azureStatus.AppID == "" {
		return false, nil
	}

	existingSecret := &corev1.Secret{}
	err = a.client.Get(ctx, types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, existingSecret)
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
