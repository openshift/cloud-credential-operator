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

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/openshift/cloud-credential-operator/pkg/controller/credentialsrequest/actuator"
	actuatoriface "github.com/openshift/cloud-credential-operator/pkg/controller/credentialsrequest/actuator"
	annotatorconst "github.com/openshift/cloud-credential-operator/pkg/controller/secretannotator/constants"
	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ actuator.Actuator = (*Actuator)(nil)

// Actuator implements the CredentialsRequest Actuator interface to create credentials for Azure.
type Actuator struct {
	client *clientWrapper
	codec  *minterv1.ProviderCodec
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
	}, nil
}

func (a *Actuator) IsValidMode() error {
	mode, err := a.client.Mode(context.Background())
	if err != nil {
		return err
	}

	switch mode {
	// TODO: case secretannotator.MintAnnotation:
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
	return nil
}

func (a *Actuator) sync(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	if isAzure, err := isAzureCredentials(cr.Spec.ProviderSpec); !isAzure {
		return err
	}

	logger := a.getLogger(cr)
	logger.Debug("running sync")

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
		return fmt.Errorf("cloud credentials minting not yet implemented")
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
