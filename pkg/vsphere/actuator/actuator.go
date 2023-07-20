/*
Copyright 2020 The OpenShift Authors.

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
	"fmt"
	"reflect"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	actuatoriface "github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/actuator"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

var _ actuatoriface.Actuator = (*VSphereActuator)(nil)

// VSphereActuator implements the CredentialsRequest Actuator interface to process CredentialsRequests in vSphere.
type VSphereActuator struct {
	Codec          *minterv1.ProviderCodec
	Client         client.Client
	RootCredClient client.Client
}

func (a *VSphereActuator) STSFeatureGateEnabled() bool {
	return false
}

// NewVSphereActuator creates a new VSphereActuator.
func NewVSphereActuator(client, rootCredClient client.Client) (*VSphereActuator, error) {
	return &VSphereActuator{
		Client:         client,
		RootCredClient: rootCredClient,
	}, nil
}

// DecodeProviderStatus returns a decoded VSphereProviderStatus from a CredentialsRequest
func DecodeProviderStatus(codec *minterv1.ProviderCodec, cr *minterv1.CredentialsRequest) (*minterv1.VSphereProviderStatus, error) {
	vSphereStatus := minterv1.VSphereProviderStatus{}
	var err error
	if cr.Status.ProviderStatus == nil {
		return &vSphereStatus, nil
	}

	err = codec.DecodeProviderStatus(cr.Status.ProviderStatus, &vSphereStatus)
	if err != nil {
		return nil, fmt.Errorf("error decoding v1 provider status: %v", err)
	}
	return &vSphereStatus, nil
}

// DecodeProviderSpec returns a decoded VSphereProviderSpec from a CredentialsRequest
func DecodeProviderSpec(codec *minterv1.ProviderCodec, cr *minterv1.CredentialsRequest) (*minterv1.VSphereProviderSpec, error) {
	if cr.Spec.ProviderSpec != nil {
		vSphereSpec := minterv1.VSphereProviderSpec{}
		err := codec.DecodeProviderSpec(cr.Spec.ProviderSpec, &vSphereSpec)
		if err != nil {
			return nil, fmt.Errorf("error decoding provider v1 spec: %v", err)
		}
		return &vSphereSpec, nil
	}

	return nil, fmt.Errorf("no providerSpec defined")
}

// Exists will check if the credentials currently exist. To do this we will check if the target
// secret exists. This call is only used to determine if we're doing a Create or an Update, but
// in the context of this acutator it makes no difference.
func (a *VSphereActuator) Exists(ctx context.Context, cr *minterv1.CredentialsRequest) (bool, error) {
	logger := a.getLogger(cr)
	logger.Debug("running Exists")
	var err error
	if isVSphere, err := isVSphereCredentials(cr.Spec.ProviderSpec); !isVSphere {
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
func (a *VSphereActuator) needsUpdate(ctx context.Context, cr *minterv1.CredentialsRequest) (bool, error) {
	logger := a.getLogger(cr)

	// If the secret simply doesn't exist, we definitely need an update
	exists, err := a.Exists(ctx, cr)
	if err != nil {
		return true, err
	}
	if !exists {
		return true, nil
	}

	// for passthrough creds, just make sure the target secret data matches the cloud creds secret data
	existingSecret, err := a.loadExistingSecret(cr)
	if err != nil {
		return true, err
	}

	credentialsRootSecret, err := a.GetCredentialsRootSecret(context.TODO(), cr)
	if err != nil {
		logger.WithError(err).Error("issue with cloud credentials secret")
		return true, err
	}
	if !reflect.DeepEqual(existingSecret.Data, credentialsRootSecret.Data) {
		logger.Debug("need update because target secret has different data than cloud creds secret")
		return true, nil
	} else {
		logger.Debug("target secret and cloud secret data match")
	}

	// If we've made it this far, then there are no updates needed
	return false, nil
}

// Create will handle creating the credentials.
func (a *VSphereActuator) Create(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	return a.sync(ctx, cr)
}

// Update will update the credentials to satisfy the CredentialsRequest.
func (a *VSphereActuator) Update(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	return a.sync(ctx, cr)
}

func (a *VSphereActuator) sync(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	if isVSphere, err := isVSphereCredentials(cr.Spec.ProviderSpec); !isVSphere {
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

	if credentialsRootSecret.Annotations[constants.AnnotationKey] == constants.InsufficientAnnotation {
		msg := "cloud credentials insufficient to satisfy credentials request"
		logger.Error(msg)
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.InsufficientCloudCredentials,
			Message:   msg,
		}
	}

	if credentialsRootSecret.Annotations[constants.AnnotationKey] == constants.PassthroughAnnotation {
		logger.Debugf("provisioning with passthrough")
		err := a.syncPassthrough(ctx, cr, credentialsRootSecret, logger)
		if err != nil {
			return err
		}
	}

	return nil
}

func (a *VSphereActuator) syncPassthrough(ctx context.Context, cr *minterv1.CredentialsRequest, cloudCredsSecret *corev1.Secret, logger log.FieldLogger) error {
	err := a.syncTargetSecret(ctx, cr, cloudCredsSecret.Data, logger)
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

func (a *VSphereActuator) updateProviderStatus(ctx context.Context, logger log.FieldLogger, cr *minterv1.CredentialsRequest, vSphereStatus *minterv1.VSphereProviderStatus) error {
	var err error
	cr.Status.ProviderStatus, err = a.Codec.EncodeProviderStatus(vSphereStatus)
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
func (a *VSphereActuator) Delete(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	// Only supporting passthrough mode right now which just means there are no
	// objects in vSphere to clean up.

	return nil
}

func (a *VSphereActuator) loadExistingSecret(cr *minterv1.CredentialsRequest) (*corev1.Secret, error) {
	logger := a.getLogger(cr)

	// Check if the credentials secret exists, if not we need to inform the syncer to generate a new one:
	existingSecret := &corev1.Secret{}
	err := a.Client.Get(context.TODO(), types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, existingSecret)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Debug("secret does not exist")
			return nil, nil
		} else {
			return nil, err
		}
	}

	return existingSecret, nil
}

func (a *VSphereActuator) getLogger(cr *minterv1.CredentialsRequest) log.FieldLogger {
	return log.WithFields(log.Fields{
		"actuator": "vsphere",
		"cr":       fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
	})
}

func (a *VSphereActuator) syncTargetSecret(ctx context.Context, cr *minterv1.CredentialsRequest, secretData map[string][]byte, logger log.FieldLogger) error {
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
		for key, value := range secretData {
			secret.Data[key] = value
		}
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
func (a *VSphereActuator) GetCredentialsRootSecretLocation() types.NamespacedName {
	return types.NamespacedName{Namespace: constants.CloudCredSecretNamespace, Name: constants.VSphereCloudCredSecretName}
}

func (a *VSphereActuator) GetCredentialsRootSecret(ctx context.Context, cr *minterv1.CredentialsRequest) (*corev1.Secret, error) {
	logger := a.getLogger(cr)
	cloudCredSecret := &corev1.Secret{}
	if err := a.RootCredClient.Get(ctx, a.GetCredentialsRootSecretLocation(), cloudCredSecret); err != nil {
		msg := "unable to fetch root cloud cred secret"
		logger.WithError(err).Error(msg)
		return nil, &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   fmt.Sprintf("%v: %v", msg, err),
		}
	}

	if !isSecretAnnotated(cloudCredSecret) {
		logger.WithField("secret", fmt.Sprintf("%s/%s", constants.CloudCredSecretNamespace, constants.VSphereCloudCredSecretName)).Error("cloud cred secret not yet annotated")
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

func isVSphereCredentials(providerSpec *runtime.RawExtension) (bool, error) {
	unknown := runtime.Unknown{}
	err := minterv1.Codec.DecodeProviderSpec(providerSpec, &unknown)
	if err != nil {
		return false, err
	}
	isVSphere := unknown.Kind == reflect.TypeOf(minterv1.VSphereProviderSpec{}).Name()
	if !isVSphere {
		log.WithField("kind", unknown.Kind).
			Info("actuator handles only vsphere credentials")
	}
	return isVSphere, nil
}

// Upgradeable returns a ClusterOperator status condition for the upgradeable type
// if the system is considered not upgradeable. Otherwise, return nil as the default
// value is for things to be upgradeable.
func (a *VSphereActuator) Upgradeable(mode operatorv1.CloudCredentialsMode) *configv1.ClusterOperatorStatusCondition {
	return utils.UpgradeableCheck(a.RootCredClient, mode, a.GetCredentialsRootSecretLocation())
}
