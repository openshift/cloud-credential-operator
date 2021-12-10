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
package nutanix

import (
	"context"
	"fmt"
	"reflect"

	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	actuatoriface "github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/actuator"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

const (
	endpointKey = "NUTANIX_ENDPOINT"
	usernameKey = "NUTANIX_USER"
	passwordKey = "NUTANIX_PASSWORD"
	portKey     = "NUTANIX_PORT"
)

type NutanixActuator struct {
	Client client.Client
}

type NutanixCreds struct {
	NutanixEndpoint string `json:"NUTANIX_ENDPOINT"`
	NutanixUser     string `json:"NUTANIX_USER"`
	NutanixPassword string `json:"NUTANIX_PASSWORD"`
	NutanixPort     string `json:"NUTANIX_PORT"`
}

// NewActuator creates a new Nutanix actuator.
func NewActuator(client client.Client) (*NutanixActuator, error) {
	return &NutanixActuator{
		Client: client,
	}, nil
}

// Create the credentials.
func (a *NutanixActuator) Create(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	logger := a.getLogger(cr)
	logger.Debug("running Create")
	return a.sync(ctx, cr, logger)
}

// Delete credentials
func (a *NutanixActuator) Delete(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	logger := a.getLogger(cr)
	logger.Debug("running Delete")

	existingSecret, err := a.getSecret(ctx, cr, logger)
	if err != nil {
		return err
	}
	if existingSecret != nil {
		logger.Info("Deleting existing secret")
		if err = a.Client.Delete(ctx, existingSecret); err != nil {
			return err
		}
	}

	return nil
}

// Update the credentials to the provided definition.
func (a *NutanixActuator) Update(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	logger := a.getLogger(cr)
	logger.Debug("running Update")
	return a.sync(ctx, cr, logger)
}

// Exists checks if the credentials currently exist.
func (a *NutanixActuator) Exists(ctx context.Context, cr *minterv1.CredentialsRequest) (bool, error) {
	logger := a.getLogger(cr)
	logger.Debug("running Exists")

	existingSecret, err := a.getSecret(ctx, cr, logger)
	if err != nil {
		return false, err
	}

	return existingSecret != nil, nil
}

// GetCredentialsRootSecretLocation returns the namespace and name where the parent credentials secret is stored.
func (a *NutanixActuator) GetCredentialsRootSecretLocation() types.NamespacedName {
	return types.NamespacedName{Namespace: constants.CloudCredSecretNamespace, Name: constants.NutanixCloudCredSecretName}
}

func (a *NutanixActuator) Upgradeable(mode operatorv1.CloudCredentialsMode) *configv1.ClusterOperatorStatusCondition {
	return utils.UpgradeableCheck(a.Client, mode, a.GetCredentialsRootSecretLocation())
}

func (a *NutanixActuator) GetCredentialsRootSecret(ctx context.Context, cr *minterv1.CredentialsRequest) (*corev1.Secret, error) {
	logger := a.getLogger(cr)

	// get the secret of the nutanix credentials
	nutanixCredentialsSecret := &corev1.Secret{}
	if err := a.Client.Get(ctx, a.GetCredentialsRootSecretLocation(), nutanixCredentialsSecret); err != nil {
		msg := "unable to fetch root cloud cred secret"
		logger.WithError(err).Error(msg)
		return nil, &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   fmt.Sprintf("%v: %v", msg, err),
		}
	}

	return nutanixCredentialsSecret, nil
}

func (a *NutanixActuator) sync(ctx context.Context, cr *minterv1.CredentialsRequest, logger log.FieldLogger) error {
	logger.Debug("running sync for Nutanix")

	credentialsRootSecret, err := a.GetCredentialsRootSecret(context.TODO(), cr)
	if err != nil {
		logger.WithError(err).Error("issue with cloud credentials secret")
		return err
	}

	nutanixCreds, err := a.getCredentialsSecretData(credentialsRootSecret, logger)
	if err != nil {
		logger.WithError(err).Error("issue with cloud credentials secret")
		return err
	}

	logger.Debugf("provisioning secret")
	existingSecret, err := a.loadExistingSecret(cr)

	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	err = a.syncCredentialSecret(cr, &nutanixCreds, existingSecret, logger)
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

// loadExistingSecret load the secret from the API. If the secret is not found, the NotFound
// err is returned, with nil secret.
// The NotFound error can be used to signal the creation of a new signal.
func (a *NutanixActuator) loadExistingSecret(cr *minterv1.CredentialsRequest) (*corev1.Secret, error) {
	logger := a.getLogger(cr)

	// Check if the credentials secret exists, if not we need to inform the syncer to generate a new one:
	loadedSecret := &corev1.Secret{}
	err := a.Client.Get(context.TODO(), types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, loadedSecret)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Debugf("secret %s does not exist", cr.Spec.SecretRef.Name)
			return nil, err
		}
	}

	if _, ok := loadedSecret.Data[endpointKey]; !ok {
		logger.Warningf("secret did not have expected key: %s", endpointKey)
	}
	if _, ok := loadedSecret.Data[usernameKey]; !ok {
		logger.Warningf("secret did not have expected key: %s", usernameKey)
	}
	if _, ok := loadedSecret.Data[passwordKey]; !ok {
		logger.Warningf("secret did not have expected key: %s", passwordKey)
	}
	if _, ok := loadedSecret.Data[portKey]; !ok {
		logger.Warningf("secret did not have expected key: %s", portKey)
	}

	return loadedSecret, nil
}

func (a *NutanixActuator) getCredentialsSecretData(cloudCredSecret *corev1.Secret, logger log.FieldLogger) (NutanixCreds, error) {
	out, err := secretToNutanixCreds(cloudCredSecret)
	if err != nil {
		return NutanixCreds{}, &actuatoriface.ActuatorError{
			ErrReason: minterv1.InsufficientCloudCredentials,
			Message:   fmt.Sprintf("secret %s did not have expected key: %s", constants.NutanixCloudCredSecretName, err),
		}
	}

	logger.Debug("extracted nutanix credentials")

	return out, nil
}

func (a *NutanixActuator) syncCredentialSecret(cr *minterv1.CredentialsRequest, nutanixCreds *NutanixCreds, existingSecret *corev1.Secret, logger log.FieldLogger) error {
	sLog := logger.WithFields(log.Fields{
		"targetSecret": fmt.Sprintf("%s/%s", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name),
		"cr":           fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
	})

	if existingSecret == nil {
		if nutanixCreds == nil {
			msg := "new access key secret needed but no key data provided"
			sLog.Error(msg)
			return &actuatoriface.ActuatorError{
				ErrReason: minterv1.CredentialsProvisionFailure,
				Message:   msg,
			}
		}
		sLog.Info("creating Nutanix secret")
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cr.Spec.SecretRef.Name,
				Namespace: cr.Spec.SecretRef.Namespace,
				Annotations: map[string]string{
					minterv1.AnnotationCredentialsRequest: fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
				},
			},
			Data: secretDataFrom(nutanixCreds),
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
	if nutanixCreds != nil {
		existingSecret.Data = secretDataFrom(nutanixCreds)
	}

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

func (a *NutanixActuator) getSecret(ctx context.Context, cr *minterv1.CredentialsRequest, logger log.FieldLogger) (*corev1.Secret, error) {
	logger.Debug("running getSecret")

	existingSecret := &corev1.Secret{}
	if err := a.Client.Get(ctx, types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, existingSecret); err != nil {
		if errors.IsNotFound(err) {
			logger.Debug("target secret does not exist")
			return nil, nil
		}
		return nil, err
	}
	// todo check secret sanity
	logger.Debug("target secret exists")
	return existingSecret, nil
}

func (a *NutanixActuator) getLogger(cr *minterv1.CredentialsRequest) log.FieldLogger {
	return log.WithFields(log.Fields{
		"actuator":     "Nutanix",
		"targetSecret": fmt.Sprintf("%s/%s", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name),
		"cr":           fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
	})
}

func secretToNutanixCreds(secret *corev1.Secret) (NutanixCreds, error) {
	c := NutanixCreds{}
	endpoint, ok := secret.Data[endpointKey]
	if !ok {
		return c, fmt.Errorf("missing field %s", endpointKey)
	}
	username, ok := secret.Data[usernameKey]
	if !ok {
		return c, fmt.Errorf("missing field %s", usernameKey)
	}
	password, ok := secret.Data[passwordKey]
	if !ok {
		return c, fmt.Errorf("missing field %s", passwordKey)
	}

	port, ok := secret.Data[portKey]
	if !ok {
		return c, fmt.Errorf("missing field %s", portKey)
	}

	c.NutanixEndpoint = string(endpoint)
	c.NutanixUser = string(username)
	c.NutanixPassword = string(password)
	c.NutanixPort = string(port)
	return c, nil
}

func secretDataFrom(nutanixCreds *NutanixCreds) map[string][]byte {
	return map[string][]byte{
		endpointKey: []byte(nutanixCreds.NutanixEndpoint),
		usernameKey: []byte(nutanixCreds.NutanixUser),
		passwordKey: []byte(nutanixCreds.NutanixPassword),
		portKey:     []byte(nutanixCreds.NutanixPort),
	}
}
