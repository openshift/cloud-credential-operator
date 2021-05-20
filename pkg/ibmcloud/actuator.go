/*
Copyright 2021 The OpenShift Authors.

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
package ibmcloud

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
)

// IBMCloudActuator is the IBM Cloud actuator.
type IBMCloudActuator struct {
	Client client.Client
}

const (
	IBMCloudCredentialsSecretKey = "ibmcloud_api_key"
)

// NewActuator creates a new IBMCloud actuator.
func NewActuator(client client.Client) (*IBMCloudActuator, error) {
	return &IBMCloudActuator{
		Client: client,
	}, nil
}

// Exists checks if the credentials currently exist.
// TODO: in the future validate the expiration of the credentials
func (a *IBMCloudActuator) Exists(ctx context.Context, cr *minterv1.CredentialsRequest) (bool, error) {
	logger := a.getLogger(cr)
	logger.Debug("running Exists")

	existingSecret, err := a.getSecret(ctx, cr, logger)
	if err != nil {
		return false, err
	}

	return existingSecret != nil, nil
}

// Create the credentials.
func (a *IBMCloudActuator) Create(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	logger := a.getLogger(cr)
	logger.Debug("running Create")
	return a.sync(ctx, cr, logger)
}

// Update the credentials to the provided definition.
func (a *IBMCloudActuator) Update(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	logger := a.getLogger(cr)
	logger.Debug("running Update")
	return a.sync(ctx, cr, logger)
}

// Delete credentials
func (a *IBMCloudActuator) Delete(ctx context.Context, cr *minterv1.CredentialsRequest) error {
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

// GetCredentialsRootSecretLocation returns the namespace and name where the parent credentials secret is stored.
func (a *IBMCloudActuator) GetCredentialsRootSecretLocation() types.NamespacedName {
	return types.NamespacedName{Namespace: constants.CloudCredSecretNamespace, Name: constants.IBMCloudCredSecretName}
}

// GetCredentialsRootSecret returns the root secret of the credentials request.
func (a *IBMCloudActuator) GetCredentialsRootSecret(ctx context.Context, cr *minterv1.CredentialsRequest) (*corev1.Secret, error) {
	logger := a.getLogger(cr)

	// get the secret of the ibmcloud credentials
	ibmcloudCredentialsSecret := &corev1.Secret{}
	if err := a.Client.Get(ctx, a.GetCredentialsRootSecretLocation(), ibmcloudCredentialsSecret); err != nil {
		msg := "unable to fetch root cloud cred secret"
		logger.WithError(err).Error(msg)
		return nil, &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   fmt.Sprintf("%v: %v", msg, err),
		}
	}

	return ibmcloudCredentialsSecret, nil
}

func (a *IBMCloudActuator) sync(ctx context.Context, cr *minterv1.CredentialsRequest, logger log.FieldLogger) error {
	logger.Debug("running sync")

	credentialsRootSecret, err := a.GetCredentialsRootSecret(context.TODO(), cr)
	if err != nil {
		logger.WithError(err).Error("issue with cloud credentials secret")
		return err
	}

	// get the secret data from the credentials request
	ibmcloudCredentialData, err := a.getCredentialsSecretData(credentialsRootSecret, logger)
	if err != nil {
		logger.WithError(err).Error("issue with cloud credentials secret")
		return err
	}

	// get the existing secret in order to check if need to update or create a new
	logger.Debug("provisioning secret")
	existingSecret, err := a.getSecret(ctx, cr, logger)
	if err != nil {
		return err
	}

	// check if need to update or create a new one
	if err = a.syncCredentialSecret(ctx, cr, &ibmcloudCredentialData, existingSecret, logger); err != nil {
		msg := "error creating/updating secret"
		logger.WithError(err).Error(msg)
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   fmt.Sprintf("%v: %v", msg, err),
		}
	}
	return nil
}

func (a *IBMCloudActuator) getCredentialsSecretData(cloudCredSecret *corev1.Secret, logger log.FieldLogger) ([]byte, error) {
	// get the secret data - the api key
	infraClusterKubeconfig, ok := cloudCredSecret.Data[IBMCloudCredentialsSecretKey]
	if !ok {
		return nil, fmt.Errorf("IBMCloud credentials secret %s did not contain key %s", cloudCredSecret.Name, IBMCloudCredentialsSecretKey)
	}

	logger.Debug("extracted ibmcloud credentials")
	return infraClusterKubeconfig, nil
}

func (a *IBMCloudActuator) syncCredentialSecret(ctx context.Context, cr *minterv1.CredentialsRequest, ibmcloudCredentialData *[]byte, existingSecret *corev1.Secret, logger log.FieldLogger) error {
	if existingSecret == nil {
		if ibmcloudCredentialData == nil {
			msg := "new access key secret needed but no key data provided"
			logger.Error(msg)
			return &actuatoriface.ActuatorError{
				ErrReason: minterv1.CredentialsProvisionFailure,
				Message:   msg,
			}
		}

		return a.createNewSecret(logger, cr, ibmcloudCredentialData, ctx)
	}

	return a.updateExistingSecret(logger, existingSecret, cr, ibmcloudCredentialData)
}

func (a *IBMCloudActuator) updateExistingSecret(logger log.FieldLogger, existingSecret *corev1.Secret, cr *minterv1.CredentialsRequest, ibmcloudCredentialData *[]byte) error {
	// Update the existing secret:
	logger.Debug("updating secret")
	origSecret := existingSecret.DeepCopy()
	if existingSecret.Annotations == nil {
		existingSecret.Annotations = map[string]string{}
	}
	existingSecret.Annotations[minterv1.AnnotationCredentialsRequest] = fmt.Sprintf("%s/%s", cr.Namespace, cr.Name)
	if ibmcloudCredentialData != nil {
		existingSecret.Data = map[string][]byte{
			IBMCloudCredentialsSecretKey: *ibmcloudCredentialData,
		}
	}

	if !reflect.DeepEqual(existingSecret, origSecret) {
		logger.Info("target secret has changed, updating")
		if err := a.Client.Update(context.TODO(), existingSecret); err != nil {
			msg := "error updating secret"
			logger.WithError(err).Error(msg)
			return &actuatoriface.ActuatorError{
				ErrReason: minterv1.CredentialsProvisionFailure,
				Message:   msg,
			}
		}
	} else {
		logger.Debug("target secret unchanged")
	}

	return nil
}

func (a *IBMCloudActuator) createNewSecret(logger log.FieldLogger, cr *minterv1.CredentialsRequest, ibmcloudCredentialData *[]byte, ctx context.Context) error {
	logger.Info("creating secret")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Spec.SecretRef.Name,
			Namespace: cr.Spec.SecretRef.Namespace,
			Annotations: map[string]string{
				minterv1.AnnotationCredentialsRequest: fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
			},
		},
		Data: map[string][]byte{
			IBMCloudCredentialsSecretKey: *ibmcloudCredentialData,
		},
	}

	if err := a.Client.Create(ctx, secret); err != nil {
		msg := "error in creating a secret"
		logger.WithError(err).Error(msg)
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   msg,
		}
	}

	logger.Info("secret created successfully")
	return nil
}

func (a *IBMCloudActuator) getSecret(ctx context.Context, cr *minterv1.CredentialsRequest, logger log.FieldLogger) (*corev1.Secret, error) {
	logger.Debug("running getSecret")

	existingSecret := &corev1.Secret{}
	if err := a.Client.Get(ctx, types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, existingSecret); err != nil {
		if errors.IsNotFound(err) {
			logger.Debug("target secret does not exist")
			return nil, nil
		}
		return nil, err
	}

	if _, ok := existingSecret.Data[IBMCloudCredentialsSecretKey]; !ok {
		logger.Warningf("secret did not have expected key: %s", IBMCloudCredentialsSecretKey)
	}

	logger.Debug("target secret exists")
	return existingSecret, nil
}

func (a *IBMCloudActuator) getLogger(cr *minterv1.CredentialsRequest) log.FieldLogger {
	return log.WithFields(log.Fields{
		"actuator":     "IBMCloud",
		"targetSecret": fmt.Sprintf("%s/%s", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name),
		"cr":           fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
	})
}

func (a *IBMCloudActuator) Upgradeable(mode operatorv1.CloudCredentialsMode) *configv1.ClusterOperatorStatusCondition {
	upgradeableCondition := &configv1.ClusterOperatorStatusCondition{
		Status: configv1.ConditionTrue,
		Type:   configv1.OperatorUpgradeable,
	}
	return upgradeableCondition
}

func (a *IBMCloudActuator) GetUpcomingCredSecrets() []types.NamespacedName {
	return []types.NamespacedName{}
}
