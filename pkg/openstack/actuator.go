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
package openstack

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	log "github.com/sirupsen/logrus"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	actuatoriface "github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/actuator"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

var _ actuatoriface.Actuator = (*OpenStackActuator)(nil)

type OpenStackActuator struct {
	Client         client.Client
	RootCredClient client.Client
}

// NewOpenStackActuator creates a new OpenStack actuator.
func NewOpenStackActuator(client, rootCredClient client.Client) (*OpenStackActuator, error) {
	return &OpenStackActuator{
		Client:         client,
		RootCredClient: rootCredClient,
	}, nil
}

// Exists checks if the credentials currently exist.
func (a *OpenStackActuator) Exists(ctx context.Context, cr *minterv1.CredentialsRequest) (bool, error) {
	logger := a.getLogger(cr)
	logger.Debug("running Exists")
	var err error

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

// Create the credentials.
func (a *OpenStackActuator) Create(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	logger := a.getLogger(cr)
	logger.Debug("running create")
	return a.sync(ctx, cr)
}

// Update the credentials to the provided definition.
func (a *OpenStackActuator) Update(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	logger := a.getLogger(cr)
	logger.Debug("running update")
	return a.sync(ctx, cr)
}

func (a *OpenStackActuator) sync(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	logger := a.getLogger(cr)
	logger.Debug("running sync")

	credentialsRootSecret, err := a.GetCredentialsRootSecret(ctx, cr)
	if err != nil {
		logger.WithError(err).Error("issue with cloud credentials secret")
		return err
	}

	clouds, err := GetRootCloudCredentialsSecretData(credentialsRootSecret, logger)
	if err != nil {
		logger.WithError(err).Error("issue with cloud credentials secret")
		return &actuatoriface.ActuatorError{
			ErrReason: minterv1.InsufficientCloudCredentials,
			Message:   err.Error(),
		}
	}

	logger.Debugf("provisioning secret")
	err = a.syncCredentialSecret(ctx, cr, clouds, logger)
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

func (a *OpenStackActuator) syncCredentialSecret(ctx context.Context, cr *minterv1.CredentialsRequest, clouds string, logger log.FieldLogger) error {
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
		if clouds != "" {
			if secret.Data == nil {
				secret.Data = map[string][]byte{}
			}
			secret.Data[RootOpenStackCredsSecretKey] = []byte(clouds)
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
func (a *OpenStackActuator) GetCredentialsRootSecretLocation() types.NamespacedName {
	return types.NamespacedName{Namespace: constants.CloudCredSecretNamespace, Name: constants.OpenStackCloudCredsSecretName}
}

func (a *OpenStackActuator) GetCredentialsRootSecret(ctx context.Context, cr *minterv1.CredentialsRequest) (*corev1.Secret, error) {
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
	return cloudCredSecret, nil
}

// Delete credentials
func (a *OpenStackActuator) Delete(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	logger := a.getLogger(cr)
	logger.Debug("running delete")

	existingSecret := &corev1.Secret{}
	err := a.Client.Get(context.TODO(), types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, existingSecret)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Debug("target secret does not exist")
			return nil
		}
		return err
	}

	err = a.Client.Delete(context.TODO(), existingSecret)
	if err != nil {
		return err
	}

	return nil
}

func (a *OpenStackActuator) getLogger(cr *minterv1.CredentialsRequest) log.FieldLogger {
	return log.WithFields(log.Fields{
		"actuator": "openstack",
		"cr":       fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
	})
}

func (a *OpenStackActuator) IsTimedTokenCluster(c client.Client, ctx context.Context, logger log.FieldLogger) (bool, error) {
	return false, nil
}

// Upgradeable returns a ClusterOperator status condition for the upgradeable type
// if the system is considered not upgradeable. Otherwise, return nil as the default
// value is for things to be upgradeable.
func (a *OpenStackActuator) Upgradeable(mode operatorv1.CloudCredentialsMode) *configv1.ClusterOperatorStatusCondition {
	return utils.UpgradeableCheck(a.RootCredClient, mode, a.GetCredentialsRootSecretLocation())
}
