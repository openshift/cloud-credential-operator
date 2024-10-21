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
package ovirt

import (
	"context"
	"fmt"
	"strconv"

	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	log "github.com/sirupsen/logrus"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	actuatoriface "github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/actuator"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

const (
	urlKey      = "ovirt_url"
	usernameKey = "ovirt_username"
	passwordKey = "ovirt_password"
	insecureKey = "ovirt_insecure"
	cabundleKey = "ovirt_ca_bundle"
)

var _ actuatoriface.Actuator = (*OvirtActuator)(nil)

type OvirtActuator struct {
	Client         client.Client
	RootCredClient client.Client
}

type OvirtCreds struct {
	URL      string `json:"ovirt_url"`
	Username string `json:"ovirt_username"`
	Password string `json:"ovirt_password"`
	CABundle string `json:"ovirt_ca_bundle"`
	Insecure bool   `json:"ovirt_insecure"`
}

// NewActuator creates a new Ovirt actuator.
func NewActuator(client, rootCredClient client.Client) (*OvirtActuator, error) {
	return &OvirtActuator{
		Client:         client,
		RootCredClient: rootCredClient,
	}, nil
}

// Exists checks if the credentials currently exist.
func (a *OvirtActuator) Exists(ctx context.Context, cr *minterv1.CredentialsRequest) (bool, error) {
	logger := a.getLogger(cr)
	logger.Debug("running Exists")
	var err error

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
func (a *OvirtActuator) Create(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	logger := a.getLogger(cr)
	logger.Debug("running create")
	return a.sync(ctx, cr)
}

// Update the credentials to the provided definition.
func (a *OvirtActuator) Update(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	logger := a.getLogger(cr)
	logger.Debug("running update")
	return a.sync(ctx, cr)
}

func (a *OvirtActuator) sync(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	logger := a.getLogger(cr)
	logger.Debug("running sync")

	credentialsRootSecret, err := a.GetCredentialsRootSecret(context.TODO(), cr)
	if err != nil {
		logger.WithError(err).Error("issue with cloud credentials secret")
		return err
	}

	ovirtCreds, err := a.getCredentialsSecretData(credentialsRootSecret, logger)
	if err != nil {
		logger.WithError(err).Error("issue with cloud credentials secret")
		return err
	}

	logger.Debugf("provisioning secret")
	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	err = a.syncCredentialSecret(ctx, cr, &ovirtCreds, logger)
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

func (a *OvirtActuator) syncCredentialSecret(ctx context.Context, cr *minterv1.CredentialsRequest, ovirtCreds *OvirtCreds, logger log.FieldLogger) error {
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
		for key, value := range secretDataFrom(ovirtCreds) {
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
func (a *OvirtActuator) GetCredentialsRootSecretLocation() types.NamespacedName {
	return types.NamespacedName{Namespace: constants.CloudCredSecretNamespace, Name: constants.OvirtCloudCredsSecretName}
}

func (a *OvirtActuator) GetCredentialsRootSecret(ctx context.Context, cr *minterv1.CredentialsRequest) (*corev1.Secret, error) {
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

func (a *OvirtActuator) getCredentialsSecretData(cloudCredSecret *corev1.Secret, logger log.FieldLogger) (OvirtCreds, error) {
	out, err := secretToCreds(cloudCredSecret)
	if err != nil {
		logger.Warnf("secret did not have expected key: %s", constants.OvirtCloudCredsSecretName)
		return OvirtCreds{}, &actuatoriface.ActuatorError{
			ErrReason: minterv1.InsufficientCloudCredentials,
			Message:   fmt.Sprintf("secret did not have expected key: %v", constants.OvirtCloudCredsSecretName),
		}
	}

	logger.Debug("extracted ovirt credentials")

	return out, nil
}

func secretToCreds(secret *corev1.Secret) (OvirtCreds, error) {
	c := OvirtCreds{}
	url, ok := secret.Data[urlKey]
	if !ok {
		return c, fmt.Errorf("missing field %s", urlKey)
	}
	username, ok := secret.Data[usernameKey]
	if !ok {
		return c, fmt.Errorf("missing field %s", usernameKey)
	}
	password, ok := secret.Data[passwordKey]
	if !ok {
		return c, fmt.Errorf("missing field %s", passwordKey)
	}
	insecure, ok := secret.Data[insecureKey]
	if !ok {
		return c, fmt.Errorf("missing field %s", insecureKey)
	}
	caBundle, ok := secret.Data[cabundleKey]
	if !ok {
		return c, fmt.Errorf("missing field %s", cabundleKey)
	}

	c.URL = string(url)
	c.Username = string(username)
	c.Password = string(password)
	parse, err := strconv.ParseBool(string(insecure))
	if err != nil {
		return c, fmt.Errorf("failed to parse filed: insecure to boolean from value: %v error: %s", insecure, err)
	}
	c.Insecure = parse
	c.CABundle = string(caBundle)
	return c, nil
}

// Delete credentials
func (a *OvirtActuator) Delete(ctx context.Context, cr *minterv1.CredentialsRequest) error {
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

func (a *OvirtActuator) getLogger(cr *minterv1.CredentialsRequest) log.FieldLogger {
	return log.WithFields(log.Fields{
		"actuator": "Ovirt",
		"cr":       fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
	})
}

func secretDataFrom(ovirtCreds *OvirtCreds) map[string][]byte {
	return map[string][]byte{
		urlKey:      []byte(ovirtCreds.URL),
		usernameKey: []byte(ovirtCreds.Username),
		passwordKey: []byte(ovirtCreds.Password),
		insecureKey: []byte(strconv.FormatBool(ovirtCreds.Insecure)),
		cabundleKey: []byte(ovirtCreds.CABundle),
	}
}

func (a *OvirtActuator) IsTimedTokenCluster(c client.Client, ctx context.Context, logger log.FieldLogger) (bool, error) {
	return false, nil
}

// Upgradeable returns a ClusterOperator status condition for the upgradeable type
// if the system is considered not upgradeable. Otherwise, return nil as the default
// value is for things to be upgradeable.
func (a *OvirtActuator) Upgradeable(mode operatorv1.CloudCredentialsMode) *configv1.ClusterOperatorStatusCondition {
	return utils.UpgradeableCheck(a.RootCredClient, mode, a.GetCredentialsRootSecretLocation())
}
