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
	"reflect"
	"strconv"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	actuatoriface "github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/actuator"
	crconst "github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/constants"
	annotatorconst "github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/constants"
)

const (
	urlKey      = "ovirt_url"
	usernameKey = "ovirt_username"
	passwordKey = "ovirt_password"
	cafileKey   = "ovirt_cafile"
	insecureKey = "ovirt_insecure"
	cabundleKey = "ovirt_ca_bundle"
)

type OvirtActuator struct {
	Client client.Client
	Codec  *minterv1.ProviderCodec
}

type OvirtCreds struct {
	URL      string `json:"ovirt_url"`
	Username string `json:"ovirt_username"`
	Passord  string `json:"ovirt_password"`
	CAFile   string `json:"ovirt_cafile"`
	CABundle string `json:"ovirt_ca_bundle"`
	Insecure bool   `json:"ovirt_insecure"`
}

// NewActuator creates a new Ovirt actuator.
func NewActuator(client client.Client) (*OvirtActuator, error) {
	codec, err := minterv1.NewCodec()
	if err != nil {
		log.WithError(err).Error("error creating Ovirt codec")
		return nil, fmt.Errorf("error creating Ovirt codec: %v", err)
	}

	return &OvirtActuator{
		Codec:  codec,
		Client: client,
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

	ovirtCreds, err := a.getCredentialsSecretData(ctx, logger)
	if err != nil {
		logger.WithError(err).Error("issue with cloud credentials secret")
		return err
	}

	logger.Debugf("provisioning secret")
	existingSecret, err := a.loadExistingSecret(cr)

	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	err = a.syncCredentialSecret(cr, &ovirtCreds, existingSecret, logger)
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

func (a *OvirtActuator) syncCredentialSecret(cr *minterv1.CredentialsRequest, ovirtCreds *OvirtCreds, existingSecret *corev1.Secret, logger log.FieldLogger) error {
	sLog := logger.WithFields(log.Fields{
		"targetSecret": fmt.Sprintf("%s/%s", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name),
		"cr":           fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
	})

	if existingSecret == nil {
		if ovirtCreds == nil {
			msg := "new access key secret needed but no key data provided"
			sLog.Error(msg)
			return &actuatoriface.ActuatorError{
				ErrReason: minterv1.CredentialsProvisionFailure,
				Message:   msg,
			}
		}
		sLog.Info("creating secret")
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cr.Spec.SecretRef.Name,
				Namespace: cr.Spec.SecretRef.Namespace,
				Annotations: map[string]string{
					minterv1.AnnotationCredentialsRequest: fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
				},
			},
			Data: secretDataFrom(ovirtCreds),
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
	if ovirtCreds != nil {
		existingSecret.Data = secretDataFrom(ovirtCreds)
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

// loadExistingSecret load the secret from the API. If the secret is not found, the NotFound
// err is returned, with nil secret.
// The NotFound error can be used to signal the creation of a new signal.
func (a *OvirtActuator) loadExistingSecret(cr *minterv1.CredentialsRequest) (*corev1.Secret, error) {
	logger := a.getLogger(cr)

	// Check if the credentials secret exists, if not we need to inform the syncer to generate a new one:
	loadedSecret := &corev1.Secret{}
	err := a.Client.Get(context.TODO(), types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, loadedSecret)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Debug("secret does not exist")
			return nil, err
		}
	}

	if _, ok := loadedSecret.Data[urlKey]; !ok {
		logger.Warningf("secret did not have expected key: %s", urlKey)
	}
	if _, ok := loadedSecret.Data[usernameKey]; !ok {
		logger.Warningf("secret did not have expected key: %s", usernameKey)
	}
	if _, ok := loadedSecret.Data[passwordKey]; !ok {
		logger.Warningf("secret did not have expected key: %s", passwordKey)
	}
	if _, ok := loadedSecret.Data[cafileKey]; !ok {
		logger.Warningf("secret did not have expected key: %s", cafileKey)
	}
	if _, ok := loadedSecret.Data[cabundleKey]; !ok {
		logger.Warningf("secret did not have expected key: %s", cabundleKey)
	}

	return loadedSecret, nil
}

// GetCredentialsRootSecretLocation returns the namespace and name where the parent credentials secret is stored.
func (a *OvirtActuator) GetCredentialsRootSecretLocation() types.NamespacedName {
	return types.NamespacedName{Namespace: crconst.KubeSystemNS, Name: annotatorconst.OvirtCloudCredsSecretName}
}

func (a *OvirtActuator) getCredentialsSecretData(ctx context.Context, logger log.FieldLogger) (OvirtCreds, error) {
	cloudCredSecret := &corev1.Secret{}
	if err := a.Client.Get(ctx, a.GetCredentialsRootSecretLocation(), cloudCredSecret); err != nil {
		msg := "unable to fetch root cloud cred secret"
		logger.WithError(err).Error(msg)
		return OvirtCreds{}, &actuatoriface.ActuatorError{
			ErrReason: minterv1.CredentialsProvisionFailure,
			Message:   fmt.Sprintf("%v: %v", msg, err),
		}
	}

	out, err := secretToCreds(cloudCredSecret)
	if err != nil {
		logger.Warnf("secret did not have expected key: %s", annotatorconst.OvirtCloudCredsSecretName)
		return OvirtCreds{}, &actuatoriface.ActuatorError{
			ErrReason: minterv1.InsufficientCloudCredentials,
			Message:   fmt.Sprintf("secret did not have expected key: %v", annotatorconst.OvirtCloudCredsSecretName),
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
	cafile, ok := secret.Data[cafileKey]
	if !ok {
		return c, fmt.Errorf("missing field %s", cafileKey)
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
	c.Passord = string(password)
	c.CAFile = string(cafile)
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
		passwordKey: []byte(ovirtCreds.Passord),
		cafileKey:   []byte(ovirtCreds.CAFile),
		insecureKey: []byte(strconv.FormatBool(ovirtCreds.Insecure)),
		cabundleKey: []byte(ovirtCreds.CABundle),
	}
}
