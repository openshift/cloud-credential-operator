/*
Copyright 2018 The OpenShift Authors.

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

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
)

// Actuator controls credentials on a specific infrastructure. All
// methods should be idempotent unless otherwise specified.
type Actuator interface {
	// Create the credentials.
	Create(context.Context, *minterv1.CredentialsRequest) error
	// Delete the credentials. If no error is returned, it is assumed that all dependent resources have been cleaned up.
	Delete(context.Context, *minterv1.CredentialsRequest) error
	// Update the credentials to the provided definition.
	Update(context.Context, *minterv1.CredentialsRequest) error
	// Exists checks if the credentials currently exist.
	Exists(context.Context, *minterv1.CredentialsRequest) (bool, error)
	// GetCredentialsRootSecretLocation returns the namespace and name where the credentials root secret is stored.
	GetCredentialsRootSecretLocation() types.NamespacedName
	// Upgradeable returns a ClusterOperator Upgradeable condition to indicate whether or not this cluster can
	// be safely upgraded to the next "minor" (4.y) Openshift release.
	Upgradeable(operatorv1.CloudCredentialsMode) *configv1.ClusterOperatorStatusCondition
	// GetCredentialsRootSecret returns the credentials root secret.
	GetCredentialsRootSecret(ctx context.Context, cr *minterv1.CredentialsRequest) (*corev1.Secret, error)
}

type DummyActuator struct {
}

func (a *DummyActuator) Exists(ctx context.Context, cr *minterv1.CredentialsRequest) (bool, error) {
	return true, nil
}

func (a *DummyActuator) Create(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	return nil
}

func (a *DummyActuator) Update(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	return nil
}

func (a *DummyActuator) Delete(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	return nil
}

// GetCredentialsRootSecretLocation returns the namespace and name where the parent credentials secret is stored.
func (a *DummyActuator) GetCredentialsRootSecretLocation() types.NamespacedName {
	return types.NamespacedName{Namespace: constants.CloudCredSecretNamespace, Name: constants.AWSCloudCredSecretName}
}

func (a *DummyActuator) Upgradeable(mode operatorv1.CloudCredentialsMode) *configv1.ClusterOperatorStatusCondition {
	upgradeableCondition := &configv1.ClusterOperatorStatusCondition{
		Status: configv1.ConditionTrue,
		Type:   configv1.OperatorUpgradeable,
	}
	return upgradeableCondition
}

func (a *DummyActuator) GetCredentialsRootSecret(ctx context.Context, cr *minterv1.CredentialsRequest) (*corev1.Secret, error) {
	return nil, nil
}

type ActuatorError struct {
	ErrReason minterv1.CredentialsRequestConditionType
	Message   string
}

type ActuatorStatus interface {
	Reason() minterv1.CredentialsRequestConditionType
}

func (e *ActuatorError) Error() string {
	return e.Message
}

func (e *ActuatorError) Reason() minterv1.CredentialsRequestConditionType {
	return e.ErrReason
}
