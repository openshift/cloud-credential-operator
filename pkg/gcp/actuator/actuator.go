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
package actuator

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
)

// Actuator implements the CredentialsRequest Actuator interface to create credentials for GCP.
type Actuator struct {
	Client client.Client
}

// NewActuator initializes and returns a new Actuator for GCP.
func NewActuator(c client.Client) (*Actuator, error) {
	return &Actuator{
		Client: c,
	}, nil
}

// Create the credentials.
func (a *Actuator) Create(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	return nil
}

// Delete the credentials. If no error returned, it is assumed that all dependent resources have been cleaned up.
func (a *Actuator) Delete(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	return nil
}

// Exists checks if the credentials currently exist.
//
// To do this we will check if the target secret exists. This call is only used to determine
// if we're doing a Create or an Update, but in the context of this acutator it makes no
// difference. As such we will not check if the service account exists in GCP and is correctly configured
// as this will all be handled in both Create and Update.
func (a *Actuator) Exists(ctx context.Context, cr *minterv1.CredentialsRequest) (bool, error) {
	return false, nil
}

// Update the credentials to the provided definition.
func (a *Actuator) Update(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	return nil
}
