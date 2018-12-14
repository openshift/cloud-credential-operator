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
	minterv1 "github.com/openshift/cred-minter/pkg/apis/credminter/v1beta1"
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
	// Checks if the credentials currently exists.
	Exists(context.Context, *minterv1.CredentialsRequest) (bool, error)
}
