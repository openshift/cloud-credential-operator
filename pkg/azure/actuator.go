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

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/controller/credentialsrequest/actuator"
	"github.com/openshift/cloud-credential-operator/pkg/controller/secretannotator"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ actuator.Actuator = (*Actuator)(nil)

// Actuator implements the CredentialsRequest Actuator interface to create credentials for Azure.
type Actuator struct {
	internal actuator.Actuator
	client   *clientWrapper
	Codec    *minterv1.ProviderCodec
}

func NewActuator(c client.Client) (*Actuator, error) {
	client := newClientWrapper(c)
	return &Actuator{
		internal: newPassthrough(client),
		client:   client,
	}, nil
}

func (a *Actuator) IsValidMode() error {
	mode, err := a.client.Mode(context.Background())
	if err != nil {
		return err
	}

	switch mode {
	// TODO: case secretannotator.MintAnnotation:
	case secretannotator.PassthroughAnnotation:
		return nil
	}

	return errors.New("invalid mode")
}

func (a *Actuator) Create(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	if err := a.IsValidMode(); err != nil {
		return err
	}
	return a.internal.Create(ctx, cr)
}

func (a *Actuator) Delete(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	if err := a.IsValidMode(); err != nil {
		return err
	}
	return a.internal.Delete(ctx, cr)
}

func (a *Actuator) Update(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	if err := a.IsValidMode(); err != nil {
		return err
	}
	return a.internal.Update(ctx, cr)
}

func (a *Actuator) Exists(ctx context.Context, cr *minterv1.CredentialsRequest) (bool, error) {
	if err := a.IsValidMode(); err != nil {
		return false, err
	}
	return a.internal.Exists(ctx, cr)
}
