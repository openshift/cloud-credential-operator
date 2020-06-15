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
	"fmt"
	"reflect"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/actuator"
	actuatoriface "github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/actuator"
	"github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/constants"
	annotatorconst "github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/constants"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ actuator.Actuator = (*passthrough)(nil)

type passthrough struct {
	base
}

func newPassthrough(c *clientWrapper) *passthrough {
	return &passthrough{base{client: c}}
}

func (a *passthrough) Create(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	return a.Update(ctx, cr)
}

func (a *passthrough) Update(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	root, err := a.client.RootSecret(ctx)
	if err != nil {
		return err
	}

	key := client.ObjectKey{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}
	existing, err := a.client.Secret(ctx, key)
	if err != nil && errors.IsNotFound(err) {
		s := &secret{}
		copySecret(cr, root, s)
		return a.client.Create(ctx, &s.Secret)
	} else if err != nil {
		return err
	}

	updated := existing.Clone()
	copySecret(cr, root, updated)
	if !reflect.DeepEqual(existing, updated) {
		err := a.client.Update(ctx, &updated.Secret)
		if err != nil {
			return &actuatoriface.ActuatorError{
				ErrReason: minterv1.CredentialsProvisionFailure,
				Message:   "error updating secret",
			}
		}
	}
	return nil
}

// GetCredentialsRootSecretLocation returns the namespace and name where the parent credentials secret is stored.
func (a *passthrough) GetCredentialsRootSecretLocation() types.NamespacedName {
	return types.NamespacedName{Namespace: constants.KubeSystemNS, Name: annotatorconst.AzureCloudCredSecretName}
}

func copySecret(cr *minterv1.CredentialsRequest, src *secret, dest *secret) {
	dest.ObjectMeta = metav1.ObjectMeta{
		Name:      cr.Spec.SecretRef.Name,
		Namespace: cr.Spec.SecretRef.Namespace,
		Annotations: map[string]string{
			minterv1.AnnotationCredentialsRequest: fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
		},
	}
	dest.Data = map[string][]byte{
		AzureClientID:       src.Data[AzureClientID],
		AzureClientSecret:   src.Data[AzureClientSecret],
		AzureRegion:         src.Data[AzureRegion],
		AzureResourceGroup:  src.Data[AzureResourceGroup],
		AzureResourcePrefix: src.Data[AzureResourcePrefix],
		AzureSubscriptionID: src.Data[AzureSubscriptionID],
		AzureTenantID:       src.Data[AzureTenantID],
	}
}
