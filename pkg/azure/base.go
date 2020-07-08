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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	minterv1 "github.com/openshift/api/cloudcredential/v1"
)

type base struct {
	client *clientWrapper
}

func (a *base) Delete(context.Context, *minterv1.CredentialsRequest) error {
	return nil
}

func (a *base) Exists(ctx context.Context, cr *minterv1.CredentialsRequest) (bool, error) {
	if isAzure, err := isAzureCredentials(cr.Spec.ProviderSpec); !isAzure {
		return false, err
	}
	req, err := newRequest(cr)
	if err != nil {
		return false, err
	}
	if req.AzureStatus.ServicePrincipalName == "" || req.AzureStatus.AppID == "" {
		return false, nil
	}

	existingSecret := &corev1.Secret{}
	err = a.client.Get(ctx, types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, existingSecret)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
