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

import minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"

type request struct {
	*minterv1.CredentialsRequest
	AzureSpec   *minterv1.AzureProviderSpec
	AzureStatus *minterv1.AzureProviderStatus
}

func newRequest(cr *minterv1.CredentialsRequest) (*request, error) {
	codec, err := minterv1.NewCodec()
	if err != nil {
		return nil, err
	}

	status := minterv1.AzureProviderStatus{}
	err = codec.DecodeProviderStatus(cr.Status.ProviderStatus, &status)
	if err != nil {
		return nil, err
	}

	spec := minterv1.AzureProviderSpec{}
	err = codec.DecodeProviderSpec(cr.Spec.ProviderSpec, &spec)
	if err != nil {
		return nil, err
	}

	return &request{CredentialsRequest: cr, AzureSpec: &spec, AzureStatus: &status}, nil
}
