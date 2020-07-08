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
	"encoding/json"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	minterv1 "github.com/openshift/api/cloudcredential/v1"
)

type gcpAuthJSON struct {
	PrivateKeyID string `json:"private_key_id"`
}

func decodeProviderSpec(codec *minterv1.ProviderCodec, cr *minterv1.CredentialsRequest) (*minterv1.GCPProviderSpec, error) {
	if cr.Spec.ProviderSpec != nil {
		gcpSpec := minterv1.GCPProviderSpec{}
		err := codec.DecodeProviderSpec(cr.Spec.ProviderSpec, &gcpSpec)
		if err != nil {
			return nil, fmt.Errorf("error decoding provider v1 spec: %v", err)
		}
		return &gcpSpec, nil
	}
	return nil, fmt.Errorf("no providerSpec defined")
}

func decodeProviderStatus(codec *minterv1.ProviderCodec, cr *minterv1.CredentialsRequest) (*minterv1.GCPProviderStatus, error) {
	gcpStatus := minterv1.GCPProviderStatus{}
	if cr.Status.ProviderStatus == nil {
		return &gcpStatus, nil
	}

	err := codec.DecodeProviderStatus(cr.Status.ProviderStatus, &gcpStatus)
	if err != nil {
		return nil, fmt.Errorf("error decoding v1 provider status: %v", err)
	}
	return &gcpStatus, nil
}

func decodeGCPAuthStringToJSON(authJSONBytes []byte) (*gcpAuthJSON, error) {
	authJSON := &gcpAuthJSON{}
	err := json.Unmarshal(authJSONBytes, authJSON)
	if err != nil {
		return nil, err
	}
	return authJSON, nil
}

func extractKeyIDFromKeyName(keyName string) string {
	return keyIDFromKeyName.ReplaceAllString(keyName, "")
}

func loadCredsFromSecret(kubeClient client.Client, namespace, secretName string) ([]byte, error) {
	secret := &corev1.Secret{}
	err := kubeClient.Get(context.TODO(),
		types.NamespacedName{
			Name:      secretName,
			Namespace: namespace,
		},
		secret)
	if err != nil {
		return nil, err
	}

	jsonBytes, ok := secret.Data[gcpSecretJSONKey]
	if !ok {
		return nil, fmt.Errorf("GCP credentials secret %s did not contain key %s",
			secretName, gcpSecretJSONKey)
	}

	return jsonBytes, nil
}
