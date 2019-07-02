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
	utilrand "k8s.io/apimachinery/pkg/util/rand"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
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

// generateUniqueNameWithFieldLimits will take infraName and crName and shorten them if necessary to no longer
// than their respective MaxLen argument. it will then add a unique ending to the resulting name
// by appended '-<5 random chars>' to the resulting string.
// Example: passing "thisIsInfraName", 8, "thisIsCrName", 8 will return:
//		'thisIsIn-thisIsCr-<5 random chars>'
func generateUniqueNameWithFieldLimits(infraName string, infraNameMaxLen int, crName string, crNameMaxlen int) (string, error) {
	genName, err := generateNameWithFieldLimits(infraName, infraNameMaxLen, crName, crNameMaxlen)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s-%s", genName, utilrand.String(5)), nil
}

// generateNameWithFieldLimits lets you pass in two strings which will be clipped to their respective
// maximum lengths.
// Example: passing "thisIsInfraName", 8, "thisIsCrName", 8 will return:
//      'thisIsIn-thisIsCr'
func generateNameWithFieldLimits(infraName string, infraNameMaxLen int, crName string, crNameLen int) (string, error) {
	if crName == "" {
		return "", fmt.Errorf("empty credential request name")
	}

	infraPrefix := ""
	if infraName != "" {
		if len(infraName) > infraNameMaxLen {
			infraName = infraName[0:infraNameMaxLen]
		}
		infraPrefix = infraName + "-"
	}
	if len(crName) > crNameLen {
		crName = crName[0:crNameLen]
	}
	return fmt.Sprintf("%s%s", infraPrefix, crName), nil
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
		return nil, fmt.Errorf("GCP credentials secret %s did not container key %s",
			secretName, gcpSecretJSONKey)
	}

	return jsonBytes, nil
}
