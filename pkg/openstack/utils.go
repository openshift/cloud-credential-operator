/*
Copyright 2021 The OpenShift Authors.

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
package openstack

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

const (
	RootOpenStackCredsSecretKey = "clouds.yaml"
	OpenStackCloudName          = "openstack"
	CACertFile                  = "/etc/kubernetes/static-pod-resources/configmaps/cloud-config/ca-bundle.pem"
)

func GetRootCloudCredentialsSecretData(cloudCredSecret *corev1.Secret, logger log.FieldLogger) (string, error) {
	var clouds string

	keyBytes, ok := cloudCredSecret.Data[RootOpenStackCredsSecretKey]
	if !ok {
		return "", fmt.Errorf("secret did not have expected key: %v", RootOpenStackCredsSecretKey)
	}

	clouds = string(keyBytes)
	logger.Debug("found clouds.yaml in target secret")

	return clouds, nil
}
