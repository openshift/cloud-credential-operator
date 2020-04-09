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
	annotatorconst "github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/constants"
	corev1 "k8s.io/api/core/v1"
)

type secret struct {
	corev1.Secret
}

func (s *secret) HasAnnotation() bool {
	if s.ObjectMeta.Annotations == nil {
		return false
	}

	if _, ok := s.ObjectMeta.Annotations[annotatorconst.AnnotationKey]; !ok {
		return false
	}

	return true
}

func (s *secret) Clone() *secret {
	return &secret{*s.Secret.DeepCopy()}
}
