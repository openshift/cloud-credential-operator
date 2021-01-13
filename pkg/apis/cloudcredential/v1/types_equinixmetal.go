/*
Copyright 2020 The OpenShift Authors.

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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TODO: these types should eventually be broken out, along with the actuator,
// to a separate repo.

// EquinixMetalProviderSpec contains the required information to create RBAC role
// bindings for EquinixMetal.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type EquinixMetalProviderSpec struct {
	metav1.TypeMeta `json:",inline"`
}

// EquinixMetalProviderStatus contains the status of the credentials request in EquinixMetal.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type EquinixMetalProviderStatus struct {
	metav1.TypeMeta `json:",inline"`
}
