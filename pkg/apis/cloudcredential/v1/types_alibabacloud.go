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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TODO: these types should eventually be broken out, along with the actuator, to a separate repo.

// AlibabaCloudProviderSpec is the specification of the credentials request in Alibaba Cloud.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type AlibabaCloudProviderSpec struct {
	metav1.TypeMeta `json:",inline"`
	Statement       []Entry `json:"statement"`
}

// Entry models an Alibaba Cloud policy statement entry.
type Entry struct {
	// Effect indicates if this policy statement is to Allow or Deny.
	Effect string `json:"effect"`
	// Action describes the particular Alibaba Cloud service actions that should be allowed or denied. (i.e. ecs:StartInstances, actiontrail:LookupEvents)
	Action []string `json:"action"`
	// Resource specifies the object(s) this statement should apply to. (or "*" for all)
	Resource string `json:"resource"`
	// Condition specifies under which condition Entry will apply
	Condition Condition `json:"condition,omitempty"`
}

// Condition - map of condition types, with associated key - value mapping
// +k8s:deepcopy-gen=false
type Condition map[string]ConditionKeyValue

// ConditionKeyValue - mapping of values for the chosen type
// +k8s:deepcopy-gen=false
type ConditionKeyValue map[string]interface{}

// AlibabaCloudProviderStatus contains the status of the Alibaba Cloud credentials request.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type AlibabaCloudProviderStatus struct {
	metav1.TypeMeta `json:",inline"`
}
