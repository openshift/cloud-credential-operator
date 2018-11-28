/*
Copyright 2018 The OpenShift Authors.

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

package v1beta1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: Run "make" to regenerate code after modifying this file

// CredentialsRequestSpec defines the desired state of CredentialsRequest
type CredentialsRequestSpec struct {

	// Secret points to the secret where the credentials should be stored once generated.
	Secret corev1.ObjectReference `json:"secret"`

	// AWS contains the details for credentials requested for an AWS cluster component.
	AWS *AWSCreds `json:"awsCreds,omitempty"`
}

type AWSCreds struct {
	Actions []string
}

// CredentialsRequestStatus defines the observed state of CredentialsRequest
type CredentialsRequestStatus struct {
	// Provisioned is true once the credentials have been initially provisioned.
	Provisioned bool `json:"provisioned"`

	// LastSyncTimestamp is the time that the zone was last sync'd.
	LastSyncTimestamp *metav1.Time `json:"lastSyncTimestamp,omitempty"`

	// LastSyncGeneration is the generation of the credentials request resource
	// that was last synced. Used to determine if the object has changed and
	// requires a sync.
	LastSyncGeneration int64 `json:"lastSyncGeneration"`

	// AWS contains AWS specific status.
	AWS *AWSStatus `json:"aws,omitempty"`
}

type AWSStatus struct {
	// Role is the name of the role created in AWS for these credentials.
	Role string `json:"role"`
	// User is the name of the User created in AWS for these credentials.
	User string `json:"user"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CredentialsRequest is the Schema for the credentialsrequests API
// +k8s:openapi-gen=true
// +kubebuilder:subresource:status
type CredentialsRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CredentialsRequestSpec   `json:"spec"`
	Status CredentialsRequestStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CredentialsRequestList contains a list of CredentialsRequest
type CredentialsRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CredentialsRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CredentialsRequest{}, &CredentialsRequestList{})
}
