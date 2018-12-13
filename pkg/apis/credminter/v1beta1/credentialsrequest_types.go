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

const (
	// FinalizerDeprovision is used on CredentialsRequests to ensure we delete the
	// credentials in AWS before allowing the CredentialsRequest to be deleted in etcd.
	FinalizerDeprovision string = "credminter.openshift.io/deprovision"

	// AnnotationCredentialsRequest is used on Secrets created as a target of CredentailsRequests.
	// The annotation value will map back to the namespace/name of the CredentialsRequest that created
	// or adopted the secret.
	AnnotationCredentialsRequest string = "credminter.openshift.io/credentials-request"
)

// NOTE: Run "make" to regenerate code after modifying this file

// CredentialsRequestSpec defines the desired state of CredentialsRequest
type CredentialsRequestSpec struct {

	// ClusterName is a user friendly name for the cluster these credentials are to be associated with.
	// It is used for naming the credential objects in the cloud provider, in conjunction with a random
	// suffix when necessary.
	ClusterName string `json:"clusterName"`

	// ClusterID is a unique identifier for the cluster these credentials belong to. Used to ensure
	// credentials are cleaned up during deprovision.
	ClusterID string `json:"clusterID"`

	// SecretRef points to the secret where the credentials should be stored once generated.
	SecretRef corev1.ObjectReference `json:"secretRef"`

	// AWS contains the details for credentials requested for an AWS cluster component.
	AWS *AWSCreds `json:"aws,omitempty"`
}

// AWSCreds contains the required information to create a user policy in AWS.
type AWSCreds struct {
	// StatementEntries contains a list of policy statements that should be associated with this credentials access key.
	StatementEntries []StatementEntry `json:"statementEntries"`
}

// StatementEntry models an AWS policy statement entry.
type StatementEntry struct {
	// Effect indicates if this policy statement is to Allow or Deny.
	Effect string `json:"effect"`
	// Action describes the particular AWS service actions that should be allowed or denied. (i.e. ec2:StartInstances, iam:ChangePassword)
	Action []string `json:"action"`
	// Resource specifies the object(s) this statement should apply to. (or "*" for all)
	Resource string `json:"resource"`
}

// CredentialsRequestStatus defines the observed state of CredentialsRequest
type CredentialsRequestStatus struct {
	// Provisioned is true once the credentials have been initially provisioned.
	Provisioned bool `json:"provisioned"`

	// LastSyncTimestamp is the time that the credentials were last synced.
	LastSyncTimestamp *metav1.Time `json:"lastSyncTimestamp,omitempty"`

	// LastSyncGeneration is the generation of the credentials request resource
	// that was last synced. Used to determine if the object has changed and
	// requires a sync.
	LastSyncGeneration int64 `json:"lastSyncGeneration"`

	// AWS contains AWS specific status.
	AWS *AWSStatus `json:"aws,omitempty"`
}

// AWSStatus containes the status of the credentials request in AWS.
type AWSStatus struct {
	// User is the name of the User created in AWS for these credentials.
	User string `json:"user"`

	// AccessKeyID is the ID of the access key created in AWS for this user and saved in the requested secret.
	AccessKeyID string `json:"accessKeyID"`
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
