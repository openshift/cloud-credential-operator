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

package alibabacloud

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
)

//go:generate mockgen -source=./client.go -destination=./mock/client_generated.go -package=mock

// Client is a wrapper object for actual Alibaba Cloud SDK clients to allow for easier testing.
type Client interface {
	//RAM
	CreatePolicy(*ram.CreatePolicyRequest) (*ram.CreatePolicyResponse, error)
	AttachPolicyToUser(*ram.AttachPolicyToUserRequest) (*ram.AttachPolicyToUserResponse, error)
	DeletePolicy(*ram.DeletePolicyRequest) (*ram.DeletePolicyResponse, error)
	DetachPolicyFromUser(*ram.DetachPolicyFromUserRequest) (*ram.DetachPolicyFromUserResponse, error)
}

type alibabaCloudClient struct {
	ramClient ram.Client
}

func (c *alibabaCloudClient) CreatePolicy(request *ram.CreatePolicyRequest) (response *ram.CreatePolicyResponse, err error) {
	return c.ramClient.CreatePolicy(request)
}

func (c *alibabaCloudClient) AttachPolicyToUser(input *ram.AttachPolicyToUserRequest) (*ram.AttachPolicyToUserResponse, error) {
	return c.ramClient.AttachPolicyToUser(input)
}

func (c *alibabaCloudClient) DeletePolicy(input *ram.DeletePolicyRequest) (*ram.DeletePolicyResponse, error) {
	return c.ramClient.DeletePolicy(input)
}

func (c *alibabaCloudClient) DetachPolicyFromUser(input *ram.DetachPolicyFromUserRequest) (*ram.DetachPolicyFromUserResponse, error) {
	return c.ramClient.DetachPolicyFromUser(input)
}

// NewClient creates our client wrapper object for the actual Alibaba Cloud clients we use.
func NewClient(accessKeyID, accessKeySecret, region string) (Client, error) {
	return ram.NewClientWithAccessKey(region, accessKeyID, accessKeySecret)
}
