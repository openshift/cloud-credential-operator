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
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials/provider"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"log"
)

//go:generate mockgen -source=./client.go -destination=./mock/client_generated.go -package=mock

// Client is a wrapper object for actual Alibaba Cloud SDK clients to allow for easier testing.
type Client interface {
	//RAM
	CreatePolicy(*ram.CreatePolicyRequest) (*ram.CreatePolicyResponse, error)
	GetPolicy(*ram.GetPolicyRequest) (*ram.GetPolicyResponse, error)
	CreatePolicyVersion(*ram.CreatePolicyVersionRequest) (*ram.CreatePolicyVersionResponse, error)
	AttachPolicyToUser(*ram.AttachPolicyToUserRequest) (*ram.AttachPolicyToUserResponse, error)
	CreateUser(*ram.CreateUserRequest) (*ram.CreateUserResponse, error)
	GetUser(*ram.GetUserRequest) (*ram.GetUserResponse, error)
	DeleteUser(*ram.DeleteUserRequest) (*ram.DeleteUserResponse, error)
	CreateAccessKey(*ram.CreateAccessKeyRequest) (*ram.CreateAccessKeyResponse, error)
	ListAccessKeys(*ram.ListAccessKeysRequest) (*ram.ListAccessKeysResponse, error)
	DeleteAccessKey(*ram.DeleteAccessKeyRequest) (*ram.DeleteAccessKeyResponse, error)
	DeletePolicy(request *ram.DeletePolicyRequest) (response *ram.DeletePolicyResponse, err error)
	DetachPolicyFromUser(request *ram.DetachPolicyFromUserRequest) (response *ram.DetachPolicyFromUserResponse, err error)
	ListPoliciesForUser(request *ram.ListPoliciesForUserRequest) (response *ram.ListPoliciesForUserResponse, err error)
}

type alibabaCloudClient struct {
	ramClient *ram.Client
}

func (c *alibabaCloudClient) CreatePolicy(request *ram.CreatePolicyRequest) (response *ram.CreatePolicyResponse, err error) {
	return c.ramClient.CreatePolicy(request)
}

func (c *alibabaCloudClient) GetPolicy(request *ram.GetPolicyRequest) (response *ram.GetPolicyResponse, err error) {
	return c.ramClient.GetPolicy(request)
}

func (c *alibabaCloudClient) CreatePolicyVersion(request *ram.CreatePolicyVersionRequest) (response *ram.CreatePolicyVersionResponse, err error) {
	return c.ramClient.CreatePolicyVersion(request)
}

func (c *alibabaCloudClient) AttachPolicyToUser(input *ram.AttachPolicyToUserRequest) (*ram.AttachPolicyToUserResponse, error) {
	return c.ramClient.AttachPolicyToUser(input)
}

func (c *alibabaCloudClient) DeletePolicy(request *ram.DeletePolicyRequest) (response *ram.DeletePolicyResponse, err error) {
	return c.ramClient.DeletePolicy(request)
}

func (c *alibabaCloudClient) DetachPolicyFromUser(request *ram.DetachPolicyFromUserRequest) (response *ram.DetachPolicyFromUserResponse, err error) {
	return c.ramClient.DetachPolicyFromUser(request)
}

func (c *alibabaCloudClient) ListPoliciesForUser(request *ram.ListPoliciesForUserRequest) (response *ram.ListPoliciesForUserResponse, err error) {
	return c.ramClient.ListPoliciesForUser(request)
}

func (c *alibabaCloudClient) CreateUser(input *ram.CreateUserRequest) (*ram.CreateUserResponse, error) {
	return c.ramClient.CreateUser(input)
}

func (c *alibabaCloudClient) GetUser(input *ram.GetUserRequest) (*ram.GetUserResponse, error) {
	return c.ramClient.GetUser(input)
}

func (c *alibabaCloudClient) DeleteUser(input *ram.DeleteUserRequest) (*ram.DeleteUserResponse, error) {
	return c.ramClient.DeleteUser(input)
}

func (c *alibabaCloudClient) ListAccessKeys(input *ram.ListAccessKeysRequest) (*ram.ListAccessKeysResponse, error) {
	return c.ramClient.ListAccessKeys(input)
}

func (c *alibabaCloudClient) CreateAccessKey(input *ram.CreateAccessKeyRequest) (*ram.CreateAccessKeyResponse, error) {
	return c.ramClient.CreateAccessKey(input)
}

func (c *alibabaCloudClient) DeleteAccessKey(input *ram.DeleteAccessKeyRequest) (*ram.DeleteAccessKeyResponse, error) {
	return c.ramClient.DeleteAccessKey(input)
}

// NewClient creates our client wrapper object for the actual Alibaba Cloud clients we use.
func NewClient(regionId string) (Client, error) {
	envProvider := provider.NewEnvProvider()
	profileProvider := provider.NewProfileProvider()
	pc := provider.NewProviderChain([]provider.Provider{envProvider, profileProvider})
	credential, err := pc.Resolve()
	if err != nil {
		log.Fatalf("Failed to resolve an authentication provider: %v", err)
	}
	config := sdk.NewConfig().WithScheme("https")

	rc, err := ram.NewClientWithOptions(regionId, config, credential)
	if err != nil {
		return nil, err
	}
	return &alibabaCloudClient{
		ramClient: rc,
	}, nil
}
