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

package aws

import (
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"

	"github.com/openshift/cloud-credential-operator/pkg/version"
)

//go:generate mockgen -source=./client.go -destination=./mock/client_generated.go -package=mock

// Client is a wrapper object for actual AWS SDK clients to allow for easier testing.
type Client interface {
	//IAM
	CreateAccessKey(*iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error)
	CreateUser(*iam.CreateUserInput) (*iam.CreateUserOutput, error)
	DeleteAccessKey(*iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error)
	DeleteUser(*iam.DeleteUserInput) (*iam.DeleteUserOutput, error)
	DeleteUserPolicy(*iam.DeleteUserPolicyInput) (*iam.DeleteUserPolicyOutput, error)
	GetUser(*iam.GetUserInput) (*iam.GetUserOutput, error)
	ListAccessKeys(*iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error)
	ListUserPolicies(*iam.ListUserPoliciesInput) (*iam.ListUserPoliciesOutput, error)
	PutUserPolicy(*iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error)
	GetUserPolicy(*iam.GetUserPolicyInput) (*iam.GetUserPolicyOutput, error)
	SimulatePrincipalPolicy(*iam.SimulatePrincipalPolicyInput) (*iam.SimulatePolicyResponse, error)
	SimulatePrincipalPolicyPages(*iam.SimulatePrincipalPolicyInput, func(*iam.SimulatePolicyResponse, bool) bool) error
	TagUser(*iam.TagUserInput) (*iam.TagUserOutput, error)
	ListOpenIDConnectProviders(*iam.ListOpenIDConnectProvidersInput) (*iam.ListOpenIDConnectProvidersOutput, error)
	CreateOpenIDConnectProvider(*iam.CreateOpenIDConnectProviderInput) (*iam.CreateOpenIDConnectProviderOutput, error)
	TagOpenIDConnectProvider(*iam.TagOpenIDConnectProviderInput) (*iam.TagOpenIDConnectProviderOutput, error)
	GetOpenIDConnectProvider(input *iam.GetOpenIDConnectProviderInput) (*iam.GetOpenIDConnectProviderOutput, error)

	//S3
	CreateBucket(*s3.CreateBucketInput) (*s3.CreateBucketOutput, error)
	PutBucketTagging(*s3.PutBucketTaggingInput) (*s3.PutBucketTaggingOutput, error)
	PutObject(*s3.PutObjectInput) (*s3.PutObjectOutput, error)
}

// ClientParams holds the various optional tunables that can be used to modify the AWS
// client that will be used for API calls.
type ClientParams struct {
	InfraName string
	Region    string
	Endpoint  string
	CABundle  string
}

type AWSClient struct {
	IAMClient iamiface.IAMAPI
	S3Client  s3iface.S3API
}

func (c *AWSClient) CreateAccessKey(input *iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
	return c.IAMClient.CreateAccessKey(input)
}

func (c *AWSClient) CreateUser(input *iam.CreateUserInput) (*iam.CreateUserOutput, error) {
	return c.IAMClient.CreateUser(input)
}

func (c *AWSClient) DeleteAccessKey(input *iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error) {
	return c.IAMClient.DeleteAccessKey(input)
}

func (c *AWSClient) DeleteUser(input *iam.DeleteUserInput) (*iam.DeleteUserOutput, error) {
	return c.IAMClient.DeleteUser(input)
}

func (c *AWSClient) DeleteUserPolicy(input *iam.DeleteUserPolicyInput) (*iam.DeleteUserPolicyOutput, error) {
	return c.IAMClient.DeleteUserPolicy(input)
}
func (c *AWSClient) GetUser(input *iam.GetUserInput) (*iam.GetUserOutput, error) {
	return c.IAMClient.GetUser(input)
}

func (c *AWSClient) ListAccessKeys(input *iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
	return c.IAMClient.ListAccessKeys(input)
}

func (c *AWSClient) ListUserPolicies(input *iam.ListUserPoliciesInput) (*iam.ListUserPoliciesOutput, error) {
	return c.IAMClient.ListUserPolicies(input)
}

func (c *AWSClient) PutUserPolicy(input *iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error) {
	return c.IAMClient.PutUserPolicy(input)
}

func (c *AWSClient) GetUserPolicy(input *iam.GetUserPolicyInput) (*iam.GetUserPolicyOutput, error) {
	return c.IAMClient.GetUserPolicy(input)
}

func (c *AWSClient) SimulatePrincipalPolicy(input *iam.SimulatePrincipalPolicyInput) (*iam.SimulatePolicyResponse, error) {
	return c.IAMClient.SimulatePrincipalPolicy(input)
}

func (c *AWSClient) SimulatePrincipalPolicyPages(input *iam.SimulatePrincipalPolicyInput, fn func(*iam.SimulatePolicyResponse, bool) bool) error {
	return c.IAMClient.SimulatePrincipalPolicyPages(input, fn)
}

func (c *AWSClient) TagUser(input *iam.TagUserInput) (*iam.TagUserOutput, error) {
	return c.IAMClient.TagUser(input)
}

func (c *AWSClient) ListOpenIDConnectProviders(input *iam.ListOpenIDConnectProvidersInput) (*iam.ListOpenIDConnectProvidersOutput, error) {
	return c.IAMClient.ListOpenIDConnectProviders(input)
}

func (c *AWSClient) CreateOpenIDConnectProvider(input *iam.CreateOpenIDConnectProviderInput) (*iam.CreateOpenIDConnectProviderOutput, error) {
	return c.IAMClient.CreateOpenIDConnectProvider(input)
}

func (c *AWSClient) TagOpenIDConnectProvider(input *iam.TagOpenIDConnectProviderInput) (*iam.TagOpenIDConnectProviderOutput, error) {
	return c.IAMClient.TagOpenIDConnectProvider(input)
}

func (c *AWSClient) GetOpenIDConnectProvider(input *iam.GetOpenIDConnectProviderInput) (*iam.GetOpenIDConnectProviderOutput, error) {
	return c.IAMClient.GetOpenIDConnectProvider(input)
}

func (c *AWSClient) CreateBucket(input *s3.CreateBucketInput) (*s3.CreateBucketOutput, error) {
	return c.S3Client.CreateBucket(input)
}

func (c *AWSClient) PutBucketTagging(input *s3.PutBucketTaggingInput) (*s3.PutBucketTaggingOutput, error) {
	return c.S3Client.PutBucketTagging(input)
}

func (c *AWSClient) PutObject(input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	return c.S3Client.PutObject(input)
}

// NewClient creates our client wrapper object for the actual AWS clients we use.
func NewClient(accessKeyID, secretAccessKey []byte, params *ClientParams) (Client, error) {
	var awsOpts session.Options

	if params != nil {
		if params.Region != "" {
			awsOpts.Config.Region = aws.String(params.Region)
		}

		if params.Endpoint != "" {
			awsOpts.Config.Endpoint = aws.String(params.Endpoint)
		}
	}

	awsOpts.Config.Credentials = credentials.NewStaticCredentials(
		string(accessKeyID), string(secretAccessKey), "")

	if params.CABundle != "" {
		awsOpts.CustomCABundle = strings.NewReader(params.CABundle)
	}

	s, err := session.NewSessionWithOptions(awsOpts)
	if err != nil {
		return nil, err
	}

	agentText := "defaultAgent"
	if params != nil && params.InfraName != "" {
		agentText = params.InfraName
	}
	s.Handlers.Build.PushBackNamed(request.NamedHandler{
		Name: "openshift.io/cloud-credential-operator",
		Fn:   request.MakeAddToUserAgentHandler("openshift.io cloud-credential-operator", version.Get().String(), agentText),
	})

	return &AWSClient{
		IAMClient: iam.New(s),
		S3Client:  s3.New(s),
	}, nil
}
