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

package gcp

import (
	"context"
	"fmt"
	"time"

	// GCP auth
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"

	// API Client Libraries (classic libs)
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	serviceusage "google.golang.org/api/serviceusage/v1"

	// Cloud Client Libraries
	iamadmin "cloud.google.com/go/iam/admin/apiv1"
	iamadminpb "google.golang.org/genproto/googleapis/iam/admin/v1"
)

//go:generate mockgen -source=./client.go -destination=./mock/client_generated.go -package=mock

// Client is a wrapper object for actual GCP libraries to allow for easier mocking/testing.
type Client interface {
	//IAM
	CreateServiceAccount(context.Context, *iamadminpb.CreateServiceAccountRequest) (*iamadminpb.ServiceAccount, error)
	CreateServiceAccountKey(context.Context, *iamadminpb.CreateServiceAccountKeyRequest) (*iamadminpb.ServiceAccountKey, error)
	DeleteServiceAccount(context.Context, *iamadminpb.DeleteServiceAccountRequest) error
	DeleteServiceAccountKey(context.Context, *iamadminpb.DeleteServiceAccountKeyRequest) error
	GetRole(context.Context, *iamadminpb.GetRoleRequest) (*iamadminpb.Role, error)
	GetServiceAccount(context.Context, *iamadminpb.GetServiceAccountRequest) (*iamadminpb.ServiceAccount, error)
	ListServiceAccountKeys(context.Context, *iamadminpb.ListServiceAccountKeysRequest) (*iamadminpb.ListServiceAccountKeysResponse, error)

	//CloudResourceManager
	GetProjectIamPolicy(projectName string, request *cloudresourcemanager.GetIamPolicyRequest) (*cloudresourcemanager.Policy, error)
	GetProjectName() string
	SetProjectIamPolicy(projectName string, request *cloudresourcemanager.SetIamPolicyRequest) (*cloudresourcemanager.Policy, error)
	TestIamPermissions(string, *cloudresourcemanager.TestIamPermissionsRequest) (*cloudresourcemanager.TestIamPermissionsResponse, error)

	//ServiceUsage
	ListServicesEnabled() (map[string]bool, error)
}

type gcpClient struct {
	projectName                string
	creds                      *google.Credentials
	cloudResourceManagerClient *cloudresourcemanager.Service
	iamClient                  *iamadmin.IamClient
	serviceUsageClient         *serviceusage.Service
}

const (
	defaultCallTimeout = 2 * time.Minute
)

func contextWithTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, defaultCallTimeout)
}

func (c *gcpClient) CreateServiceAccount(ctx context.Context, request *iamadminpb.CreateServiceAccountRequest) (*iamadminpb.ServiceAccount, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	svcAcct, err := c.iamClient.CreateServiceAccount(ctx, request)
	return svcAcct, err
}

func (c *gcpClient) CreateServiceAccountKey(ctx context.Context, request *iamadminpb.CreateServiceAccountKeyRequest) (*iamadminpb.ServiceAccountKey, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamClient.CreateServiceAccountKey(ctx, request)
}

func (c *gcpClient) DeleteServiceAccount(ctx context.Context, request *iamadminpb.DeleteServiceAccountRequest) error {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamClient.DeleteServiceAccount(ctx, request)
}

func (c *gcpClient) DeleteServiceAccountKey(ctx context.Context, request *iamadminpb.DeleteServiceAccountKeyRequest) error {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamClient.DeleteServiceAccountKey(ctx, request)
}

func (c *gcpClient) GetRole(ctx context.Context, request *iamadminpb.GetRoleRequest) (*iamadminpb.Role, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamClient.GetRole(ctx, request)
}

func (c *gcpClient) GetServiceAccount(ctx context.Context, request *iamadminpb.GetServiceAccountRequest) (*iamadminpb.ServiceAccount, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamClient.GetServiceAccount(ctx, request)
}

func (c *gcpClient) ListServiceAccountKeys(ctx context.Context, request *iamadminpb.ListServiceAccountKeysRequest) (*iamadminpb.ListServiceAccountKeysResponse, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamClient.ListServiceAccountKeys(ctx, request)
}

func (c *gcpClient) GetProjectIamPolicy(projectName string, request *cloudresourcemanager.GetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
	ctx, cancel := contextWithTimeout(context.TODO())
	defer cancel()
	return c.cloudResourceManagerClient.Projects.GetIamPolicy(projectName, request).Context(ctx).Do()
}

func (c *gcpClient) GetProjectName() string {
	return c.projectName
}

func (c *gcpClient) SetProjectIamPolicy(projectName string, request *cloudresourcemanager.SetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
	ctx, cancel := contextWithTimeout(context.TODO())
	defer cancel()
	return c.cloudResourceManagerClient.Projects.SetIamPolicy(projectName, request).Context(ctx).Do()
}

func (c *gcpClient) TestIamPermissions(projectName string, permRequest *cloudresourcemanager.TestIamPermissionsRequest) (*cloudresourcemanager.TestIamPermissionsResponse, error) {
	ctx, cancel := contextWithTimeout(context.TODO())
	defer cancel()
	response, err := c.cloudResourceManagerClient.Projects.TestIamPermissions(projectName, permRequest).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (c *gcpClient) ListServicesEnabled() (map[string]bool, error) {
	serviceMap := map[string]bool{}

	ctx, cancel := contextWithTimeout(context.TODO())
	defer cancel()
	proj, err := c.cloudResourceManagerClient.Projects.Get(c.GetProjectName()).Context(ctx).Do()
	if err != nil {
		return serviceMap, fmt.Errorf("error getting project number: %v", err)
	}

	// serviceusageService.Services.List() requires us to provide the missing
	// piece in the following REST format: https://serviceusage.googleapis.com/v1/{parent=*/*}/services
	// where {parent=*/*} should be the object type and it's name/ID (in our case 'projects' and
	// the project number)
	listQueryString := fmt.Sprintf("projects/%d", proj.ProjectNumber)
	listSvcCtx, listSvcCancel := contextWithTimeout(context.TODO())
	defer listSvcCancel()
	req := c.serviceUsageClient.Services.List(listQueryString).Filter("state:ENABLED")
	err = req.Pages(listSvcCtx, func(listResponse *serviceusage.ListServicesResponse) error {
		for _, service := range listResponse.Services {
			serviceMap[service.Config.Name] = true
		}
		return nil
	})
	if err != nil {
		return serviceMap, fmt.Errorf("error listing services: %v", err)
	}
	fixupServiceMap(serviceMap)

	return serviceMap, nil
}

func fixupServiceMap(serviceMap map[string]bool) {
	// Every API permission has a form of <service>.<category>.<action>
	// where <service>.googleapis.com is the name of the service.
	//
	// ...All of them except for the one(s) below where the naming scheme
	// doesn't match up.
	// Manually fix up the serviceMap so that we can pretend that the above
	// description is always true.

	if val, ok := serviceMap["cloudresourcemanager.googleapis.com"]; ok {
		serviceMap["resourcemanager.googleapis.com"] = val
	}
}

// NewClient creates our client wrapper object for interacting with GCP.
func NewClient(projectName string, authJSON []byte) (Client, error) {
	ctx := context.TODO()

	// since we're using a single creds var, we should specify all the required scopes when initializing
	creds, err := google.CredentialsFromJSON(context.TODO(), authJSON, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, err
	}

	cloudResourceManagerClient, err := cloudresourcemanager.NewService(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}

	iamClient, err := iamadmin.NewIamClient(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}

	serviceUsageClient, err := serviceusage.NewService(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}

	return &gcpClient{
		projectName:                projectName,
		creds:                      creds,
		cloudResourceManagerClient: cloudResourceManagerClient,
		iamClient:                  iamClient,
		serviceUsageClient:         serviceUsageClient,
	}, nil
}
