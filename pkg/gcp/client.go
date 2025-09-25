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

	iamcloud "cloud.google.com/go/iam"
	storage "cloud.google.com/go/storage"
	"golang.org/x/oauth2/google"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	compute "google.golang.org/api/compute/v1"
	iam "google.golang.org/api/iam/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	serviceusage "google.golang.org/api/serviceusage/v1"
)

//go:generate mockgen -source=./client.go -destination=./mock/client_generated.go -package=mock

// Client is a wrapper object for actual GCP libraries to allow for easier mocking/testing.
type Client interface {
	//IAM
	CreateServiceAccount(context.Context, string, *iam.CreateServiceAccountRequest) (*iam.ServiceAccount, error)
	CreateServiceAccountKey(context.Context, string, *iam.CreateServiceAccountKeyRequest) (*iam.ServiceAccountKey, error)
	DeleteServiceAccount(context.Context, string) error
	DeleteServiceAccountKey(context.Context, string) error
	GetRole(context.Context, string) (*iam.Role, error)
	CreateRole(context.Context, string, *iam.CreateRoleRequest) (*iam.Role, error)
	UpdateRole(context.Context, string, *iam.Role) (*iam.Role, error)
	DeleteRole(context.Context, string) (*iam.Role, error)
	UndeleteRole(context.Context, string, *iam.UndeleteRoleRequest) (*iam.Role, error)
	ListRoles(context.Context, string, string) (*iam.ListRolesResponse, error)
	GetServiceAccount(context.Context, string) (*iam.ServiceAccount, error)
	ListServiceAccountKeys(context.Context, string, string) (*iam.ListServiceAccountKeysResponse, error)
	ListServiceAccounts(context.Context, string, string) (*iam.ListServiceAccountsResponse, error)
	QueryTestablePermissions(context.Context, *iam.QueryTestablePermissionsRequest) (*iam.QueryTestablePermissionsResponse, error)
	CreateWorkloadIdentityPool(context.Context, string, string, *iam.WorkloadIdentityPool) (*iam.Operation, error)
	GetWorkloadIdentityPool(context.Context, string) (*iam.WorkloadIdentityPool, error)
	DeleteWorkloadIdentityPool(context.Context, string) (*iam.Operation, error)
	UndeleteWorkloadIdentityPool(context.Context, string, *iam.UndeleteWorkloadIdentityPoolRequest) (*iam.Operation, error)
	CreateWorkloadIdentityProvider(context.Context, string, string, *iam.WorkloadIdentityPoolProvider) (*iam.Operation, error)
	GetWorkloadIdentityProvider(context.Context, string) (*iam.WorkloadIdentityPoolProvider, error)

	//CloudResourceManager
	GetProjectName() string
	GetProject(ctx context.Context, projectName string) (*cloudresourcemanager.Project, error)
	GetProjectIamPolicy(string, *cloudresourcemanager.GetIamPolicyRequest) (*cloudresourcemanager.Policy, error)
	SetProjectIamPolicy(string, *cloudresourcemanager.SetIamPolicyRequest) (*cloudresourcemanager.Policy, error)
	GetServiceAccountIamPolicy(string) (*iam.Policy, error)
	SetServiceAccountIamPolicy(string, *iam.SetIamPolicyRequest) (*iam.Policy, error)
	TestIamPermissions(string, *cloudresourcemanager.TestIamPermissionsRequest) (*cloudresourcemanager.TestIamPermissionsResponse, error)

	//ServiceUsage
	ListServicesEnabled() (map[string]bool, error)

	//Storage
	CreateBucket(context.Context, string, string, *storage.BucketAttrs) error
	GetBucketAttrs(context.Context, string) (*storage.BucketAttrs, error)
	GetBucketPolicy(context.Context, string) (*iamcloud.Policy3, error)
	SetBucketPolicy(context.Context, string, *iamcloud.Policy3) error
	DeleteBucket(context.Context, string) error
	ListObjects(context.Context, string) ([]*storage.ObjectAttrs, error)
	PutObject(context.Context, string, string, []byte) error
	DeleteObject(context.Context, string, string) error
}

type gcpClient struct {
	projectName                string
	creds                      *google.Credentials
	cloudResourceManagerClient *cloudresourcemanager.Service
	iamService                 *iam.Service
	serviceUsageClient         *serviceusage.Service
	storageClient              *storage.Client
}

const (
	defaultCallTimeout = 2 * time.Minute
)

func contextWithTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, defaultCallTimeout)
}

func (c *gcpClient) CreateServiceAccount(ctx context.Context, name string, request *iam.CreateServiceAccountRequest) (*iam.ServiceAccount, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamService.Projects.ServiceAccounts.Create(name, request).Context(ctx).Do()
}

func (c *gcpClient) CreateServiceAccountKey(ctx context.Context, name string, request *iam.CreateServiceAccountKeyRequest) (*iam.ServiceAccountKey, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamService.Projects.ServiceAccounts.Keys.Create(name, request).Context(ctx).Do()
}

func (c *gcpClient) DeleteServiceAccount(ctx context.Context, name string) error {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	_, err := c.iamService.Projects.ServiceAccounts.Delete(name).Context(ctx).Do()
	return err
}

func (c *gcpClient) DeleteServiceAccountKey(ctx context.Context, name string) error {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	_, err := c.iamService.Projects.ServiceAccounts.Keys.Delete(name).Context(ctx).Do()
	return err
}

func (c *gcpClient) GetRole(ctx context.Context, name string) (*iam.Role, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamService.Projects.Roles.Get(name).Context(ctx).Do()
}

func (c *gcpClient) CreateRole(ctx context.Context, name string, request *iam.CreateRoleRequest) (*iam.Role, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamService.Projects.Roles.Create(name, request).Context(ctx).Do()
}

func (c *gcpClient) UpdateRole(ctx context.Context, name string, request *iam.Role) (*iam.Role, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamService.Projects.Roles.Patch(name, request).Context(ctx).Do()
}

func (c *gcpClient) DeleteRole(ctx context.Context, name string) (*iam.Role, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamService.Projects.Roles.Delete(name).Context(ctx).Do()
}

func (c *gcpClient) UndeleteRole(ctx context.Context, name string, request *iam.UndeleteRoleRequest) (*iam.Role, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamService.Projects.Roles.Undelete(name, request).Context(ctx).Do()
}

func (c *gcpClient) ListRoles(ctx context.Context, name string, pageToken string) (*iam.ListRolesResponse, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamService.Projects.Roles.List(name).Context(ctx).PageToken(pageToken).Do()
}

func (c *gcpClient) GetServiceAccount(ctx context.Context, name string) (*iam.ServiceAccount, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamService.Projects.ServiceAccounts.Get(name).Context(ctx).Do()
}

func (c *gcpClient) ListServiceAccountKeys(ctx context.Context, name, keyTypes string) (*iam.ListServiceAccountKeysResponse, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamService.Projects.ServiceAccounts.Keys.List(name).KeyTypes(keyTypes).Context(ctx).Do()
}

func (c *gcpClient) ListServiceAccounts(ctx context.Context, name string, pageToken string) (*iam.ListServiceAccountsResponse, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamService.Projects.ServiceAccounts.List(name).Context(ctx).PageToken(pageToken).Do()
}

func (c *gcpClient) GetProjectIamPolicy(projectName string, request *cloudresourcemanager.GetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
	ctx, cancel := contextWithTimeout(context.TODO())
	defer cancel()
	return c.cloudResourceManagerClient.Projects.GetIamPolicy(projectName, request).Context(ctx).Do()
}

func (c *gcpClient) GetServiceAccountIamPolicy(svcAcctResource string) (*iam.Policy, error) {
	ctx, cancel := contextWithTimeout(context.TODO())
	defer cancel()
	return c.iamService.Projects.ServiceAccounts.GetIamPolicy(svcAcctResource).Context(ctx).Do()
}

func (c *gcpClient) GetProjectName() string {
	return c.projectName
}

func (c *gcpClient) GetProject(ctx context.Context, projectName string) (*cloudresourcemanager.Project, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.cloudResourceManagerClient.Projects.Get(projectName).Context(ctx).Do()
}

func (c *gcpClient) SetProjectIamPolicy(svcAcctResource string, request *cloudresourcemanager.SetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
	ctx, cancel := contextWithTimeout(context.TODO())
	defer cancel()
	return c.cloudResourceManagerClient.Projects.SetIamPolicy(svcAcctResource, request).Context(ctx).Do()
}

func (c *gcpClient) SetServiceAccountIamPolicy(serviceAccountEmail string, request *iam.SetIamPolicyRequest) (*iam.Policy, error) {
	ctx, cancel := contextWithTimeout(context.TODO())
	defer cancel()
	return c.iamService.Projects.ServiceAccounts.SetIamPolicy(serviceAccountEmail, request).Context(ctx).Do()
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

func (c *gcpClient) QueryTestablePermissions(ctx context.Context, request *iam.QueryTestablePermissionsRequest) (*iam.QueryTestablePermissionsResponse, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamService.Permissions.QueryTestablePermissions(request).Context(ctx).Do()
}

func (c *gcpClient) CreateWorkloadIdentityPool(ctx context.Context, parent, poolID string, pool *iam.WorkloadIdentityPool) (*iam.Operation, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamService.Projects.Locations.WorkloadIdentityPools.Create(parent, pool).WorkloadIdentityPoolId(poolID).Context(ctx).Do()
}

func (c *gcpClient) GetWorkloadIdentityPool(ctx context.Context, resource string) (*iam.WorkloadIdentityPool, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamService.Projects.Locations.WorkloadIdentityPools.Get(resource).Context(ctx).Do()
}

func (c *gcpClient) DeleteWorkloadIdentityPool(ctx context.Context, resource string) (*iam.Operation, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamService.Projects.Locations.WorkloadIdentityPools.Delete(resource).Context(ctx).Do()
}

func (c *gcpClient) UndeleteWorkloadIdentityPool(ctx context.Context, resource string, request *iam.UndeleteWorkloadIdentityPoolRequest) (*iam.Operation, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamService.Projects.Locations.WorkloadIdentityPools.Undelete(resource, request).Context(ctx).Do()
}

func (c *gcpClient) CreateWorkloadIdentityProvider(ctx context.Context, parent, providerID string, provider *iam.WorkloadIdentityPoolProvider) (*iam.Operation, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamService.Projects.Locations.WorkloadIdentityPools.Providers.Create(parent, provider).WorkloadIdentityPoolProviderId(providerID).Context(ctx).Do()
}

func (c *gcpClient) GetWorkloadIdentityProvider(ctx context.Context, resource string) (*iam.WorkloadIdentityPoolProvider, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.iamService.Projects.Locations.WorkloadIdentityPools.Providers.Get(resource).Context(ctx).Do()
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

func (c *gcpClient) CreateBucket(ctx context.Context, bucketName, project string, attributes *storage.BucketAttrs) error {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.storageClient.Bucket(bucketName).Create(ctx, project, attributes)
}

func (c *gcpClient) GetBucketAttrs(ctx context.Context, bucketName string) (*storage.BucketAttrs, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.storageClient.Bucket(bucketName).Attrs(ctx)
}

func (c *gcpClient) GetBucketPolicy(ctx context.Context, bucketName string) (*iamcloud.Policy3, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.storageClient.Bucket(bucketName).IAM().V3().Policy(ctx)
}

func (c *gcpClient) SetBucketPolicy(ctx context.Context, bucketName string, policy *iamcloud.Policy3) error {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.storageClient.Bucket(bucketName).IAM().V3().SetPolicy(ctx, policy)
}

func (c *gcpClient) PutObject(ctx context.Context, bucketName, objectName string, data []byte) error {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	obj := c.storageClient.Bucket(bucketName).Object(objectName)
	w := obj.NewWriter(ctx)
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return nil
}

func (c *gcpClient) DeleteBucket(ctx context.Context, bucketName string) error {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.storageClient.Bucket(bucketName).Delete(ctx)
}

func (c *gcpClient) ListObjects(ctx context.Context, bucketName string) ([]*storage.ObjectAttrs, error) {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	var objectAttrs []*storage.ObjectAttrs
	it := c.storageClient.Bucket(bucketName).Objects(ctx, nil)
	for {
		attrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to fetch objects from bucket %s: %v", bucketName, err)
		}
		objectAttrs = append(objectAttrs, attrs)
	}
	return objectAttrs, nil
}

func (c *gcpClient) DeleteObject(ctx context.Context, bucketName, objectName string) error {
	ctx, cancel := contextWithTimeout(ctx)
	defer cancel()
	return c.storageClient.Bucket(bucketName).Object(objectName).Delete(ctx)
}

// NewClient creates our client wrapper object for interacting with GCP.
func NewClient(projectName string, creds *google.Credentials) (Client, error) {
	ctx := context.TODO()

	cloudResourceManagerClient, err := cloudresourcemanager.NewService(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}

	iamService, err := iam.NewService(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}

	serviceUsageClient, err := serviceusage.NewService(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}

	storageClient, err := storage.NewClient(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}

	return &gcpClient{
		projectName:                projectName,
		creds:                      creds,
		cloudResourceManagerClient: cloudResourceManagerClient,
		iamService:                 iamService,
		serviceUsageClient:         serviceUsageClient,
		storageClient:              storageClient,
	}, nil
}

func NewClientFromJSON(projectName string, authJSON []byte) (Client, error) {
	var creds *google.Credentials
	var err error
	// since we're using a single creds var, we should specify all the required scopes when initializing
	creds, err = google.CredentialsFromJSON(context.TODO(), authJSON, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	return NewClient(projectName, creds)
}
