package azure

import (
	"context"
	"errors"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	armauthorization "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/applications"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
)

//go:generate mockgen -source=./clients.go -destination=./mock/client_generated.go -package=mock

// AppClient is a wrapper object for actual Azure SDK to allow for easier testing.
type AppClient interface {
	List(ctx context.Context, filter string) ([]models.Applicationable, error)
	Delete(ctx context.Context, applicationObjectID string) error
}

type appClient struct {
	client *msgraphsdk.GraphServiceClient
}

func (appClient *appClient) List(ctx context.Context, filter string) ([]models.Applicationable, error) {
	listQuery := applications.ApplicationsRequestBuilderGetRequestConfiguration{
		QueryParameters: &applications.ApplicationsRequestBuilderGetQueryParameters{
			Filter: &filter,
		},
	}
	appResp, err := appClient.client.Applications().Get(ctx, &listQuery)
	if err != nil {
		return nil, err
	}

	return appResp.GetValue(), nil
}

func (appClient *appClient) Delete(ctx context.Context, applicationObjectID string) error {
	return appClient.client.ApplicationsById(applicationObjectID).Delete(ctx, nil)
}

var _ AppClient = &appClient{}

func NewAppClient(authorizer *msgraphsdk.GraphRequestAdapter) *appClient {
	client := msgraphsdk.NewGraphServiceClient(authorizer)

	return &appClient{
		client: client,
	}
}

type ResourceGroupsClient interface {
	Get(ctx context.Context, resourceGroupName string, options *armresources.ResourceGroupsClientGetOptions) (armresources.ResourceGroupsClientGetResponse, error)
	CreateOrUpdate(ctx context.Context, resourceGroupName string, parameters armresources.ResourceGroup, options *armresources.ResourceGroupsClientCreateOrUpdateOptions) (armresources.ResourceGroupsClientCreateOrUpdateResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, options *armresources.ResourceGroupsClientBeginDeleteOptions) (*runtime.Poller[armresources.ResourceGroupsClientDeleteResponse], error)
}

type resourceGroupsClient struct {
	client *armresources.ResourceGroupsClient
}

func NewResourceGroupsClient(subscriptionID string, cred azcore.TokenCredential, options *policy.ClientOptions) (*resourceGroupsClient, error) {
	client, err := armresources.NewResourceGroupsClient(subscriptionID, cred, options)
	if err != nil {
		return nil, err
	}
	return &resourceGroupsClient{client: client}, nil
}

func (resourceGroupsClient *resourceGroupsClient) Get(ctx context.Context, resourceGroupName string, options *armresources.ResourceGroupsClientGetOptions) (armresources.ResourceGroupsClientGetResponse, error) {
	return resourceGroupsClient.client.Get(ctx, resourceGroupName, options)
}

func (resourceGroupsClient *resourceGroupsClient) CreateOrUpdate(ctx context.Context, resourceGroupName string, parameters armresources.ResourceGroup, options *armresources.ResourceGroupsClientCreateOrUpdateOptions) (armresources.ResourceGroupsClientCreateOrUpdateResponse, error) {
	return resourceGroupsClient.client.CreateOrUpdate(ctx, resourceGroupName, parameters, options)
}

func (resourceGroupsClient *resourceGroupsClient) BeginDelete(ctx context.Context, resourceGroupName string, options *armresources.ResourceGroupsClientBeginDeleteOptions) (*runtime.Poller[armresources.ResourceGroupsClientDeleteResponse], error) {
	return resourceGroupsClient.client.BeginDelete(ctx, resourceGroupName, options)
}

type AccountsClient interface {
	NewListByResourceGroupPager(resourceGroupName string, options *armstorage.AccountsClientListByResourceGroupOptions) *runtime.Pager[armstorage.AccountsClientListByResourceGroupResponse]
	NewListPager(options *armstorage.AccountsClientListOptions) *runtime.Pager[armstorage.AccountsClientListResponse]
	BeginCreate(ctx context.Context, resourceGroupName string, accountName string, parameters armstorage.AccountCreateParameters, options *armstorage.AccountsClientBeginCreateOptions) (*runtime.Poller[armstorage.AccountsClientCreateResponse], error)
	ListKeys(ctx context.Context, resourceGroupName string, accountName string, options *armstorage.AccountsClientListKeysOptions) (armstorage.AccountsClientListKeysResponse, error)
	Delete(ctx context.Context, resourceGroupName string, accountName string, options *armstorage.AccountsClientDeleteOptions) (armstorage.AccountsClientDeleteResponse, error)
	Update(ctx context.Context, resourceGroupName string, accountName string, parameters armstorage.AccountUpdateParameters, options *armstorage.AccountsClientUpdateOptions) (armstorage.AccountsClientUpdateResponse, error)
}

type accountsClient struct {
	client *armstorage.AccountsClient
}

func NewAccountsClient(subscriptionID string, cred azcore.TokenCredential, options *policy.ClientOptions) (*accountsClient, error) {
	client, err := armstorage.NewAccountsClient(subscriptionID, cred, options)
	if err != nil {
		return nil, err
	}
	return &accountsClient{client: client}, nil
}

func (accountsClient *accountsClient) NewListByResourceGroupPager(resourceGroupName string, options *armstorage.AccountsClientListByResourceGroupOptions) *runtime.Pager[armstorage.AccountsClientListByResourceGroupResponse] {
	return accountsClient.client.NewListByResourceGroupPager(resourceGroupName, options)
}

func (accountsClient *accountsClient) NewListPager(options *armstorage.AccountsClientListOptions) *runtime.Pager[armstorage.AccountsClientListResponse] {
	return accountsClient.client.NewListPager(options)
}

func (accountsClient *accountsClient) BeginCreate(ctx context.Context, resourceGroupName string, accountName string, parameters armstorage.AccountCreateParameters, options *armstorage.AccountsClientBeginCreateOptions) (*runtime.Poller[armstorage.AccountsClientCreateResponse], error) {
	return accountsClient.client.BeginCreate(ctx, resourceGroupName, accountName, parameters, options)
}

func (accountsClient *accountsClient) ListKeys(ctx context.Context, resourceGroupName string, accountName string, options *armstorage.AccountsClientListKeysOptions) (armstorage.AccountsClientListKeysResponse, error) {
	return accountsClient.client.ListKeys(ctx, resourceGroupName, accountName, options)
}

func (accountsClient *accountsClient) Delete(ctx context.Context, resourceGroupName string, accountName string, options *armstorage.AccountsClientDeleteOptions) (armstorage.AccountsClientDeleteResponse, error) {
	return accountsClient.client.Delete(ctx, resourceGroupName, accountName, options)
}

func (accountsClient *accountsClient) Update(ctx context.Context, resourceGroupName string, accountName string, parameters armstorage.AccountUpdateParameters, options *armstorage.AccountsClientUpdateOptions) (armstorage.AccountsClientUpdateResponse, error) {
	return accountsClient.client.Update(ctx, resourceGroupName, accountName, parameters, options)
}

type BlobContainersClient interface {
	Get(ctx context.Context, resourceGroupName string, accountName string, containerName string, options *armstorage.BlobContainersClientGetOptions) (armstorage.BlobContainersClientGetResponse, error)
	Create(ctx context.Context, resourceGroupName string, accountName string, containerName string, blobContainer armstorage.BlobContainer, options *armstorage.BlobContainersClientCreateOptions) (armstorage.BlobContainersClientCreateResponse, error)
}

type blobContainersClient struct {
	client *armstorage.BlobContainersClient
}

func NewBlobContainersClient(subscriptionID string, cred azcore.TokenCredential, options *policy.ClientOptions) (*blobContainersClient, error) {
	client, err := armstorage.NewBlobContainersClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	return &blobContainersClient{client: client}, nil
}

func (blobContainersClient *blobContainersClient) Get(ctx context.Context, resourceGroupName string, accountName string, containerName string, options *armstorage.BlobContainersClientGetOptions) (armstorage.BlobContainersClientGetResponse, error) {
	return blobContainersClient.client.Get(ctx, resourceGroupName, accountName, containerName, options)
}

func (blobContainersClient *blobContainersClient) Create(ctx context.Context, resourceGroupName string, accountName string, containerName string, blobContainer armstorage.BlobContainer, options *armstorage.BlobContainersClientCreateOptions) (armstorage.BlobContainersClientCreateResponse, error) {
	return blobContainersClient.client.Create(ctx, resourceGroupName, accountName, containerName, blobContainer, options)
}

type AZBlobClient interface {
	UploadBuffer(ctx context.Context, containerName string, blobName string, buffer []byte, o *blockblob.UploadBufferOptions) (blockblob.UploadBufferResponse, error)
}

type azBlobClient struct {
	client *azblob.Client
}

func NewAZBlobClientWithSharedKeyCredential(blobContainerURL string, sharedKeyCredential *azblob.SharedKeyCredential, options *azblob.ClientOptions) (AZBlobClient, error) {
	client, err := azblob.NewClientWithSharedKeyCredential(blobContainerURL, sharedKeyCredential, options)
	if err != nil {
		return nil, err
	}
	return &azBlobClient{client: client}, nil
}

func (azBlobClient *azBlobClient) UploadBuffer(ctx context.Context, containerName string, blobName string, buffer []byte, o *blockblob.UploadBufferOptions) (blockblob.UploadBufferResponse, error) {
	return azBlobClient.client.UploadBuffer(ctx, containerName, blobName, buffer, o)
}

type UserAssignedIdentitiesClient interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, resourceName string, parameters armmsi.Identity, options *armmsi.UserAssignedIdentitiesClientCreateOrUpdateOptions) (armmsi.UserAssignedIdentitiesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, resourceName string, options *armmsi.UserAssignedIdentitiesClientGetOptions) (armmsi.UserAssignedIdentitiesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, resourceName string, options *armmsi.UserAssignedIdentitiesClientDeleteOptions) (armmsi.UserAssignedIdentitiesClientDeleteResponse, error)
	NewListByResourceGroupPager(resourceGroupName string, options *armmsi.UserAssignedIdentitiesClientListByResourceGroupOptions) *runtime.Pager[armmsi.UserAssignedIdentitiesClientListByResourceGroupResponse]
}

type userAssignedIdentitiesClient struct {
	client *armmsi.UserAssignedIdentitiesClient
}

func NewUserAssignedIdentitiesClient(subscriptionID string, cred azcore.TokenCredential, options *policy.ClientOptions) (*userAssignedIdentitiesClient, error) {
	client, err := armmsi.NewUserAssignedIdentitiesClient(subscriptionID, cred, options)
	if err != nil {
		return nil, err
	}
	return &userAssignedIdentitiesClient{client: client}, err
}

func (userAssignedIdentitiesClient *userAssignedIdentitiesClient) CreateOrUpdate(ctx context.Context, resourceGroupName string, resourceName string, parameters armmsi.Identity, options *armmsi.UserAssignedIdentitiesClientCreateOrUpdateOptions) (armmsi.UserAssignedIdentitiesClientCreateOrUpdateResponse, error) {
	return userAssignedIdentitiesClient.client.CreateOrUpdate(ctx, resourceGroupName, resourceName, parameters, options)
}

func (userAssignedIdentitiesClient *userAssignedIdentitiesClient) Get(ctx context.Context, resourceGroupName string, resourceName string, options *armmsi.UserAssignedIdentitiesClientGetOptions) (armmsi.UserAssignedIdentitiesClientGetResponse, error) {
	return userAssignedIdentitiesClient.client.Get(ctx, resourceGroupName, resourceName, options)
}

type RoleDefinitionsClient interface {
	GetByID(ctx context.Context, roleDefinitionID string, options *armauthorization.RoleDefinitionsClientGetByIDOptions) (armauthorization.RoleDefinitionsClientGetByIDResponse, error)
	NewListPager(scope string, options *armauthorization.RoleDefinitionsClientListOptions) *runtime.Pager[armauthorization.RoleDefinitionsClientListResponse]
}

type roleDefinitionsClient struct {
	client *armauthorization.RoleDefinitionsClient
}

func NewRoleDefinitionsClient(cred azcore.TokenCredential, options *policy.ClientOptions) (*roleDefinitionsClient, error) {
	client, err := armauthorization.NewRoleDefinitionsClient(cred, options)
	if err != nil {
		return nil, err
	}
	return &roleDefinitionsClient{client: client}, err
}

func (roleDefinitionsClient *roleDefinitionsClient) NewListPager(scope string, options *armauthorization.RoleDefinitionsClientListOptions) *runtime.Pager[armauthorization.RoleDefinitionsClientListResponse] {
	return roleDefinitionsClient.client.NewListPager(scope, options)
}

func (roleDefinitionsClient *roleDefinitionsClient) GetByID(ctx context.Context, roleDefinitionID string, options *armauthorization.RoleDefinitionsClientGetByIDOptions) (armauthorization.RoleDefinitionsClientGetByIDResponse, error) {
	return roleDefinitionsClient.client.GetByID(ctx, roleDefinitionID, options)
}

type RoleAssignmentsClient interface {
	Create(ctx context.Context, scope string, roleAssignmentName string, parameters armauthorization.RoleAssignmentCreateParameters, options *armauthorization.RoleAssignmentsClientCreateOptions) (armauthorization.RoleAssignmentsClientCreateResponse, error)
	NewListForScopePager(scope string, options *armauthorization.RoleAssignmentsClientListForScopeOptions) *runtime.Pager[armauthorization.RoleAssignmentsClientListForScopeResponse]
	Delete(ctx context.Context, scope string, roleAssignmentName string, options *armauthorization.RoleAssignmentsClientDeleteOptions) (armauthorization.RoleAssignmentsClientDeleteResponse, error)
}

type roleAssignmentsClient struct {
	client *armauthorization.RoleAssignmentsClient
}

func NewRoleAssignmentsClient(subscriptionID string, cred azcore.TokenCredential, options *policy.ClientOptions) (*roleAssignmentsClient, error) {
	client, err := armauthorization.NewRoleAssignmentsClient(subscriptionID, cred, options)
	if err != nil {
		return nil, err
	}
	return &roleAssignmentsClient{client: client}, err
}

func (roleAssignmentsClient *roleAssignmentsClient) Create(ctx context.Context, scope string, roleAssignmentName string, parameters armauthorization.RoleAssignmentCreateParameters, options *armauthorization.RoleAssignmentsClientCreateOptions) (armauthorization.RoleAssignmentsClientCreateResponse, error) {
	return roleAssignmentsClient.client.Create(ctx, scope, roleAssignmentName, parameters, options)
}

func (roleAssignmentsClient *roleAssignmentsClient) NewListForScopePager(scope string, options *armauthorization.RoleAssignmentsClientListForScopeOptions) *runtime.Pager[armauthorization.RoleAssignmentsClientListForScopeResponse] {
	return roleAssignmentsClient.client.NewListForScopePager(scope, options)
}

func (roleAssignmentsClient *roleAssignmentsClient) Delete(ctx context.Context, scope string, roleAssignmentName string, options *armauthorization.RoleAssignmentsClientDeleteOptions) (armauthorization.RoleAssignmentsClientDeleteResponse, error) {
	return roleAssignmentsClient.client.Delete(ctx, scope, roleAssignmentName, options)
}

type FederatedIdentityCredentialsClient interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, resourceName string, federatedIdentityCredentialResourceName string, parameters armmsi.FederatedIdentityCredential, options *armmsi.FederatedIdentityCredentialsClientCreateOrUpdateOptions) (armmsi.FederatedIdentityCredentialsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, resourceName string, federatedIdentityCredentialResourceName string, options *armmsi.FederatedIdentityCredentialsClientGetOptions) (armmsi.FederatedIdentityCredentialsClientGetResponse, error)
}

type federatedIdentityCredentialsClient struct {
	client *armmsi.FederatedIdentityCredentialsClient
}

func NewFederatedIdentityCredentialsClient(subscriptionID string, cred azcore.TokenCredential, options *policy.ClientOptions) (*federatedIdentityCredentialsClient, error) {
	client, err := armmsi.NewFederatedIdentityCredentialsClient(subscriptionID, cred, options)
	if err != nil {
		return nil, err
	}
	return &federatedIdentityCredentialsClient{client: client}, err
}

func (federatedIdentityCredentialsClient *federatedIdentityCredentialsClient) CreateOrUpdate(ctx context.Context, resourceGroupName string, resourceName string, federatedIdentityCredentialResourceName string, parameters armmsi.FederatedIdentityCredential, options *armmsi.FederatedIdentityCredentialsClientCreateOrUpdateOptions) (armmsi.FederatedIdentityCredentialsClientCreateOrUpdateResponse, error) {
	return federatedIdentityCredentialsClient.client.CreateOrUpdate(ctx, resourceGroupName, resourceName, federatedIdentityCredentialResourceName, parameters, options)
}

func (federatedIdentityCredentialsClient *federatedIdentityCredentialsClient) Get(ctx context.Context, resourceGroupName string, resourceName string, federatedIdentityCredentialResourceName string, options *armmsi.FederatedIdentityCredentialsClientGetOptions) (armmsi.FederatedIdentityCredentialsClientGetResponse, error) {
	return federatedIdentityCredentialsClient.client.Get(ctx, resourceGroupName, resourceName, federatedIdentityCredentialResourceName, options)
}

type AzureClientWrapper struct {
	cred                               azcore.TokenCredential
	ResourceGroupsClient               ResourceGroupsClient
	StorageAccountClient               AccountsClient
	BlobContainerClient                BlobContainersClient
	BlobSharedKeyClient                AZBlobClient
	UserAssignedIdentitiesClient       UserAssignedIdentitiesClient
	RoleDefinitionsClient              RoleDefinitionsClient
	RoleAssignmentClient               RoleAssignmentsClient
	FederatedIdentityCredentialsClient FederatedIdentityCredentialsClient
	// Mock field is used to create a PollerWrapper to facilitate testing
	// Azure client operations that return a runtime.Poller
	Mock bool
	// MockStorageClientBeginCreateResp is the AccountsClientCreateResponse
	// that will be returned from mocked StorageAccountClient.BeginCreate
	// operations such as from a PollerWrapper implementing PollUntilDone.
	MockStorageClientBeginCreateResp armstorage.AccountsClientCreateResponse
}

func NewAzureClientWrapper(subscriptionID string, cred azcore.TokenCredential, options *policy.ClientOptions, mock bool) (*AzureClientWrapper, error) {
	wrapper := &AzureClientWrapper{
		cred: cred,
	}

	resourceGroupClient, err := NewResourceGroupsClient(subscriptionID, cred, options)
	if err != nil {
		return nil, err
	}
	wrapper.ResourceGroupsClient = resourceGroupClient.client

	storageAccountClient, err := NewAccountsClient(subscriptionID, cred, options)
	if err != nil {
		return nil, err
	}
	wrapper.StorageAccountClient = storageAccountClient.client

	blobContainerClient, err := NewBlobContainersClient(subscriptionID, cred, options)
	if err != nil {
		return nil, err
	}
	wrapper.BlobContainerClient = blobContainerClient.client

	userAssignedIdentitiesClient, err := NewUserAssignedIdentitiesClient(subscriptionID, cred, options)
	if err != nil {
		return nil, err
	}
	wrapper.UserAssignedIdentitiesClient = userAssignedIdentitiesClient.client

	roleDefinitionsClient, err := NewRoleDefinitionsClient(cred, options)
	if err != nil {
		return nil, err
	}
	wrapper.RoleDefinitionsClient = roleDefinitionsClient.client

	roleAssignmentsClient, err := NewRoleAssignmentsClient(subscriptionID, cred, options)
	if err != nil {
		return nil, err
	}
	wrapper.RoleAssignmentClient = roleAssignmentsClient.client

	federatedIdentityCredentialsClient, err := NewFederatedIdentityCredentialsClient(subscriptionID, cred, options)
	if err != nil {
		return nil, err
	}
	wrapper.FederatedIdentityCredentialsClient = federatedIdentityCredentialsClient.client

	wrapper.Mock = mock

	return wrapper, nil
}

type MockablePoller[T any] interface {
	PollUntilDone(ctx context.Context, options *runtime.PollUntilDoneOptions) (T, error)
	Poll(ctx context.Context) (*http.Response, error)
	Done() bool
	Result(ctx context.Context) (T, error)
	ResumeToken() (string, error)
}

type PollerWrapper[T any] struct {
	*runtime.Poller[T]
	mock     bool
	mockResp *T
}

// NewPollerWrapper wraps runtime.Poller such that the Poller's methods may be conditionally mocked
// based on the provided mock bool. When mock is true, PollUntilDone() will return the provided mockResp
// generically typed object.
func NewPollerWrapper[T any](poller *runtime.Poller[T], mock bool, mockResp T) MockablePoller[T] {
	return &PollerWrapper[T]{
		Poller:   poller,
		mock:     mock,
		mockResp: &mockResp,
	}
}

func (p *PollerWrapper[T]) Done() bool {
	if p.mock {
		return true
	}
	return p.Poller.Done()
}

func (p *PollerWrapper[T]) Poll(ctx context.Context) (*http.Response, error) {
	if p.mock {
		resp := http.Response{}
		return &resp, nil
	}
	return p.Poller.Poll(ctx)
}

func (p *PollerWrapper[T]) PollUntilDone(ctx context.Context, options *runtime.PollUntilDoneOptions) (T, error) {
	if p.mock {
		if p.mockResp == nil {
			var result T
			return result, errors.New("mocked poller has no generically typed object to return")
		}
		return *p.mockResp, nil
	}
	return p.Poller.PollUntilDone(ctx, options)
}

func (p *PollerWrapper[T]) Result(ctx context.Context) (T, error) {
	if p.mock {
		if p.mockResp == nil {
			var result T
			return result, nil
		}
		return *p.mockResp, nil
	}
	return p.Poller.Result(ctx)
}

func (p *PollerWrapper[T]) ResumeToken() (string, error) {
	if p.mock {
		return "", nil
	}
	return p.Poller.ResumeToken()
}
