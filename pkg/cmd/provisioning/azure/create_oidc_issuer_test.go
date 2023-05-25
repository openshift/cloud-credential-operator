package azure

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/golang/mock/gomock"
	azureclients "github.com/openshift/cloud-credential-operator/pkg/azure"
	mockazure "github.com/openshift/cloud-credential-operator/pkg/azure/mock"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
	"github.com/stretchr/testify/require"
)

var (
	testDirPrefix      = "oidcissuertestdir"
	testInfraName      = "testinfraname"
	testRegionName     = "testregion"
	testSubscriptionID = "123456789"
	testUserTags       = map[string]string{
		"testtagname0": "testtagvalue0",
		"testtagname1": "testtagvalue1",
	}
	testOIDCResourceGroupName    = testInfraName + oidcResourceGroupSuffix
	testInstallResourceGroupName = testInfraName
	testStorageAccountName       = testInfraName
	testBlobContainerName        = testInfraName
	testDNSZoneResourceGroupName = testInfraName
	testIssuerURL                = fmt.Sprintf("https://%s.blob.core.windows.net/%s", testBlobContainerName, testBlobContainerName)

	testPublicKeyFile = "publicKeyFile"
	testPublicKeyData = "-----BEGIN PUBLIC KEY-----" +
		"\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwlzW80E8Tj19NCuPTdwd" +
		"\ng56fcpRKW6cnJ981cXNrHbQt/0ZR7HDYf/r+B1GRUblSoncQOA2IPU95wnPq6HHf" +
		"\nkxP6G8qRgA3MfhW1m/OAD9U16YTcBIN3BMnNtmJzQkCbEQz6JSlFRRU5vhPmL59h" +
		"\nZ61CBYhbxd3whtoG6WXifhrudowJdZnTMEeZnkiJ8uhHpJOGZJmcRkQ6RPVlaiqC" +
		"\ntmpTZf3DU0yvajoqMH4t3EwxzB1QYLDsNJvpnh5FlvLZUTAvpp0u6TxbnFeBFMO/" +
		"\nP6V5sjNf+aPPEr+BDaL/Jv7KbB1FYdX/ngDvsjq36+GrDvDjbnd+5GfqpuR02a/X" +
		"\nfM0zVtvWXxIgD8gKFfYSfJH3K6x4SbxGdaXSX2ixmQjB1jwdkbAgQ1cbe2MgnqTO" +
		"\n8KcgAFxwdvTUo0CA2R1NGgmeLoPUYv9kTSRWhRvgRoLAlzFGnfdqO6Gq5CwHR820" +
		"\nAdohiu7Lgp940AR7mMRcjxkpfArpyKOxfVIFrpZDw0G39zd9bn3KYYWQ4Kah1BR0" +
		"\nWpJJV+OtxxsUI51vQ0+wp9KI5Eu0ibyzL1Fq7IoBOhFRea384iF4LEXmkM/y1eRi" +
		"\nhEnmk6kDfjWWsPkxXrD5qY4KgSp1/fqJP29p0Ypeh0cfrVkdQvn3v7ppcS/7TmWk" +
		"\nhiFcsE1ngFW/nR6+7K/JdVUCAwEAAQ==" +
		"\n-----END PUBLIC KEY-----\n"
)

func TestCreateOIDCIssuer(t *testing.T) {
	tests := []struct {
		name                   string
		mockAzureClientWrapper func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper
		setup                  func(*testing.T) string
		verify                 func(t *testing.T, tempDirName string)
		dryRun                 bool
		expectError            bool
	}{
		{
			name: "Public key not found",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				return wrapper
			},
			setup: func(t *testing.T) string {
				tempDirName, err := os.MkdirTemp(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "failed to create temp directory")
				return tempDirName
			},
			expectError: true,
			verify:      func(t *testing.T, tempDirName string) {},
		},
		{
			name: "OIDC issuer created",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				mockStorageClientBeginCreateResp := armstorage.AccountsClientCreateResponse{
					Account: armstorage.Account{
						Name: to.Ptr(testStorageAccountName),
						ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s", testSubscriptionID, testOIDCResourceGroupName, testStorageAccountName)),
					}}
				wrapper := mockAzureClientWrapperWithStorageClientBeginCrateResp(mockCtrl, &mockStorageClientBeginCreateResp)
				mockGetResourceGroupNotFound(wrapper, testOIDCResourceGroupName, testSubscriptionID)
				mockCreateResourceGroupSuccess(wrapper, testOIDCResourceGroupName, testSubscriptionID)
				mockStorageAccountListByResourceGroupPager(wrapper, []string{}, testOIDCResourceGroupName, testRegionName, testSubscriptionID)
				mockStorageAccountBeginCreate(wrapper, testOIDCResourceGroupName, testStorageAccountName, testRegionName, testSubscriptionID, testUserTags)
				mockStorageAccountListKeys(wrapper, testOIDCResourceGroupName, testStorageAccountName)
				mockGetBlobContainerNotFound(wrapper, testOIDCResourceGroupName, testStorageAccountName, testBlobContainerName)
				mockCreateBlobContainerSuccess(wrapper, testOIDCResourceGroupName, testStorageAccountName, testBlobContainerName, testSubscriptionID)
				mockBlobContainerUploadBufferSuccess(wrapper, filepath.Join(".well-known", openidConfigurationFileName))
				mockBlobContainerUploadBufferSuccess(wrapper, filepath.Join("openid/v1/", jwksFileName))
				return wrapper
			},
			setup: func(t *testing.T) string {
				tempDirName, err := os.MkdirTemp(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "failed to create temp directory")

				err = os.WriteFile(filepath.Join(tempDirName, testPublicKeyFile), []byte(testPublicKeyData), 0600)
				require.NoError(t, err, "errored while setting up environment for test")

				manifestsDirPath := filepath.Join(tempDirName, provisioning.ManifestsDirName)
				err = provisioning.EnsureDir(manifestsDirPath)
				require.NoError(t, err, "errored while creating manifests directory for test")
				return tempDirName
			},
			verify:      func(t *testing.T, tempDirName string) {},
			expectError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)

			mockAzureClientWrapper := test.mockAzureClientWrapper(mockCtrl)

			tempDirName := test.setup(t)
			defer os.RemoveAll(tempDirName)

			testPublicKeyPath := filepath.Join(tempDirName, testPublicKeyFile)

			issuerURL, err := createOIDCIssuer(
				mockAzureClientWrapper,
				testInfraName,
				testRegionName,
				testOIDCResourceGroupName,
				testStorageAccountName,
				testBlobContainerName,
				testSubscriptionID,
				testPublicKeyPath,
				tempDirName,
				testUserTags,
				test.dryRun)
			if test.expectError {
				require.Error(t, err, "expected error")
			} else {
				require.NoError(t, err, "unexpected error")
				test.verify(t, tempDirName)
				require.Equal(t, fmt.Sprintf("https://%s.blob.core.windows.net/%s", testBlobContainerName, testBlobContainerName), issuerURL, "unexpected issuerURL returned")
			}
		})
	}
}

func TestEnsureResourceGroup(t *testing.T) {
	tests := []struct {
		name                   string
		mockAzureClientWrapper func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper
		generateOnly           bool
		expectError            bool
	}{
		{
			name: "Pre-existing resource group not found, resource group created",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetResourceGroupNotFound(wrapper, testOIDCResourceGroupName, testSubscriptionID)
				mockCreateResourceGroupSuccess(wrapper, testOIDCResourceGroupName, testSubscriptionID)
				return wrapper
			},
			expectError: false,
		},
		{
			name: "Pre-existing resource group found in correct region, resource group not created",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetResourceGroupSuccess(wrapper, testOIDCResourceGroupName, testRegionName, testSubscriptionID)
				return wrapper
			},
			expectError: false,
		},
		{
			name: "Pre-existing resource group found in incorrect region",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetResourceGroupSuccess(wrapper, testOIDCResourceGroupName, "westus3", testSubscriptionID)
				return wrapper
			},
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)

			mockAzureClientWrapper := test.mockAzureClientWrapper(mockCtrl)

			resourceGroup, err := ensureResourceGroup(mockAzureClientWrapper, testOIDCResourceGroupName, testRegionName, testUserTags)
			if test.expectError {
				require.Error(t, err, "expected error")
			} else {
				require.NoError(t, err, "unexpected error")
				require.NotNil(t, resourceGroup, "expected resourceGroup to not be nil")
			}
		})
	}
}

func TestEnsureStorageAccount(t *testing.T) {
	tests := []struct {
		name                   string
		mockAzureClientWrapper func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper
		generateOnly           bool
		expectError            bool
	}{
		{
			name: "Pre-existing storage account not found, storage account created",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				mockStorageClientBeginCreateResp := armstorage.AccountsClientCreateResponse{
					Account: armstorage.Account{
						Name: to.Ptr(testStorageAccountName),
						ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s", testSubscriptionID, testOIDCResourceGroupName, testStorageAccountName)),
					}}
				wrapper := mockAzureClientWrapperWithStorageClientBeginCrateResp(mockCtrl, &mockStorageClientBeginCreateResp)
				mockStorageAccountListByResourceGroupPager(wrapper, []string{}, testOIDCResourceGroupName, testRegionName, testSubscriptionID)
				mockStorageAccountBeginCreate(wrapper, testOIDCResourceGroupName, testStorageAccountName, testRegionName, testSubscriptionID, testUserTags)
				return wrapper
			},
			expectError: false,
		},
		{
			name: "Pre-existing storage account found in correct region, storage account not created",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockStorageAccountListByResourceGroupPager(wrapper, []string{testStorageAccountName}, testOIDCResourceGroupName, testRegionName, testSubscriptionID)
				return wrapper
			},
			expectError: false,
		},
		{
			// This shouldn't be possible since we're listing storage accounts by resource group
			// and we ensureResourceGroup() of the resource group in which the storage account
			// would be created / exists and we validate the region within ensureResourceGroup().
			name: "Pre-existing storage account found in incorrect region",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockStorageAccountListByResourceGroupPager(wrapper, []string{testStorageAccountName}, testOIDCResourceGroupName, "westus3", testSubscriptionID)
				return wrapper
			},
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)

			mockAzureClientWrapper := test.mockAzureClientWrapper(mockCtrl)

			storageAccount, err := ensureStorageAccount(mockAzureClientWrapper, testStorageAccountName, testOIDCResourceGroupName, testRegionName, testUserTags)
			if test.expectError {
				require.Error(t, err, "expected error")
			} else {
				require.NoError(t, err, "unexpected error")
				require.NotNil(t, storageAccount, "expected storageAccount to not be nil")
			}
		})
	}
}

func mockAzureClientWrapper(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
	wrapper := azureclients.AzureClientWrapper{}
	wrapper.ResourceGroupsClient = mockazure.NewMockResourceGroupsClient(mockCtrl)
	wrapper.StorageAccountClient = mockazure.NewMockAccountsClient(mockCtrl)
	wrapper.BlobContainerClient = mockazure.NewMockBlobContainersClient(mockCtrl)
	// BlobSharedKeyClient is not set by azureclients.NewAzureClientWrapper because we won't
	// have storage account keys needed to instantiate the client. When BlobSharedKeyClient is previously
	// set as it is here, uploadOIDCDocuments will use wrapper.BlobSharedKeyClient and will not create
	// a real client.
	wrapper.BlobSharedKeyClient = mockazure.NewMockAZBlobClient(mockCtrl)
	wrapper.UserAssignedIdentitiesClient = mockazure.NewMockUserAssignedIdentitiesClient(mockCtrl)
	wrapper.RoleDefinitionsClient = mockazure.NewMockRoleDefinitionsClient(mockCtrl)
	wrapper.RoleAssignmentClient = mockazure.NewMockRoleAssignmentsClient(mockCtrl)
	wrapper.FederatedIdentityCredentialsClient = mockazure.NewMockFederatedIdentityCredentialsClient(mockCtrl)
	// Mock = true so that runtime.Poller operations will be mocked by an azureclients.PollerWrapper
	wrapper.Mock = true
	return &wrapper
}

func mockAzureClientWrapperWithStorageClientBeginCrateResp(mockCtrl *gomock.Controller, mockStorageClientBeginCreateResp *armstorage.AccountsClientCreateResponse) *azureclients.AzureClientWrapper {
	wrapper := mockAzureClientWrapper(mockCtrl)
	if mockStorageClientBeginCreateResp != nil {
		wrapper.MockStorageClientBeginCreateResp = *mockStorageClientBeginCreateResp
	}
	return wrapper
}

func mockCreateResourceGroupSuccess(wrapper *azureclients.AzureClientWrapper, resourceGroupName, subscriptionID string) {
	wrapper.ResourceGroupsClient.(*mockazure.MockResourceGroupsClient).EXPECT().CreateOrUpdate(gomock.Any(), resourceGroupName, gomock.Any(), gomock.Any()).Return(
		armresources.ResourceGroupsClientCreateOrUpdateResponse{
			ResourceGroup: armresources.ResourceGroup{
				Name: to.Ptr(resourceGroupName),
				ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", subscriptionID, resourceGroupName)),
			},
		},
		nil, // no error
	)
}

func mockGetResourceGroupSuccess(wrapper *azureclients.AzureClientWrapper, resourceGroupName, regionName, subscriptionID string) {
	wrapper.ResourceGroupsClient.(*mockazure.MockResourceGroupsClient).EXPECT().Get(gomock.Any(), resourceGroupName, gomock.Any()).Return(
		armresources.ResourceGroupsClientGetResponse{
			ResourceGroup: armresources.ResourceGroup{
				Location: to.Ptr(regionName),
				Name:     to.Ptr(resourceGroupName),
				ID:       to.Ptr(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", subscriptionID, resourceGroupName)),
			},
		},
		nil, // no error
	)
}

func mockGetResourceGroupNotFound(wrapper *azureclients.AzureClientWrapper, resourceGroupName, subscriptionID string) {
	respHeader := http.Header{}
	respHeader.Set("x-ms-error-code", "ResourceGroupNotFound")
	resp := &http.Response{
		Header: respHeader,
	}
	wrapper.ResourceGroupsClient.(*mockazure.MockResourceGroupsClient).EXPECT().Get(gomock.Any(), resourceGroupName, gomock.Any()).Return(
		armresources.ResourceGroupsClientGetResponse{
			ResourceGroup: armresources.ResourceGroup{
				Name: to.Ptr(resourceGroupName),
				ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", subscriptionID, resourceGroupName)),
			},
		},
		NewResponseError(resp),
	)
}

func mockStorageAccountListByResourceGroupPager(wrapper *azureclients.AzureClientWrapper, existingStorageAccountNames []string, resourceGroupName, regionName, subscriptionID string) {
	accountListByResourceGroupResult := armstorage.AccountsClientListByResourceGroupResponse{
		AccountListResult: armstorage.AccountListResult{
			Value: []*armstorage.Account{},
		},
	}
	for _, storageAccountName := range existingStorageAccountNames {
		accountListByResourceGroupResult.Value = append(accountListByResourceGroupResult.Value, &armstorage.Account{
			Name:     to.Ptr(storageAccountName),
			Location: to.Ptr(regionName),
			ID:       to.Ptr(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s", subscriptionID, resourceGroupName, storageAccountName)),
		})
	}

	wrapper.StorageAccountClient.(*mockazure.MockAccountsClient).EXPECT().NewListByResourceGroupPager(resourceGroupName, gomock.Any()).Return(
		runtime.NewPager(runtime.PagingHandler[armstorage.AccountsClientListByResourceGroupResponse]{
			More: func(current armstorage.AccountsClientListByResourceGroupResponse) bool {
				return current.NextLink != nil
			},
			Fetcher: func(ctx context.Context, current *armstorage.AccountsClientListByResourceGroupResponse) (armstorage.AccountsClientListByResourceGroupResponse, error) {
				return accountListByResourceGroupResult, nil
			},
		}),
	)
}

func mockStorageAccountBeginCreate(wrapper *azureclients.AzureClientWrapper, resourceGroupName, storageAccountName, region, subscriptionID string, userTags map[string]string) {
	storageAccountParameters := armstorage.AccountCreateParameters{
		Kind: to.Ptr(armstorage.KindStorageV2),
		SKU: &armstorage.SKU{
			Name: to.Ptr(armstorage.SKUNameStandardLRS),
		},
		Location: to.Ptr(region),
		Tags: map[string]*string{
			nameTagKey: to.Ptr(storageAccountName),
			fmt.Sprintf("%s_%s", ownedAzureResourceTagKeyPrefix, storageAccountName): to.Ptr(ownedAzureResourceTagValue),
		},
	}

	for userTagKey, userTagValue := range userTags {
		storageAccountParameters.Tags[userTagKey] = to.Ptr(userTagValue)
	}

	// This poller is not returned from PollerWrapper.PollUntilDone().
	// See AzureClientWrapper.MockStorageClientBeginCreateResp
	poller, _ := runtime.NewPoller(
		&http.Response{
			Body: http.NoBody,
		},
		runtime.NewPipeline("testpipeline", "", runtime.PipelineOptions{}, nil),
		&runtime.NewPollerOptions[armstorage.AccountsClientCreateResponse]{},
	)

	wrapper.StorageAccountClient.(*mockazure.MockAccountsClient).EXPECT().BeginCreate(gomock.Any(), resourceGroupName, storageAccountName, storageAccountParameters, gomock.Any()).Return(poller, nil)
}

func mockStorageAccountListKeys(wrapper *azureclients.AzureClientWrapper, resourceGroupName, storageAccountName string) {
	accountsClientListKeysResponse := armstorage.AccountsClientListKeysResponse{
		AccountListKeysResult: armstorage.AccountListKeysResult{
			Keys: []*armstorage.AccountKey{
				{
					KeyName: to.Ptr("dGVzdEtleQo="),     // "testKey"
					Value:   to.Ptr("dGVzdFZhbHVlCg=="), // "testValue"
				},
			},
		},
	}
	wrapper.StorageAccountClient.(*mockazure.MockAccountsClient).EXPECT().ListKeys(gomock.Any(), resourceGroupName, storageAccountName, gomock.Any()).Return(
		accountsClientListKeysResponse,
		nil, // no error
	)
}

func mockGetBlobContainerNotFound(wrapper *azureclients.AzureClientWrapper, resourceGroupName, storageAccountName, blobContainerName string) {
	respHeader := http.Header{}
	respHeader.Set("x-ms-error-code", "ContainerNotFound")
	resp := &http.Response{
		Header: respHeader,
	}
	wrapper.BlobContainerClient.(*mockazure.MockBlobContainersClient).EXPECT().Get(gomock.Any(), resourceGroupName, storageAccountName, blobContainerName, gomock.Any()).Return(
		armstorage.BlobContainersClientGetResponse{},
		NewResponseError(resp),
	)
}

func mockCreateBlobContainerSuccess(wrapper *azureclients.AzureClientWrapper, resourceGroupName, storageAccountName, containerName, subscriptionID string) {
	blobContainersClientCreateResponse := armstorage.BlobContainersClientCreateResponse{
		BlobContainer: armstorage.BlobContainer{
			ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/blobServices/default/containers/%s", subscriptionID, resourceGroupName, storageAccountName, containerName)),
			Name: to.Ptr(testInfraName),
		},
	}
	wrapper.BlobContainerClient.(*mockazure.MockBlobContainersClient).EXPECT().Create(gomock.Any(), resourceGroupName, storageAccountName, containerName, gomock.Any(), gomock.Any()).Return(
		blobContainersClientCreateResponse,
		nil, // no error
	)
}

func mockBlobContainerUploadBufferSuccess(wrapper *azureclients.AzureClientWrapper, blobName string) {
	// Response is squashed in implementation as we don't need any other information other than
	// knowing UploadBuffer() was successful based on the error returned
	uploadBufferResponse := azblob.UploadBufferResponse{}
	wrapper.BlobSharedKeyClient.(*mockazure.MockAZBlobClient).EXPECT().UploadBuffer(gomock.Any(), "", blobName, gomock.Any(), gomock.Any()).Return(
		uploadBufferResponse,
		nil, // no error
	)
}

// NewResponseError creates a new *azcore.ResponseError from the provided HTTP response
// and returns it as error. The ResponseError.ErrorCode is based on the "x-ms-error-code"
// header of the provided response.
// Allows for converting error type into an azcore.ResponseError. For example,
//
//	  var respErr *azcore.ResponseError
//		 if errors.As(err, &respErr) {
//	      switch respErr.ErrorCode
func NewResponseError(resp *http.Response) error {
	respErr := &azcore.ResponseError{
		StatusCode:  resp.StatusCode,
		RawResponse: resp,
	}

	// Use the error code from the response header
	if ec := resp.Header.Get("x-ms-error-code"); ec != "" {
		respErr.ErrorCode = ec
		return respErr
	}

	return respErr
}
