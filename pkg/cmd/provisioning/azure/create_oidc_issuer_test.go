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
		// Warning: createOIDCIssuer() and createManagedIdentities() modify this map to include this owned tag.
		// If passing testUserTags around a lot, expect the map to be modified to include this tag.
		fmt.Sprintf("%s_%s", ownedAzureResourceTagKeyPrefix, testInfraName): ownedAzureResourceTagValue,
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
				// Calling infrastructure creation via createOIDCIssuer() adds CCO's owned tag
				// to the resourceTags we set.
				existingResourceTags := map[string]*string{
					fmt.Sprintf("%s_%s", ownedAzureResourceTagKeyPrefix, testInfraName): to.Ptr(ownedAzureResourceTagValue),
				}
				// Merge CCO's owned tag with testUserTags.
				existingResourceTags, _ = mergeResourceTags(testUserTags, existingResourceTags)
				mockStorageClientBeginCreateResp := armstorage.AccountsClientCreateResponse{
					Account: armstorage.Account{
						Name: to.Ptr(testStorageAccountName),
						ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s", testSubscriptionID, testOIDCResourceGroupName, testStorageAccountName)),
						Tags: existingResourceTags,
					}}
				wrapper := mockAzureClientWrapperWithStorageClientBeginCrateResp(mockCtrl, &mockStorageClientBeginCreateResp)
				mockGetResourceGroupNotFound(wrapper, testOIDCResourceGroupName, testSubscriptionID)
				mockCreateOrUpdateResourceGroupSuccess(wrapper, testOIDCResourceGroupName, testRegionName, testSubscriptionID, existingResourceTags)
				mockStorageAccountListByResourceGroupPager(wrapper, []string{}, testOIDCResourceGroupName, testRegionName, testSubscriptionID, existingResourceTags)
				mockStorageAccountBeginCreate(wrapper, testOIDCResourceGroupName, testStorageAccountName, testRegionName, testSubscriptionID, existingResourceTags)
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
			verify: func(t *testing.T, tempDirName string) {},
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
				resourceTags, _ := mergeResourceTags(testUserTags, map[string]*string{})
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetResourceGroupNotFound(wrapper, testOIDCResourceGroupName, testSubscriptionID)
				mockCreateOrUpdateResourceGroupSuccess(wrapper, testOIDCResourceGroupName, testRegionName, testSubscriptionID, resourceTags)
				return wrapper
			},
		},
		{
			name: "Pre-existing resource group found in correct region with expected tags, resource group not created or updated",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				resourceTags, _ := mergeResourceTags(testUserTags, map[string]*string{})
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetResourceGroupSuccess(wrapper, testOIDCResourceGroupName, testRegionName, testSubscriptionID, resourceTags)
				return wrapper
			},
		},
		{
			name: "Pre-existing resource group found in incorrect region, error",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				resourceTags, _ := mergeResourceTags(testUserTags, map[string]*string{})
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetResourceGroupSuccess(wrapper, testOIDCResourceGroupName, "westus3", testSubscriptionID, resourceTags)
				return wrapper
			},
			expectError: true,
		},
		{
			name: "Pre-existing resource group found with missing and different tags, resource group updated",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				gotResourceTags := map[string]*string{
					"existingtagname0": to.Ptr("existingtagvalue0"),
					"testtagname1":     to.Ptr("differentvalue0"),
				}
				wantResourceTags := map[string]*string{
					"testtagname0":     to.Ptr("testtagvalue0"),
					"testtagname1":     to.Ptr("testtagvalue1"),
					"existingtagname0": to.Ptr("existingtagvalue0"),
					fmt.Sprintf("%s_%s", ownedAzureResourceTagKeyPrefix, testInfraName): to.Ptr(ownedAzureResourceTagValue),
				}
				mockGetResourceGroupSuccess(wrapper, testOIDCResourceGroupName, testRegionName, testSubscriptionID, gotResourceTags)
				mockCreateOrUpdateResourceGroupSuccess(wrapper, testOIDCResourceGroupName, testRegionName, testSubscriptionID, wantResourceTags)
				return wrapper
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			mockAzureClientWrapper := test.mockAzureClientWrapper(mockCtrl)
			err := ensureResourceGroup(mockAzureClientWrapper, testOIDCResourceGroupName, testRegionName, testUserTags)
			if test.expectError {
				require.Error(t, err, "expected error")
			} else {
				require.NoError(t, err, "unexpected error")
			}
		})
	}
}

func TestEnsureStorageAccount(t *testing.T) {
	tests := []struct {
		name                   string
		mockAzureClientWrapper func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper
		expectError            bool
	}{
		{
			name: "Pre-existing storage account not found, storage account created",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				resourceTags, _ := mergeResourceTags(testUserTags, map[string]*string{})
				mockStorageClientBeginCreateResp := armstorage.AccountsClientCreateResponse{
					Account: armstorage.Account{
						Name: to.Ptr(testStorageAccountName),
						ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s", testSubscriptionID, testOIDCResourceGroupName, testStorageAccountName)),
						Tags: resourceTags,
					}}
				wrapper := mockAzureClientWrapperWithStorageClientBeginCrateResp(mockCtrl, &mockStorageClientBeginCreateResp)
				mockStorageAccountListByResourceGroupPager(wrapper, []string{}, testOIDCResourceGroupName, testRegionName, testSubscriptionID, resourceTags)
				mockStorageAccountBeginCreate(wrapper, testOIDCResourceGroupName, testStorageAccountName, testRegionName, testSubscriptionID, resourceTags)
				return wrapper
			},
		},
		{
			name: "Pre-existing storage account found with correct tags, storage account not created or updated",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				resourceTags, _ := mergeResourceTags(testUserTags, map[string]*string{})
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockStorageAccountListByResourceGroupPager(wrapper, []string{testStorageAccountName}, testOIDCResourceGroupName, testRegionName, testSubscriptionID, resourceTags)
				return wrapper
			},
		},
		{
			name: "Pre-existing storage account found with missing and different tags, storage account updated",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				gotTags := map[string]*string{
					"testtagname1":     to.Ptr("differentvalue0"),
					"existingtagname0": to.Ptr("existingtagvalue0"),
				}
				mockStorageAccountListByResourceGroupPager(wrapper, []string{testStorageAccountName}, testOIDCResourceGroupName, testRegionName, testSubscriptionID, gotTags)
				wantTags := map[string]*string{
					"testtagname1":     to.Ptr("testtagvalue1"),
					"testtagname0":     to.Ptr("testtagvalue0"),
					"existingtagname0": to.Ptr("existingtagvalue0"),
					fmt.Sprintf("%s_%s", ownedAzureResourceTagKeyPrefix, testInfraName): to.Ptr(ownedAzureResourceTagValue),
				}
				mockUpdateStorageAccountSuccess(wrapper, testOIDCResourceGroupName, testStorageAccountName, testRegionName, testSubscriptionID, wantTags)
				return wrapper
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			mockAzureClientWrapper := test.mockAzureClientWrapper(mockCtrl)
			err := ensureStorageAccount(mockAzureClientWrapper, testStorageAccountName, testOIDCResourceGroupName, testRegionName, testUserTags)
			if test.expectError {
				require.Error(t, err, "expected error")
			} else {
				require.NoError(t, err, "unexpected error")
			}
		})
	}
}

func TestEnsureBlobContainer(t *testing.T) {
	tests := []struct {
		name                   string
		mockAzureClientWrapper func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper
		expectError            bool
	}{
		{
			name: "Pre-existing blob container not found, blob container created",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetBlobContainerNotFound(wrapper, testOIDCResourceGroupName, testStorageAccountName, testBlobContainerName)
				mockCreateBlobContainerSuccess(wrapper, testOIDCResourceGroupName, testStorageAccountName, testBlobContainerName, testSubscriptionID)
				return wrapper
			},
		},
		{
			name: "Pre-existing blob container found, blob container not created",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetBlobContainerFound(wrapper, testOIDCResourceGroupName, testStorageAccountName, testBlobContainerName, testSubscriptionID)
				return wrapper
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			mockAzureClientWrapper := test.mockAzureClientWrapper(mockCtrl)
			err := ensureBlobContainer(mockAzureClientWrapper, testOIDCResourceGroupName, testStorageAccountName, testBlobContainerName)
			if test.expectError {
				require.Error(t, err, "expected error")
			} else {
				require.NoError(t, err, "unexpected error")
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
	// set as it is here, uploadOIDCDocuments() will use wrapper.BlobSharedKeyClient and will not create
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

func mockCreateOrUpdateResourceGroupSuccess(wrapper *azureclients.AzureClientWrapper, resourceGroupName, region, subscriptionID string, tags map[string]*string) {
	parameters := armresources.ResourceGroup{
		Location: to.Ptr(region),
		Tags:     tags,
	}
	wrapper.ResourceGroupsClient.(*mockazure.MockResourceGroupsClient).EXPECT().CreateOrUpdate(gomock.Any(), resourceGroupName, parameters, gomock.Any()).Return(
		armresources.ResourceGroupsClientCreateOrUpdateResponse{
			ResourceGroup: armresources.ResourceGroup{
				Name: to.Ptr(resourceGroupName),
				ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", subscriptionID, resourceGroupName)),
				Tags: tags,
			},
		},
		nil, // no error
	)
}

func mockGetResourceGroupSuccess(wrapper *azureclients.AzureClientWrapper, resourceGroupName, regionName, subscriptionID string, tags map[string]*string) {
	wrapper.ResourceGroupsClient.(*mockazure.MockResourceGroupsClient).EXPECT().Get(gomock.Any(), resourceGroupName, gomock.Any()).Return(
		armresources.ResourceGroupsClientGetResponse{
			ResourceGroup: armresources.ResourceGroup{
				Location: to.Ptr(regionName),
				Name:     to.Ptr(resourceGroupName),
				ID:       to.Ptr(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", subscriptionID, resourceGroupName)),
				Tags:     tags,
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

func mockStorageAccountListByResourceGroupPager(wrapper *azureclients.AzureClientWrapper, existingStorageAccountNames []string, resourceGroupName, regionName, subscriptionID string, tags map[string]*string) {
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
			Tags:     tags,
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

func mockStorageAccountBeginCreate(wrapper *azureclients.AzureClientWrapper, resourceGroupName, storageAccountName, region, subscriptionID string, tags map[string]*string) {
	storageAccountParameters := armstorage.AccountCreateParameters{
		Kind: to.Ptr(armstorage.KindStorageV2),
		SKU: &armstorage.SKU{
			Name: to.Ptr(armstorage.SKUNameStandardLRS),
		},
		Location: to.Ptr(region),
		Tags:     tags,
	}

	// This poller is not returned from subsequent PollerWrapper.PollUntilDone() and is just instantiated
	// to satisfy the return of StorageAccountClient.BeginCreate().
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

func mockUpdateStorageAccountSuccess(wrapper *azureclients.AzureClientWrapper, resourceGroupName, storageAccountName, regionName, subscriptionID string, tags map[string]*string) {
	accountsClientUpdateParameters := armstorage.AccountUpdateParameters{
		Tags: tags,
	}
	accountsClientUpdateResponse := armstorage.AccountsClientUpdateResponse{
		Account: armstorage.Account{
			Name:     to.Ptr(storageAccountName),
			Location: to.Ptr(regionName),
			ID:       to.Ptr(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s", subscriptionID, resourceGroupName, storageAccountName)),
			Tags:     tags,
		}}
	wrapper.StorageAccountClient.(*mockazure.MockAccountsClient).EXPECT().Update(gomock.Any(), resourceGroupName, storageAccountName, accountsClientUpdateParameters, gomock.Any()).Return(
		accountsClientUpdateResponse,
		nil, // no error
	)
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

func mockGetBlobContainerFound(wrapper *azureclients.AzureClientWrapper, resourceGroupName, storageAccountName, blobContainerName, subscriptionID string) {
	wrapper.BlobContainerClient.(*mockazure.MockBlobContainersClient).EXPECT().Get(gomock.Any(), resourceGroupName, storageAccountName, blobContainerName, gomock.Any()).Return(
		armstorage.BlobContainersClientGetResponse{
			BlobContainer: armstorage.BlobContainer{
				ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/blobServices/default/containers/%s", subscriptionID, resourceGroupName, storageAccountName, blobContainerName)),
				Name: to.Ptr(blobContainerName),
			},
		},
		nil, // no error
	)
}

func mockCreateBlobContainerSuccess(wrapper *azureclients.AzureClientWrapper, resourceGroupName, storageAccountName, blobContainerName, subscriptionID string) {
	blobContainersClientCreateResponse := armstorage.BlobContainersClientCreateResponse{
		BlobContainer: armstorage.BlobContainer{
			ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s/blobServices/default/containers/%s", subscriptionID, resourceGroupName, storageAccountName, blobContainerName)),
			Name: to.Ptr(blobContainerName),
		},
	}
	wrapper.BlobContainerClient.(*mockazure.MockBlobContainersClient).EXPECT().Create(gomock.Any(), resourceGroupName, storageAccountName, blobContainerName, gomock.Any(), gomock.Any()).Return(
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
