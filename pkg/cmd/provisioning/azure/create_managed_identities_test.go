package azure

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	azureclients "github.com/openshift/cloud-credential-operator/pkg/azure"
	mockazure "github.com/openshift/cloud-credential-operator/pkg/azure/mock"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/golang/mock/gomock"
)

var (
	credReqTemplate = `---
apiVersion: cloudcredential.openshift.io/v1
kind: CredentialsRequest
metadata:
  name: %s
  namespace: openshift-cloud-credential-operator
spec:
  providerSpec:
    apiVersion: cloudcredential.openshift.io/v1
    kind: AzureProviderSpec
    roleBindings:
    - role: Contributor
  secretRef:
    name: %s
    namespace: %s
  serviceAccountNames:
  - testServiceAccount1
  - testServiceAccount2`

	credReqTechPreviewTemplate = `---
apiVersion: cloudcredential.openshift.io/v1
kind: CredentialsRequest
metadata:
  annotations:
    release.openshift.io/feature-set: TechPreviewNoUpgrade
  name: %s
  namespace: openshift-cloud-credential-operator
spec:
  providerSpec:
    apiVersion: cloudcredential.openshift.io/v1
    kind: AzureProviderSpec
    roleBindings:
    - role: Contributor
  secretRef:
    name: %s
    namespace: %s
  serviceAccountNames:
  - testServiceAccount1
  - testServiceAccount2`

	testManagedIdentityPrincipalID = "prinicpal-be9f-4e32-bb21-42564b35285f"
	testScopingResourceGroupNames  = []string{testInfraName}
)

func TestCreateManagedIdentities(t *testing.T) {
	tests := []struct {
		name                   string
		mockAzureClientWrapper func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper
		setup                  func(*testing.T) string
		verify                 func(t *testing.T, tempDirName string)
		enableTechPreview      bool
		dryRun                 bool
		expectError            bool
	}{
		{
			name: "Create managed identities for zero (0) CredentialsRequests",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				resourceTags, _ := mergeResourceTags(testUserTags, map[string]*string{})
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetResourceGroupNotFound(wrapper, testInstallResourceGroupName, testSubscriptionID)
				mockCreateOrUpdateResourceGroupSuccess(wrapper, testInstallResourceGroupName, testRegionName, testSubscriptionID, resourceTags)
				return wrapper
			},
			setup: func(t *testing.T) string {
				tempDirName, err := os.MkdirTemp(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "failed to create temp directory")

				manifestsDirPath := filepath.Join(tempDirName, provisioning.ManifestsDirName)
				err = provisioning.EnsureDir(manifestsDirPath)
				require.NoError(t, err, "errored while creating manifests directory for test")

				credReqDirPath := filepath.Join(tempDirName, "credreqs")
				err = provisioning.EnsureDir(credReqDirPath)
				require.NoError(t, err, "errored while creating credreq directory for test")
				return tempDirName
			},
			verify: func(t *testing.T, targetDir string) {
				files, err := ioutil.ReadDir(targetDir)
				require.NoError(t, err, "unexpected error listing files in targetDir")
				assert.Zero(t, provisioning.CountNonDirectoryFiles(files), "Should be no files in targetDir when no CredReqs to process")

				files, err = ioutil.ReadDir(filepath.Join(targetDir, provisioning.ManifestsDirName))
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Zero(t, provisioning.CountNonDirectoryFiles(files), "Should be no files in manifestsDir when no CredReqs to process")
			},
			expectError: false,
		},
		{
			name: "Create managed identities for one (1) CredentialsRequest",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				resourceTags, _ := mergeResourceTags(testUserTags, map[string]*string{})
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetResourceGroupNotFound(wrapper, testInstallResourceGroupName, testSubscriptionID)
				mockCreateOrUpdateResourceGroupSuccess(wrapper, testInstallResourceGroupName, testRegionName, testSubscriptionID, resourceTags)
				mockGetUserAssignedManagedIdentityNotFound(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1")
				mockCreateOrUpdateManagedIdentitySuccess(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", testRegionName, testSubscriptionID, resourceTags)
				mockRoleAssignmentsListPager(wrapper,
					[]*armauthorization.RoleAssignment{},
					testManagedIdentityPrincipalID,
				)
				mockRoleDefinitionsListPager(wrapper, "/subscriptions/"+testSubscriptionID,
					[]*armauthorization.RoleDefinition{
						{
							Name: to.Ptr("ContibutorRoleDefinitionID"),
							ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", testSubscriptionID, "ContibutorRoleDefinitionID")),
							Properties: &armauthorization.RoleDefinitionProperties{
								RoleName: to.Ptr("Contributor"),
							},
						},
					})
				mockCreateRoleAssignmentSuccess(wrapper, "/subscriptions/"+testSubscriptionID+"/resourceGroups/"+testInstallResourceGroupName, "RandomContributorRoleAssignmentNameGUID")
				mockGetFederatedIdentityCredentialNotFound(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", "testServiceAccount1")
				mockCreateOrUpdateFederatedIdentityCredentialSuccess(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", "testServiceAccount1", testSubscriptionID)
				mockGetFederatedIdentityCredentialNotFound(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", "testServiceAccount2")
				mockCreateOrUpdateFederatedIdentityCredentialSuccess(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", "testServiceAccount2", testSubscriptionID)
				return wrapper
			},
			setup: func(t *testing.T) string {
				tempDirName, err := os.MkdirTemp(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "failed to create temp directory")

				manifestsDirPath := filepath.Join(tempDirName, provisioning.ManifestsDirName)
				err = provisioning.EnsureDir(manifestsDirPath)
				require.NoError(t, err, "errored while creating manifests directory for test")

				credReqDirPath := filepath.Join(tempDirName, "credreqs")
				err = provisioning.EnsureDir(credReqDirPath)
				require.NoError(t, err, "errored while creating credreq directory for test")

				err = testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", filepath.Join(tempDirName, "credreqs"), false)
				require.NoError(t, err, "errored while setting up test CredReq files")
				return tempDirName
			},
			verify: func(t *testing.T, tempDirName string) {
				files, err := ioutil.ReadDir(tempDirName)
				require.NoError(t, err, "unexpected error listing files in targetDir")
				assert.Zero(t, provisioning.CountNonDirectoryFiles(files), "Should be no generated files in targetDir")

				manifestsDirPath := filepath.Join(tempDirName, provisioning.ManifestsDirName)
				files, err = ioutil.ReadDir(manifestsDirPath)
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Equal(t, 1, provisioning.CountNonDirectoryFiles(files), "Should be exactly 1 secret in manifestsDir for one CredReq")
			},
			expectError: false,
		},
		{
			name: "Write secrets for one (1) managed identities for one (1) CredentialsRequest in dry run",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				// No Azure API calls mocked because they are skipped in dry run
				return wrapper
			},
			dryRun: true,
			setup: func(t *testing.T) string {
				tempDirName, err := os.MkdirTemp(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "failed to create temp directory")

				manifestsDirPath := filepath.Join(tempDirName, provisioning.ManifestsDirName)
				err = provisioning.EnsureDir(manifestsDirPath)
				require.NoError(t, err, "errored while creating manifests directory for test")

				credReqDirPath := filepath.Join(tempDirName, "credreqs")
				err = provisioning.EnsureDir(credReqDirPath)
				require.NoError(t, err, "errored while creating credreq directory for test")

				err = testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", filepath.Join(tempDirName, "credreqs"), false)
				require.NoError(t, err, "errored while setting up test CredReq files")
				return tempDirName
			},
			verify: func(t *testing.T, tempDirName string) {
				files, err := ioutil.ReadDir(tempDirName)
				require.NoError(t, err, "unexpected error listing files in targetDir")
				assert.Zero(t, provisioning.CountNonDirectoryFiles(files), "Should be no generated files in targetDir")

				manifestsDirPath := filepath.Join(tempDirName, provisioning.ManifestsDirName)
				files, err = ioutil.ReadDir(manifestsDirPath)
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Equal(t, 1, provisioning.CountNonDirectoryFiles(files), "Should be exactly 1 secret in manifestsDir for one CredReq")
			},
			expectError: false,
		},
		{
			name: "Create managed identities for one (1) CredentialsRequest with a TechPreviewNoUpgrade annotation, --enable-tech-preview set",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				resourceTags, _ := mergeResourceTags(testUserTags, map[string]*string{})
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetResourceGroupNotFound(wrapper, testInstallResourceGroupName, testSubscriptionID)
				mockCreateOrUpdateResourceGroupSuccess(wrapper, testInstallResourceGroupName, testRegionName, testSubscriptionID, resourceTags)
				mockGetUserAssignedManagedIdentityNotFound(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1")
				mockCreateOrUpdateManagedIdentitySuccess(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", testRegionName, testSubscriptionID, resourceTags)
				mockRoleAssignmentsListPager(wrapper,
					[]*armauthorization.RoleAssignment{},
					testManagedIdentityPrincipalID,
				)
				mockRoleDefinitionsListPager(wrapper, "/subscriptions/"+testSubscriptionID,
					[]*armauthorization.RoleDefinition{
						{
							Name: to.Ptr("ContibutorRoleDefinitionName"),
							ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", testSubscriptionID, "ContibutorRoleDefinitionID")),
							Properties: &armauthorization.RoleDefinitionProperties{
								RoleName: to.Ptr("Contributor"),
							},
						},
					})
				mockCreateRoleAssignmentSuccess(wrapper, "/subscriptions/"+testSubscriptionID+"/resourceGroups/"+testInstallResourceGroupName, "RandomContributorRoleAssignmentNameGUID")
				mockGetFederatedIdentityCredentialNotFound(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", "testServiceAccount1")
				mockCreateOrUpdateFederatedIdentityCredentialSuccess(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", "testServiceAccount1", testSubscriptionID)
				mockGetFederatedIdentityCredentialNotFound(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", "testServiceAccount2")
				mockCreateOrUpdateFederatedIdentityCredentialSuccess(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", "testServiceAccount2", testSubscriptionID)
				return wrapper
			},
			enableTechPreview: true,
			setup: func(t *testing.T) string {
				tempDirName, err := os.MkdirTemp(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "failed to create temp directory")

				manifestsDirPath := filepath.Join(tempDirName, provisioning.ManifestsDirName)
				err = provisioning.EnsureDir(manifestsDirPath)
				require.NoError(t, err, "errored while creating manifests directory for test")

				credReqDirPath := filepath.Join(tempDirName, "credreqs")
				err = provisioning.EnsureDir(credReqDirPath)
				require.NoError(t, err, "errored while creating credreq directory for test")

				err = testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", filepath.Join(tempDirName, "credreqs"), true)
				require.NoError(t, err, "errored while setting up test CredReq files")
				return tempDirName
			},
			verify: func(t *testing.T, tempDirName string) {
				files, err := ioutil.ReadDir(tempDirName)
				require.NoError(t, err, "unexpected error listing files in targetDir")
				assert.Zero(t, provisioning.CountNonDirectoryFiles(files), "Should be no generated files in targetDir")

				manifestsDirPath := filepath.Join(tempDirName, provisioning.ManifestsDirName)
				files, err = ioutil.ReadDir(manifestsDirPath)
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Equal(t, 1, provisioning.CountNonDirectoryFiles(files), "Should be exactly 1 secret in manifestsDir for one CredReq")
			},
			expectError: false,
		},
		{
			name: "Create zero (0) managed identities for one (1) CredentialsRequest with a TechPreviewNoUpgrade annotation, --enable-tech-preview not set",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				resourceTags, _ := mergeResourceTags(testUserTags, map[string]*string{})
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetResourceGroupNotFound(wrapper, testInstallResourceGroupName, testSubscriptionID)
				mockCreateOrUpdateResourceGroupSuccess(wrapper, testInstallResourceGroupName, testRegionName, testSubscriptionID, resourceTags)
				return wrapper
			},
			enableTechPreview: false,
			setup: func(t *testing.T) string {
				tempDirName, err := os.MkdirTemp(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "failed to create temp directory")

				manifestsDirPath := filepath.Join(tempDirName, provisioning.ManifestsDirName)
				err = provisioning.EnsureDir(manifestsDirPath)
				require.NoError(t, err, "errored while creating manifests directory for test")

				credReqDirPath := filepath.Join(tempDirName, "credreqs")
				err = provisioning.EnsureDir(credReqDirPath)
				require.NoError(t, err, "errored while creating credreq directory for test")

				err = testCredentialsRequest(t, "firstcredreq", "namespace1", "secretName1", filepath.Join(tempDirName, "credreqs"), true)
				require.NoError(t, err, "errored while setting up test CredReq files")
				return tempDirName
			},
			verify: func(t *testing.T, targetDir string) {
				files, err := ioutil.ReadDir(targetDir)
				require.NoError(t, err, "unexpected error listing files in targetDir")
				assert.Zero(t, provisioning.CountNonDirectoryFiles(files), "Should be no files in targetDir when no CredReqs to process")

				files, err = ioutil.ReadDir(filepath.Join(targetDir, provisioning.ManifestsDirName))
				require.NoError(t, err, "unexpected error listing files in manifestsDir")
				assert.Zero(t, provisioning.CountNonDirectoryFiles(files), "Should be no files in manifestsDir when no CredReqs to process")
			},
			expectError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)

			mockAzureClientWrapper := test.mockAzureClientWrapper(mockCtrl)

			tempDirName := test.setup(t)
			defer os.RemoveAll(tempDirName)

			err := createManagedIdentities(
				mockAzureClientWrapper,
				filepath.Join(tempDirName, "credreqs"),
				testInfraName,
				testOIDCResourceGroupName,
				testSubscriptionID,
				testRegionName,
				testIssuerURL,
				tempDirName,
				testInstallResourceGroupName,
				testDNSZoneResourceGroupName,
				testUserTags,
				test.enableTechPreview,
				test.dryRun)
			if test.expectError {
				require.Error(t, err, "expected error")
			} else {
				require.NoError(t, err, "unexpected error")
				test.verify(t, tempDirName)
			}
		})
	}
}

func TestEnsureUserAssignedManagedIdentity(t *testing.T) {
	tests := []struct {
		name                   string
		mockAzureClientWrapper func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper
		expectError            bool
	}{
		{
			name: "Pre-existing user-assigned managed identity not found, identity created",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				resourceTags, _ := mergeResourceTags(testUserTags, map[string]*string{})
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetUserAssignedManagedIdentityNotFound(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1")
				mockCreateOrUpdateManagedIdentitySuccess(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", testRegionName, testSubscriptionID, resourceTags)
				return wrapper
			},
		},
		{
			name: "Pre-existing user-assigned managed identity found with correct tags, identity not created or updated",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				resourceTags, _ := mergeResourceTags(testUserTags, map[string]*string{})
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetUserAssignedManagedIdentitySuccess(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", testSubscriptionID, resourceTags)
				return wrapper
			},
		},
		{
			name: "Pre-existing user-assigned managed identity found with incorrect tags, identity updated",
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
				mockGetUserAssignedManagedIdentitySuccess(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", testSubscriptionID, gotResourceTags)
				mockCreateOrUpdateManagedIdentitySuccess(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", testRegionName, testSubscriptionID, wantResourceTags)
				return wrapper
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			mockAzureClientWrapper := test.mockAzureClientWrapper(mockCtrl)
			_, err := ensureUserAssignedManagedIdentity(mockAzureClientWrapper, "testinfraname-secretName1-namespace1", testOIDCResourceGroupName, testRegionName, testUserTags)
			if test.expectError {
				require.Error(t, err, "expected error")
			} else {
				require.NoError(t, err, "unexpected error")
			}
		})
	}
}

func TestEnsureFederatedIdentityCredential(t *testing.T) {
	tests := []struct {
		name                   string
		mockAzureClientWrapper func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper
		expectError            bool
	}{
		{
			name: "Pre-existing federated identity credential not found, credential created",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetFederatedIdentityCredentialNotFound(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", "testServiceAccount1")
				mockCreateOrUpdateFederatedIdentityCredentialSuccess(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", "testServiceAccount1", testSubscriptionID)
				return wrapper
			},
		},
		{
			name: "Pre-existing federated identity credential found with correct audience, subject and issuer URL, credential not created or updated",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetFederatedIdentityCredentialSuccess(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", "testServiceAccount1", testSubscriptionID, "openshift", testIssuerURL, "system:serviceaccount:namespace1:testServiceAccount1")
				return wrapper
			},
		},
		{
			name: "Pre-existing federated identity credential found with incorrect audience, credential updated",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetFederatedIdentityCredentialSuccess(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", "testServiceAccount1", testSubscriptionID, "wrongaudience", testIssuerURL, "system:serviceaccount:namespace1:testServiceAccount1")
				mockCreateOrUpdateFederatedIdentityCredentialSuccess(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", "testServiceAccount1", testSubscriptionID)
				return wrapper
			},
		},
		{
			name: "Pre-existing federated identity credential found with incorrect subject, credential updated",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetFederatedIdentityCredentialSuccess(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", "testServiceAccount1", testSubscriptionID, "openshift", testIssuerURL, "system:serviceaccount:wrongnamespace:testServiceAccount1")
				mockCreateOrUpdateFederatedIdentityCredentialSuccess(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", "testServiceAccount1", testSubscriptionID)
				return wrapper
			},
		},
		{
			name: "Pre-existing federated identity credential found with incorrect issuer URL, credential updated",
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockGetFederatedIdentityCredentialSuccess(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", "testServiceAccount1", testSubscriptionID, "openshift", "http://hue.hae", "system:serviceaccount:namespace1:testServiceAccount1")
				mockCreateOrUpdateFederatedIdentityCredentialSuccess(wrapper, testOIDCResourceGroupName, "testinfraname-secretName1-namespace1", "testServiceAccount1", testSubscriptionID)
				return wrapper
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			mockAzureClientWrapper := test.mockAzureClientWrapper(mockCtrl)
			err := ensureFederatedIdentityCredential(mockAzureClientWrapper, "testinfraname-secretName1-namespace1", testIssuerURL, "namespace1", "testServiceAccount1", testOIDCResourceGroupName)
			if test.expectError {
				require.Error(t, err, "expected error")
			} else {
				require.NoError(t, err, "unexpected error")
			}
		})
	}
}

func TestEnsureRolesAssignedToManagedIdentity(t *testing.T) {
	tests := []struct {
		name                   string
		mockAzureClientWrapper func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper
		roleBindings           []credreqv1.RoleBinding
		expectError            bool
	}{
		{
			name: "Managed identity has expected role assignments, no role assignments created, no role assignments deleted",
			roleBindings: []credreqv1.RoleBinding{
				{
					Role: "Private DNS Zone Contributor",
				},
				{
					Role: "DNS Zone Contributor",
				},
			},
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockRoleAssignmentsListPager(wrapper,
					[]*armauthorization.RoleAssignment{
						{
							Name: to.Ptr("PrivateDNSZoneContibutorRoleAssignmentName"),
							Properties: &armauthorization.RoleAssignmentPropertiesWithScope{
								Scope:            to.Ptr("/subscriptions/" + testSubscriptionID + "/resourceGroups/" + testInstallResourceGroupName),
								PrincipalID:      to.Ptr(testManagedIdentityPrincipalID),
								RoleDefinitionID: to.Ptr(fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", testSubscriptionID, "PrivateDNSZoneContibutorRoleDefinitionID")),
							},
						},
						{
							Name: to.Ptr("DNSZoneContibutorRoleAssignmentName"),
							Properties: &armauthorization.RoleAssignmentPropertiesWithScope{
								Scope:            to.Ptr("/subscriptions/" + testSubscriptionID + "/resourceGroups/" + testInstallResourceGroupName),
								PrincipalID:      to.Ptr(testManagedIdentityPrincipalID),
								RoleDefinitionID: to.Ptr(fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", testSubscriptionID, "DNSZoneContributorRoleDefinitionID")),
							},
						},
					},
					testManagedIdentityPrincipalID,
				)
				mockRoleDefinitionsListPager(wrapper, "/subscriptions/"+testSubscriptionID,
					[]*armauthorization.RoleDefinition{
						{
							Name: to.Ptr("PrivateDNSZoneContibutorRoleDefinitionID"),
							ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", testSubscriptionID, "PrivateDNSZoneContibutorRoleDefinitionID")),
							Properties: &armauthorization.RoleDefinitionProperties{
								RoleName: to.Ptr("Private DNS Zone Contributor"),
							},
						},
					})
				mockRoleDefinitionsListPager(wrapper, "/subscriptions/"+testSubscriptionID,
					[]*armauthorization.RoleDefinition{
						{
							Name: to.Ptr("DNSZoneContributorRoleDefinitionID"),
							ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", testSubscriptionID, "DNSZoneContributorRoleDefinitionID")),
							Properties: &armauthorization.RoleDefinitionProperties{
								RoleName: to.Ptr("DNS Zone Contributor"),
							},
						},
					})
				return wrapper
			},
		},
		{
			name: "Managed identity has extra role assignments not enumerated in RoleBindings, extra role assignments deleted",
			roleBindings: []credreqv1.RoleBinding{
				{
					Role: "Private DNS Zone Contributor",
				},
			},
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockRoleAssignmentsListPager(wrapper,
					[]*armauthorization.RoleAssignment{
						{
							Name: to.Ptr("PrivateDNSZoneContibutorRoleAssignmentName"),
							Properties: &armauthorization.RoleAssignmentPropertiesWithScope{
								Scope:            to.Ptr("/subscriptions/" + testSubscriptionID + "/resourceGroups/" + testInstallResourceGroupName),
								PrincipalID:      to.Ptr(testManagedIdentityPrincipalID),
								RoleDefinitionID: to.Ptr(fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", testSubscriptionID, "PrivateDNSZoneContibutorRoleDefinitionID")),
							},
						},
						// This existing role assignment isn't enumerated in the credreqv1.RoleBindings
						{
							Name: to.Ptr("DNSZoneContibutorRoleAssignmentName"),
							Properties: &armauthorization.RoleAssignmentPropertiesWithScope{
								Scope:            to.Ptr("/subscriptions/" + testSubscriptionID + "/resourceGroups/" + testInstallResourceGroupName),
								PrincipalID:      to.Ptr(testManagedIdentityPrincipalID),
								RoleDefinitionID: to.Ptr(fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", testSubscriptionID, "DNSZoneContributorRoleDefinitionID")),
							},
						},
					},
					testManagedIdentityPrincipalID,
				)
				mockRoleDefinitionsListPager(wrapper, "/subscriptions/"+testSubscriptionID,
					[]*armauthorization.RoleDefinition{
						{
							Name: to.Ptr("PrivateDNSZoneContibutorRoleDefinitionName"),
							ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", testSubscriptionID, "PrivateDNSZoneContibutorRoleDefinitionID")),
							Properties: &armauthorization.RoleDefinitionProperties{
								RoleName: to.Ptr("Private DNS Zone Contributor"),
							},
						},
					})
				mockGetRoleDefinitionByIDSuccess(wrapper, fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", testSubscriptionID, "DNSZoneContributorRoleDefinitionID"), "DNS Zone Contributor")
				mockDeleteRoleAssignmentSuccess(wrapper, "/subscriptions/"+testSubscriptionID+"/resourceGroups/"+testInstallResourceGroupName, "DNSZoneContibutorRoleAssignmentName")
				return wrapper
			},
		},
		{
			name: "Managed identity has missing role assignments, missing role assignments created",
			roleBindings: []credreqv1.RoleBinding{
				{
					Role: "Private DNS Zone Contributor",
				},
				// This RoleBinding won't be found in the RoleAssignments listed for the managed identity
				{
					Role: "DNS Zone Contributor",
				},
			},
			mockAzureClientWrapper: func(mockCtrl *gomock.Controller) *azureclients.AzureClientWrapper {
				wrapper := mockAzureClientWrapper(mockCtrl)
				mockRoleAssignmentsListPager(wrapper,
					[]*armauthorization.RoleAssignment{
						{
							Name: to.Ptr("PrivateDNSZoneContibutorRoleAssignmentName"),
							Properties: &armauthorization.RoleAssignmentPropertiesWithScope{
								Scope:            to.Ptr("/subscriptions/" + testSubscriptionID + "/resourceGroups/" + testInstallResourceGroupName),
								PrincipalID:      to.Ptr(testManagedIdentityPrincipalID),
								RoleDefinitionID: to.Ptr(fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", testSubscriptionID, "PrivateDNSZoneContibutorRoleDefinitionID")),
							},
						},
					},
					testManagedIdentityPrincipalID,
				)
				mockRoleDefinitionsListPager(wrapper, "/subscriptions/"+testSubscriptionID,
					[]*armauthorization.RoleDefinition{
						{
							Name: to.Ptr("PrivateDNSZoneContibutorRoleDefinitionName"),
							ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", testSubscriptionID, "PrivateDNSZoneContibutorRoleDefinitionID")),
							Properties: &armauthorization.RoleDefinitionProperties{
								RoleName: to.Ptr("Private DNS Zone Contributor"),
							},
						},
					})
				mockRoleDefinitionsListPager(wrapper, "/subscriptions/"+testSubscriptionID,
					[]*armauthorization.RoleDefinition{
						{
							Name: to.Ptr("DNSZoneContributorRoleDefinitionName"),
							ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", testSubscriptionID, "DNSZoneContributorRoleDefinitionID")),
							Properties: &armauthorization.RoleDefinitionProperties{
								RoleName: to.Ptr("DNS Zone Contributor"),
							},
						},
					})
				mockCreateRoleAssignmentSuccess(wrapper, "/subscriptions/"+testSubscriptionID+"/resourceGroups/"+testInstallResourceGroupName, "RandomRoleAssignmentNameGUID")
				return wrapper
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			mockAzureClientWrapper := test.mockAzureClientWrapper(mockCtrl)
			err := ensureRolesAssignedToManagedIdentity(mockAzureClientWrapper, testManagedIdentityPrincipalID, testSubscriptionID, test.roleBindings, testScopingResourceGroupNames)
			if test.expectError {
				require.Error(t, err, "expected error")
			} else {
				require.NoError(t, err, "unexpected error")
			}
		})
	}
}

func testCredentialsRequest(t *testing.T, crName, targetSecretNamespace, targetSecretName, targetDir string, isTechPreview bool) error {
	var credReq string
	if isTechPreview {
		credReq = fmt.Sprintf(credReqTechPreviewTemplate, crName, targetSecretNamespace, targetSecretName)
	} else {
		credReq = fmt.Sprintf(credReqTemplate, crName, targetSecretNamespace, targetSecretName)
	}

	f, err := ioutil.TempFile(targetDir, "testCredReq*.yaml")
	require.NoError(t, err, "error creating temp file for CredentialsRequest")
	defer f.Close()

	_, err = f.Write([]byte(credReq))
	require.NoError(t, err, "error while writing out contents of CredentialsRequest file")

	return nil
}

func mockGetUserAssignedManagedIdentitySuccess(wrapper *azureclients.AzureClientWrapper, resourceGroupName, managedIdentityName, subscriptionID string, tags map[string]*string) {
	wrapper.UserAssignedIdentitiesClient.(*mockazure.MockUserAssignedIdentitiesClient).EXPECT().Get(
		gomock.Any(), // context
		resourceGroupName,
		managedIdentityName,
		gomock.Any(), // options
	).Return(
		armmsi.UserAssignedIdentitiesClientGetResponse{
			Identity: armmsi.Identity{
				ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/resourcegroups/%s/providers/Microsoft.ManagedIdentity/userAssignedIdentities/%s", subscriptionID, resourceGroupName, managedIdentityName)),
				Name: to.Ptr(managedIdentityName),
				Properties: &armmsi.UserAssignedIdentityProperties{
					PrincipalID: to.Ptr(testManagedIdentityPrincipalID),
					ClientID:    to.Ptr("testClientID"),
					TenantID:    to.Ptr("testTenantID"),
				},
				Tags: tags,
			},
		},
		nil, // no error
	)
}

func mockGetUserAssignedManagedIdentityNotFound(wrapper *azureclients.AzureClientWrapper, resourceGroupName, managedIdentityName string) {
	respHeader := http.Header{}
	respHeader.Set("x-ms-error-code", "ResourceNotFound")
	resp := &http.Response{
		Header: respHeader,
	}
	wrapper.UserAssignedIdentitiesClient.(*mockazure.MockUserAssignedIdentitiesClient).EXPECT().Get(
		gomock.Any(), // context
		resourceGroupName,
		managedIdentityName,
		gomock.Any(), // options
	).Return(
		armmsi.UserAssignedIdentitiesClientGetResponse{},
		NewResponseError(resp),
	)
}

func mockCreateOrUpdateManagedIdentitySuccess(wrapper *azureclients.AzureClientWrapper, resourceGroupName, managedIdentityName, region, subscriptionID string, tags map[string]*string) {
	parameters := armmsi.Identity{
		Location: to.Ptr(region),
		Tags:     tags,
	}
	userAssignedIdentitiesClientCreateOrUpdateResponse := armmsi.UserAssignedIdentitiesClientCreateOrUpdateResponse{
		Identity: armmsi.Identity{
			ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/resourcegroups/%s/providers/Microsoft.ManagedIdentity/userAssignedIdentities/%s", subscriptionID, resourceGroupName, managedIdentityName)),
			Name: to.Ptr(managedIdentityName),
			Properties: &armmsi.UserAssignedIdentityProperties{
				PrincipalID: to.Ptr(testManagedIdentityPrincipalID),
				ClientID:    to.Ptr("testClientID"),
				TenantID:    to.Ptr("testTenantID"),
			},
			Tags: tags,
		},
	}
	wrapper.UserAssignedIdentitiesClient.(*mockazure.MockUserAssignedIdentitiesClient).EXPECT().CreateOrUpdate(
		gomock.Any(), // context
		resourceGroupName,
		managedIdentityName,
		parameters,
		gomock.Any(), // options
	).Return(
		userAssignedIdentitiesClientCreateOrUpdateResponse,
		nil, // no error
	)
}

func mockRoleDefinitionsListPager(wrapper *azureclients.AzureClientWrapper, scope string, existingRoleDefinitions []*armauthorization.RoleDefinition) {
	roleDefinitionsListResult := armauthorization.RoleDefinitionsClientListResponse{
		RoleDefinitionListResult: armauthorization.RoleDefinitionListResult{
			Value: existingRoleDefinitions,
		},
	}

	wrapper.RoleDefinitionsClient.(*mockazure.MockRoleDefinitionsClient).EXPECT().NewListPager(
		scope,
		gomock.Any(), // options
	).Return(
		runtime.NewPager(runtime.PagingHandler[armauthorization.RoleDefinitionsClientListResponse]{
			More: func(current armauthorization.RoleDefinitionsClientListResponse) bool {
				return current.NextLink != nil
			},
			Fetcher: func(ctx context.Context, current *armauthorization.RoleDefinitionsClientListResponse) (armauthorization.RoleDefinitionsClientListResponse, error) {
				return roleDefinitionsListResult, nil
			},
		}),
	)
}

func mockRoleAssignmentsListPager(wrapper *azureclients.AzureClientWrapper, existingRoleAssignments []*armauthorization.RoleAssignment, managedIdentityPrincipalID string) {
	roleAssignmentsListResult := armauthorization.RoleAssignmentsClientListResponse{
		RoleAssignmentListResult: armauthorization.RoleAssignmentListResult{
			Value: existingRoleAssignments,
		},
	}
	options := armauthorization.RoleAssignmentsClientListOptions{
		Filter: to.Ptr(fmt.Sprintf("principalId eq '%s'", managedIdentityPrincipalID)),
	}
	wrapper.RoleAssignmentClient.(*mockazure.MockRoleAssignmentsClient).EXPECT().NewListPager(&options).Return(
		runtime.NewPager(runtime.PagingHandler[armauthorization.RoleAssignmentsClientListResponse]{
			More: func(current armauthorization.RoleAssignmentsClientListResponse) bool {
				return current.NextLink != nil
			},
			Fetcher: func(ctx context.Context, current *armauthorization.RoleAssignmentsClientListResponse) (armauthorization.RoleAssignmentsClientListResponse, error) {
				return roleAssignmentsListResult, nil
			},
		}),
	)
}

func mockCreateRoleAssignmentSuccess(wrapper *azureclients.AzureClientWrapper, scope, roleAssignmentName string) {
	roleAssignmentsClientCreateResponse := armauthorization.RoleAssignmentsClientCreateResponse{
		RoleAssignment: armauthorization.RoleAssignment{
			ID:   to.Ptr("/role/assignment/ID/path"),
			Name: to.Ptr(roleAssignmentName),
		},
	}
	wrapper.RoleAssignmentClient.(*mockazure.MockRoleAssignmentsClient).EXPECT().Create(
		gomock.Any(), // context
		scope,
		gomock.Any(), // roleAssignmentName, GUID generated by createRoleAssignment()
		gomock.Any(), // parameters
		gomock.Any(), // options
	).Return(
		roleAssignmentsClientCreateResponse,
		nil, // no error
	)
}

func mockCreateOrUpdateFederatedIdentityCredentialSuccess(wrapper *azureclients.AzureClientWrapper, resourceGroupName, managedIdentityName, federatedIdentityCredentialName, subscriptionID string) {
	federatedIdentityCredentialsClientCreateOrUpdateResponse := armmsi.FederatedIdentityCredentialsClientCreateOrUpdateResponse{
		FederatedIdentityCredential: armmsi.FederatedIdentityCredential{
			ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/resourcegroups/abutcherdemo-oidc/providers/Microsoft.ManagedIdentity/userAssignedIdentities/%s/federatedIdentityCredentials/%s", subscriptionID, managedIdentityName, federatedIdentityCredentialName)),
			Name: to.Ptr(federatedIdentityCredentialName),
		},
	}
	wrapper.FederatedIdentityCredentialsClient.(*mockazure.MockFederatedIdentityCredentialsClient).EXPECT().CreateOrUpdate(
		gomock.Any(), // context
		resourceGroupName,
		managedIdentityName,
		federatedIdentityCredentialName,
		gomock.Any(), // parameters
		gomock.Any(), // options
	).Return(
		federatedIdentityCredentialsClientCreateOrUpdateResponse,
		nil, // no error
	)
}

func mockGetFederatedIdentityCredentialNotFound(wrapper *azureclients.AzureClientWrapper, resourceGroupName, managedIdentityName, federatedIdentityCredentialName string) {
	respHeader := http.Header{}
	respHeader.Set("x-ms-error-code", "NotFound")
	resp := &http.Response{
		Header: respHeader,
	}
	wrapper.FederatedIdentityCredentialsClient.(*mockazure.MockFederatedIdentityCredentialsClient).EXPECT().Get(
		gomock.Any(), // context
		resourceGroupName,
		managedIdentityName,
		federatedIdentityCredentialName,
		gomock.Any(), // options
	).Return(
		armmsi.FederatedIdentityCredentialsClientGetResponse{},
		NewResponseError(resp),
	)
}

func mockGetFederatedIdentityCredentialSuccess(wrapper *azureclients.AzureClientWrapper, resourceGroupName, managedIdentityName, federatedIdentityCredentialName, subscriptionID, audience, issuerURL, subject string) {
	wrapper.FederatedIdentityCredentialsClient.(*mockazure.MockFederatedIdentityCredentialsClient).EXPECT().Get(
		gomock.Any(), // context
		resourceGroupName,
		managedIdentityName,
		federatedIdentityCredentialName,
		gomock.Any(), // options
	).Return(
		armmsi.FederatedIdentityCredentialsClientGetResponse{
			FederatedIdentityCredential: armmsi.FederatedIdentityCredential{
				ID: to.Ptr(fmt.Sprintf("/subscriptions/%s/resourcegroups/%s/providers/Microsoft.ManagedIdentity/userAssignedIdentities/%s/federatedIdentityCredentials/%s", subscriptionID, resourceGroupName, managedIdentityName, federatedIdentityCredentialName)),
				Properties: &armmsi.FederatedIdentityCredentialProperties{
					Audiences: []*string{to.Ptr(audience)},
					Issuer:    to.Ptr(issuerURL),
					Subject:   to.Ptr(subject),
				},
			},
		},
		nil, // no error
	)
}

func mockGetRoleDefinitionByIDSuccess(wrapper *azureclients.AzureClientWrapper, roleDefinitionID, roleName string) {
	wrapper.RoleDefinitionsClient.(*mockazure.MockRoleDefinitionsClient).EXPECT().GetByID(
		gomock.Any(), // context
		roleDefinitionID,
		gomock.Any(), // options
	).Return(
		armauthorization.RoleDefinitionsClientGetByIDResponse{
			RoleDefinition: armauthorization.RoleDefinition{
				Properties: &armauthorization.RoleDefinitionProperties{
					RoleName: to.Ptr(roleName),
				},
			},
		},
		nil, // no error
	)
}

func mockDeleteRoleAssignmentSuccess(wrapper *azureclients.AzureClientWrapper, scope, roleAssignmentName string) {
	wrapper.RoleAssignmentClient.(*mockazure.MockRoleAssignmentsClient).EXPECT().Delete(
		gomock.Any(), // context
		scope,
		roleAssignmentName,
		gomock.Any(), // options
	).Return(
		armauthorization.RoleAssignmentsClientDeleteResponse{},
		nil,
	)
}
