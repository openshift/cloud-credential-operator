package azure

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	azureclients "github.com/openshift/cloud-credential-operator/pkg/azure"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
)

var (
	// CreateOIDCIssuerOpts captures the azureOptions that affect creation of the OIDC issuer
	CreateOIDCIssuerOpts = azureOptions{}

	openidConfigurationTemplate = `{
		"issuer": "%s",
		"jwks_uri": "%s/openid/v1/jwks",
		"response_types_supported": [
		  "id_token"
		],
		"subject_types_supported": [
		  "public"
		],
		"id_token_signing_alg_values_supported": [
		  "RS256"
		]
	  }`

	openidConfigurationFileName = "openid-configuration"
	jwksFileName                = "jwks"
	fileMode                    = 0644

	// oidcResourceGroupSuffix is the suffix used for the name of the resource group in which the OIDC
	// infrastructure is created
	oidcResourceGroupSuffix = "-oidc"

	// ownedAzureResourceTagKeyPrefix is the prefix of the tag key applied to Azure resources created by ccoctl
	ownedAzureResourceTagKeyPrefix = "openshift.io_cloud-credential-operator"

	// ownedAzureResourceTagValue is the value of the tag applied to the Azure resources created by ccoctl
	ownedAzureResourceTagValue = "owned"

	// nameTagKey is the key of the "Name" tag applied to Azure resources created by ccoctl
	nameTagKey = "Name"
)

// ensureResourceGroup ensures that a resource group with resourceGroupName exists within the provided region and subscription
// The resource group will only be tagged when created by ensureResourceGroup().
func ensureResourceGroup(client *azureclients.AzureClientWrapper, resourceGroupName, region string, resourceTags map[string]string) (*armresources.ResourceGroup, error) {
	// Check if resource group already exists
	needToCreateResourceGroup := false
	var rawResponse *http.Response
	ctxWithResp := runtime.WithCaptureResponse(context.Background(), &rawResponse)
	getResourceGroupResp, err := client.ResourceGroupsClient.Get(
		ctxWithResp,
		resourceGroupName,
		&armresources.ResourceGroupsClientGetOptions{})
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) {
			switch respErr.ErrorCode {
			case "ResourceGroupNotFound":
				// Resource group wasn't found so the resource group will need to be created
				needToCreateResourceGroup = true
			default:
				return nil, errors.Wrapf(err, "unable to get resource group")
			}
		} else {
			return nil, err
		}
	}

	// Validate that existing resource group is in requested region
	if getResourceGroupResp.Location != nil && *getResourceGroupResp.Location != region {
		return nil, fmt.Errorf("found existing resource group %s in unexpected region=%s, requested region=%s",
			*getResourceGroupResp.ResourceGroup.ID,
			*getResourceGroupResp.Location,
			region)
	}

	// Found and validated existing resource group, return
	if !needToCreateResourceGroup {
		log.Printf("Found existing resource group %s", *getResourceGroupResp.ResourceGroup.ID)
		return &getResourceGroupResp.ResourceGroup, nil
	}

	// Add provided tags to resource group parameters
	// NOTE: resourceTags will not be added to a resource group that ccoctl did not create. See return above.
	resourceGroupParameters := armresources.ResourceGroup{
		Location: to.Ptr(region),
		Tags: map[string]*string{
			nameTagKey: to.Ptr(resourceGroupName),
		},
	}
	for tagKey, tagValue := range resourceTags {
		resourceGroupParameters.Tags[tagKey] = to.Ptr(tagValue)
	}

	// Create resource group
	createResourceGroupResp, err := client.ResourceGroupsClient.CreateOrUpdate(
		context.Background(),
		resourceGroupName,
		resourceGroupParameters,
		nil)
	if err != nil {
		return nil, err
	}
	log.Printf("Created resource group %s", *createResourceGroupResp.ResourceGroup.ID)
	return &createResourceGroupResp.ResourceGroup, nil
}

// ensureStorageAccount ensures that a storage account with storageAccountName exists within the provided resource group, region and subscription
// The storage account will only be tagged when created by ensureStorageAccount().
func ensureStorageAccount(client *azureclients.AzureClientWrapper, storageAccountName, resourceGroupName, region string, resourceTags map[string]string) (*armstorage.Account, error) {
	listAccounts := client.StorageAccountClient.NewListByResourceGroupPager(resourceGroupName, &armstorage.AccountsClientListByResourceGroupOptions{})
	list := make([]*armstorage.Account, 0)
	for listAccounts.More() {
		pageResponse, err := listAccounts.NextPage(context.Background())
		if err != nil {
			return nil, err
		}
		list = append(list, pageResponse.AccountListResult.Value...)
	}
	for _, storageAccount := range list {
		if *storageAccount.Name == storageAccountName {
			// Validate that existing storage account is in requested region
			if *storageAccount.Location != region {
				return nil, fmt.Errorf("found existing storage account %s in unexpected region=%s, requested region=%s",
					*storageAccount.ID,
					*storageAccount.Location,
					region)
			}
			// Found and validated existing storage account, return
			log.Printf("Found existing storage account %s", *storageAccount.ID)
			return storageAccount, nil
		}
	}

	storageAccountParameters := armstorage.AccountCreateParameters{
		Kind: to.Ptr(armstorage.KindStorageV2),
		SKU: &armstorage.SKU{
			Name: to.Ptr(armstorage.SKUNameStandardLRS),
		},
		Location: to.Ptr(region),
		Tags: map[string]*string{
			nameTagKey: to.Ptr(storageAccountName),
		},
	}

	// Add provided tags to storage account parameters
	// NOTE: userTags will not be added to a storage account that ccoctl did not create. See return above.
	for tagKey, tagValue := range resourceTags {
		storageAccountParameters.Tags[tagKey] = to.Ptr(tagValue)
	}

	// Create storage account
	pollerResp, err := client.StorageAccountClient.BeginCreate(
		context.TODO(),
		resourceGroupName,
		storageAccountName,
		storageAccountParameters,
		&armstorage.AccountsClientBeginCreateOptions{})
	if err != nil {
		return nil, err
	}
	// TODO: Creating the storage account can take time, do we need to display progress in some way or is it
	//       acceptable to output a log line when we have finished?
	// PollUntilDone polls every 30 seconds by default.
	pollerWrapper := azureclients.NewPollerWrapper[armstorage.AccountsClientCreateResponse](
		pollerResp,
		client.Mock,
		// When Mock = true this armstorage.AccountsClientCreateResponse will be returned
		// from PollUntilDone() from the azureclients.PollerWrapper defined herein.
		armstorage.AccountsClientCreateResponse{
			Account: armstorage.Account{
				Name: to.Ptr(storageAccountName),
				ID:   to.Ptr(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Storage/storageAccounts/%s", "123456789", resourceGroupName, storageAccountName)),
			},
		},
	)
	resp, err := pollerWrapper.PollUntilDone(context.Background(), &runtime.PollUntilDoneOptions{Frequency: 10 * time.Second})
	if err != nil {
		return nil, err
	}
	log.Printf("Created storage account %s", *resp.Account.ID)
	return &resp.Account, nil
}

// getStorageAccountKey lists storage account keys for the storage account identified by storageAccountName and
// returns the first key found.
func getStorageAccountKey(client *azureclients.AzureClientWrapper, storageAccountName, resourceGroupName string) (string, error) {
	listKeysResp, err := client.StorageAccountClient.ListKeys(context.Background(), resourceGroupName, storageAccountName, &armstorage.AccountsClientListKeysOptions{})
	if err != nil {
		return "", err
	}
	keys := listKeysResp.Keys
	for _, key := range keys {
		if key.Value != nil {
			return *key.Value, nil
		}
	}
	return "", nil
}

// ensureBlobContainer ensures that a storage group with storageAccountName exists within the provided resource group, region and subscription
// The storage group will only be tagged when created by ensureStorageAccount().
func ensureBlobContainer(client *azureclients.AzureClientWrapper, resourceGroupName, storageAccountName, containerName string) (*armstorage.BlobContainer, error) {
	// Check if blob container already exists
	needToCreateBlobContainer := false
	var rawResponse *http.Response
	ctxWithResp := runtime.WithCaptureResponse(context.Background(), &rawResponse)
	getBlobContainerResp, err := client.BlobContainerClient.Get(
		ctxWithResp,
		resourceGroupName,
		storageAccountName,
		containerName,
		&armstorage.BlobContainersClientGetOptions{})
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) {
			switch respErr.ErrorCode {
			case "ContainerNotFound":
				needToCreateBlobContainer = true
			default:
				log.Printf("Unable to get blob container: %v", respErr.ErrorCode)
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	// Found and validated existing blob container, return
	if !needToCreateBlobContainer {
		log.Printf("Found existing blob container %s", *getBlobContainerResp.BlobContainer.ID)
		return &getBlobContainerResp.BlobContainer, nil
	}

	createBlobContainerResp, err := client.BlobContainerClient.Create(
		context.Background(),
		resourceGroupName,
		storageAccountName,
		containerName,
		armstorage.BlobContainer{
			ContainerProperties: &armstorage.ContainerProperties{
				PublicAccess: to.Ptr(armstorage.PublicAccessContainer),
				// Note that blob containers cannot be tagged
			},
		},
		nil,
	)
	if err != nil {
		return nil, err
	}
	log.Printf("Created blob container %s", *createBlobContainerResp.BlobContainer.ID)
	return &createBlobContainerResp.BlobContainer, nil
}

// uploadOIDCDocuments generates and uploads the OIDC discovery document (.well-known/openid-configuration) and the JSON web key set (jwks.json)
// to the blob container
func uploadOIDCDocuments(client *azureclients.AzureClientWrapper, storageAccountName, storageAccountKey, publicKeyFilepath, blobContainerName, targetDir string, dryRun bool) (string, error) {
	blobContainerURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s", storageAccountName, blobContainerName)

	oidcDiscoveryDocumentData := []byte(fmt.Sprintf(openidConfigurationTemplate, blobContainerURL, blobContainerURL))
	oidcDiscoveryDocumentFullPath := filepath.Join(targetDir, openidConfigurationFileName)
	err := os.WriteFile(oidcDiscoveryDocumentFullPath, oidcDiscoveryDocumentData, fs.FileMode(fileMode))
	if err != nil {
		return blobContainerURL, err
	}
	log.Printf("Saved OIDC discovery document at path %s", oidcDiscoveryDocumentFullPath)

	jwksFullPath := filepath.Join(targetDir, jwksFileName)
	jwksData, err := provisioning.BuildJsonWebKeySet(publicKeyFilepath)
	if err != nil {
		return blobContainerURL, err
	}
	err = os.WriteFile(jwksFullPath, jwksData, fs.FileMode(fileMode))
	if err != nil {
		return blobContainerURL, err
	}
	log.Printf("Saved JSON web key set at path %s", jwksFullPath)

	// Return before uploading documents if doing a dry run
	if dryRun {
		return blobContainerURL, nil
	}

	sharedKeyCredential, err := azblob.NewSharedKeyCredential(storageAccountName, storageAccountKey)
	if err != nil {
		log.Fatal(err)
		return blobContainerURL, err
	}
	// NOTE: It is not possible to instantiate an azureclients.AzureClientWrapper with this client
	// because the storage key isn't known when we instantiate the other clients.
	//
	// client.BlobSharedKeyClient is previously set in tests for mocking so only create a real client
	// if client.BlobSharedKeyClient is nil.
	if client.BlobSharedKeyClient == nil {
		client.BlobSharedKeyClient, err = azureclients.NewAZBlobClientWithSharedKeyCredential(blobContainerURL, sharedKeyCredential, nil)
		if err != nil {
			return blobContainerURL, err
		}
	}

	_, err = client.BlobSharedKeyClient.UploadBuffer(
		context.TODO(),
		"",
		filepath.Join(".well-known", openidConfigurationFileName),
		oidcDiscoveryDocumentData,
		// Note: Blobs can be tagged in this options object but the container itself is tagged.
		&azblob.UploadBufferOptions{},
	)
	if err != nil {
		return blobContainerURL, err
	}
	log.Printf("Uploaded OIDC discovery document %s", blobContainerURL+"/.well-known/"+openidConfigurationFileName)

	_, err = client.BlobSharedKeyClient.UploadBuffer(
		context.TODO(),
		"",
		filepath.Join("openid/v1/", jwksFileName),
		jwksData,
		&azblob.UploadBufferOptions{},
	)
	if err != nil {
		return blobContainerURL, err
	}
	log.Printf("Uploaded JSON web key set %s", blobContainerURL+"/openid/v1/"+jwksFileName)

	return blobContainerURL, nil
}

// createOIDCIssuer creates infrastructure necessary for Azure Workload Identity including,
// * resource group in which to create storage account & identities
// * scoping resource group which will remain empty and is used to scope identity role assignment, this resource group is for installation
// * storage account
// * blob container which hosts OIDC documents
func createOIDCIssuer(client *azureclients.AzureClientWrapper, name, region, oidcResourceGroupName, storageAccountName, blobContainerName, subscriptionID, publicKeyPath, outputDir string, resourceTags map[string]string, dryRun bool) (string, error) {
	// Add CCO's "owned" tag to resource tags map
	resourceTags[fmt.Sprintf("%s_%s", ownedAzureResourceTagKeyPrefix, name)] = ownedAzureResourceTagValue

	storageAccountKey := ""
	if !dryRun {
		// Ensure that the public key file can be read at the publicKeyPath before continuing
		_, err := os.ReadFile(publicKeyPath)
		if err != nil {
			return "", errors.Wrap(err, "unable to read public key file")
		}

		// Ensure the resource group exists
		_, err = ensureResourceGroup(client, oidcResourceGroupName, region, resourceTags)
		if err != nil {
			return "", errors.Wrap(err, "failed to ensure resource group")
		}

		// Ensure storage account exists
		_, err = ensureStorageAccount(client, storageAccountName, oidcResourceGroupName, region, resourceTags)
		if err != nil {
			return "", errors.Wrap(err, "failed to ensure storage account")
		}

		storageAccountKey, err = getStorageAccountKey(client, storageAccountName, oidcResourceGroupName)
		if err != nil {
			return "", errors.Wrap(err, "failed to get storage account key")
		}

		// Ensure blob container exists
		_, err = ensureBlobContainer(client, oidcResourceGroupName, storageAccountName, blobContainerName)
		if err != nil {
			return "", errors.Wrap(err, "failed to create blob container")
		}
	}

	// Upload OIDC documents (openid-configuration, jwks.json) to the blob container
	outputDirAbsPath, err := filepath.Abs(outputDir)
	if err != nil {
		return "", err
	}
	issuerURL, err := uploadOIDCDocuments(client, storageAccountName, storageAccountKey, publicKeyPath, blobContainerName, outputDirAbsPath, dryRun)
	if err != nil {
		return "", errors.Wrap(err, "failed to upload OIDC documents")
	}

	// Write cluster authentication object installer manifest cluster-authentication-02-config.yaml
	// for our issuerURL within outputDir/manifests
	if err = provisioning.CreateClusterAuthentication(issuerURL, outputDir); err != nil {
		return "", errors.Wrap(err, "failed to create cluster authentication manifest")
	}

	return issuerURL, nil
}

func createOIDCIssuerCmd(cmd *cobra.Command, args []string) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatal(err)
	}

	azureClientWrapper, err := azureclients.NewAzureClientWrapper(CreateOIDCIssuerOpts.SubscriptionID, cred, &policy.ClientOptions{}, false)
	if err != nil {
		log.Fatalf("Failed to create Azure client: %s", err)
	}

	if CreateOIDCIssuerOpts.OIDCResourceGroupName == "" {
		CreateOIDCIssuerOpts.OIDCResourceGroupName = CreateOIDCIssuerOpts.Name + oidcResourceGroupSuffix
		log.Printf("No --oidc-resource-group-name provided, defaulting OIDC resource group name to %s", CreateOIDCIssuerOpts.OIDCResourceGroupName)
	}

	if CreateOIDCIssuerOpts.StorageAccountName == "" {
		CreateOIDCIssuerOpts.StorageAccountName = CreateOIDCIssuerOpts.Name
		log.Printf("No --storage-account-name provided, defaulting storage account name to %s", CreateOIDCIssuerOpts.StorageAccountName)
	}
	if err := validateStorageAccountName(CreateOIDCIssuerOpts.StorageAccountName); err != nil {
		log.Fatal(err)
	}

	if CreateOIDCIssuerOpts.BlobContainerName == "" {
		CreateOIDCIssuerOpts.BlobContainerName = CreateOIDCIssuerOpts.Name
		log.Printf("No --blob-container-name provided, defaulting blob container name to %s", CreateOIDCIssuerOpts.BlobContainerName)
	}

	_, err = createOIDCIssuer(azureClientWrapper,
		CreateOIDCIssuerOpts.Name,
		CreateOIDCIssuerOpts.Region,
		CreateOIDCIssuerOpts.OIDCResourceGroupName,
		CreateOIDCIssuerOpts.StorageAccountName,
		CreateOIDCIssuerOpts.BlobContainerName,
		CreateOIDCIssuerOpts.SubscriptionID,
		CreateOIDCIssuerOpts.PublicKeyPath,
		CreateOIDCIssuerOpts.OutputDir,
		CreateOIDCIssuerOpts.UserTags,
		CreateOIDCIssuerOpts.DryRun)
	if err != nil {
		log.Fatal(err)
	}
}

func validateStorageAccountName(storageAccountName string) error {
	re := regexp.MustCompile(`^[a-z0-9]{3,24}$`)
	if !re.MatchString(storageAccountName) {
		return errors.New(fmt.Sprintf("invalid storage account name: %s. Azure storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.", storageAccountName))
	}
	return nil
}

// initEnvForCreateOIDCIssuerCmd ensures that the output directory specified by --output-dir exists
func initEnvForCreateOIDCIssuerCmd(cmd *cobra.Command, args []string) {
	if CreateOIDCIssuerOpts.OutputDir == "" {
		pwd, err := os.Getwd()
		if err != nil {
			log.Fatalf("Failed to get current directory: %s", err)
		}
		CreateOIDCIssuerOpts.OutputDir = pwd
		log.Printf("No --output-dir provided, defaulting output directory to the current working directory %s", CreateOIDCIssuerOpts.OutputDir)
	}

	outputDirPath, err := filepath.Abs(CreateOIDCIssuerOpts.OutputDir)
	if err != nil {
		log.Fatalf("Failed to resolve full path of the output directory %s", err)
	}

	// Create output dir if it doesn't exist
	err = provisioning.EnsureDir(outputDirPath)
	if err != nil {
		log.Fatalf("Failed to create target directory at path %s", outputDirPath)
	}

	// Create manifests dir within the output dir if it doesn't exist
	manifestsDirPath := filepath.Join(outputDirPath, provisioning.ManifestsDirName)
	err = provisioning.EnsureDir(manifestsDirPath)
	if err != nil {
		log.Fatalf("Failed to create manifests directory at path %s", manifestsDirPath)
	}
}

// NewCreateOIDCIssuerCmd provides the "create-oidc-issuer" subcommand
func NewCreateOIDCIssuerCmd() *cobra.Command {
	createOIDCIssuerCmd := &cobra.Command{
		Use:              "create-oidc-issuer --name NAME --region REGION --subscription-id SUBSCRIPTION_ID --public-key-file PUBLIC_KEY_FILE",
		Short:            "Create OIDC Issuer",
		Run:              createOIDCIssuerCmd,
		PersistentPreRun: initEnvForCreateOIDCIssuerCmd,
	}

	// Required parameters
	createOIDCIssuerCmd.PersistentFlags().StringVar(
		&CreateOIDCIssuerOpts.Name,
		"name",
		"",
		"User-defined name for all created Azure resources. This user-defined name can be separate from the cluster's infra-id. "+
			fmt.Sprintf("Azure resources created by ccoctl will be tagged with '%s_NAME = %s'", ownedAzureResourceTagKeyPrefix, ownedAzureResourceTagValue),
	)
	createOIDCIssuerCmd.MarkPersistentFlagRequired("name")
	createOIDCIssuerCmd.PersistentFlags().StringVar(&CreateOIDCIssuerOpts.Region, "region", "", "Azure region in which to create identity provider infrastructure")
	createOIDCIssuerCmd.MarkPersistentFlagRequired("region")
	createOIDCIssuerCmd.PersistentFlags().StringVar(&CreateOIDCIssuerOpts.SubscriptionID, "subscription-id", "", "Azure Subscription ID within which to create identity provider infrastructure")
	createOIDCIssuerCmd.MarkPersistentFlagRequired("subscription-id")
	createOIDCIssuerCmd.PersistentFlags().StringVar(&CreateOIDCIssuerOpts.PublicKeyPath, "public-key-file", "", "Path to public ServiceAccount signing key")
	createOIDCIssuerCmd.MarkPersistentFlagRequired("public-key-file")

	// Optional parameters
	createOIDCIssuerCmd.PersistentFlags().StringVar(
		&CreateOIDCIssuerOpts.OIDCResourceGroupName,
		"oidc-resource-group-name",
		"",
		"The Azure resource group in which to create OIDC infrastructure including a storage account, blob storage container and user-assigned managed identities. "+
			"A resource group will be created with a name derived from the --name parameter if an --oidc-resource-group-name parameter was not provided.",
	)
	createOIDCIssuerCmd.PersistentFlags().StringVar(
		&CreateOIDCIssuerOpts.StorageAccountName,
		"storage-account-name",
		"",
		"The name of the Azure storage account in which to create OIDC issuer infrastructure. "+
			"A storage account will be created with a name derived from the --name parameter if a --storage-account-name parameter was not provided. "+
			"The storage account will be created within the OIDC resource group identified by the --oidc-resource-group-name parameter. "+
			"If pre-existing, the storage account must exist within the OIDC resource group identified by the --oidc-resource-group-name parameter. "+
			"Azure storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.",
	)
	createOIDCIssuerCmd.PersistentFlags().StringVar(
		&CreateOIDCIssuerOpts.BlobContainerName,
		"blob-container-name",
		"",
		"The name of the Azure blob container in which to upload OIDC discovery documents. "+
			"A blob container will be created with a name derived from the --name parameter if a --blob-container-name parameter was not provided. "+
			"The blob container will be created within the OIDC resource group identified by the --oidc-resource-group-name parameter "+
			"and storage account identified by --storage-account-name.",
	)
	createOIDCIssuerCmd.PersistentFlags().BoolVar(&CreateOIDCIssuerOpts.DryRun, "dry-run", false, "Skip creating objects, and just save what would have been created into files")
	createOIDCIssuerCmd.PersistentFlags().StringVar(&CreateOIDCIssuerOpts.OutputDir, "output-dir", "", "Directory to place generated manifest files. Defaults to the current directory.")
	createOIDCIssuerCmd.PersistentFlags().StringToStringVar(&CreateOIDCIssuerOpts.UserTags, "user-tags", map[string]string{}, "User tags to be applied to Azure resources, multiple tags may be specified comma-separated for example: --user-tags key1=value1,key2=value2")

	return createOIDCIssuerCmd
}
