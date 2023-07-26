package azure

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	azureclients "github.com/openshift/cloud-credential-operator/pkg/azure"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
	"github.com/spf13/cobra"
)

var (
	// CreateAllOpts captures the azureOptions that affect creation of the OIDC issuer
	// and user-assigned managed identities
	CreateAllOpts = azureOptions{}
)

func createAllCmd(cmd *cobra.Command, args []string) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatal(err)
	}

	azureClientWrapper, err := azureclients.NewAzureClientWrapper(CreateAllOpts.SubscriptionID, cred, &policy.ClientOptions{}, false)
	if err != nil {
		log.Fatalf("Failed to create Azure client: %s", err)
	}

	publicKeyPath := CreateAllOpts.PublicKeyPath
	if publicKeyPath == "" {
		publicKeyPath = filepath.Join(CreateAllOpts.OutputDir, provisioning.PublicKeyFile)
		if err := provisioning.CreateKeys(CreateAllOpts.OutputDir); err != nil {
			log.Fatalf("Failed to create RSA key pair: %s", err)
		}
	}

	if CreateAllOpts.OIDCResourceGroupName == "" {
		CreateAllOpts.OIDCResourceGroupName = CreateAllOpts.Name + oidcResourceGroupSuffix
		log.Printf("No --oidc-resource-group-name provided, defaulting OIDC resource group name to %s", CreateAllOpts.OIDCResourceGroupName)
	}

	if CreateAllOpts.InstallationResourceGroupName == "" {
		CreateAllOpts.InstallationResourceGroupName = CreateAllOpts.Name
		log.Printf("No --installation-resource-group-name provided, defaulting installation resource group name to %s", CreateAllOpts.InstallationResourceGroupName)
	}

	if CreateAllOpts.OIDCResourceGroupName == CreateAllOpts.InstallationResourceGroupName {
		log.Fatalf("OIDC and installation resource group names cannot be the same")
	}

	if CreateAllOpts.StorageAccountName == "" {
		CreateAllOpts.StorageAccountName = CreateAllOpts.Name
		log.Printf("No --storage-account-name provided, defaulting storage account name to %s", CreateAllOpts.StorageAccountName)
	}
	if err := validateStorageAccountName(CreateAllOpts.StorageAccountName); err != nil {
		log.Fatal(err)
	}

	if CreateAllOpts.BlobContainerName == "" {
		CreateAllOpts.BlobContainerName = CreateAllOpts.Name
		log.Printf("No --blob-container-name provided, defaulting blob container name to %s", CreateAllOpts.BlobContainerName)
	}

	issuerURL, err := createOIDCIssuer(azureClientWrapper,
		CreateAllOpts.Name,
		CreateAllOpts.Region,
		CreateAllOpts.OIDCResourceGroupName,
		CreateAllOpts.StorageAccountName,
		CreateAllOpts.BlobContainerName,
		CreateAllOpts.SubscriptionID,
		publicKeyPath,
		CreateAllOpts.OutputDir,
		CreateAllOpts.UserTags,
		// dryRun may only be invoked by subcommands create-oidc-issuer and create-managed-identities
		false)
	if err != nil {
		log.Fatal(err)
	}

	err = createManagedIdentities(azureClientWrapper,
		CreateAllOpts.CredRequestDir,
		CreateAllOpts.Name,
		CreateAllOpts.OIDCResourceGroupName,
		CreateAllOpts.SubscriptionID,
		CreateAllOpts.Region,
		issuerURL,
		CreateAllOpts.OutputDir,
		CreateAllOpts.InstallationResourceGroupName,
		CreateAllOpts.DNSZoneResourceGroupName,
		CreateAllOpts.UserTags,
		CreateAllOpts.EnableTechPreview,
		// dryRun may only be invoked by subcommands create-oidc-issuer and create-managed-identities
		false)
	if err != nil {
		log.Fatal(err)
	}
}

// initEnvForCreateAllCmd ensures that the output directory specified by --output-dir exists
func initEnvForCreateAllCmd(cmd *cobra.Command, args []string) {
	if CreateAllOpts.OutputDir == "" {
		pwd, err := os.Getwd()
		if err != nil {
			log.Fatalf("failed to get current directory: %s", err)
		}
		CreateAllOpts.OutputDir = pwd
		log.Printf("No --output-dir provided, defaulting output directory to the current working directory %s", CreateAllOpts.OutputDir)
	}

	outputDirPath, err := filepath.Abs(CreateAllOpts.OutputDir)
	if err != nil {
		log.Fatalf("Failed to resolve full path of the output directory %s", err)
	}

	// Create output dir if it doesn't exist
	err = provisioning.EnsureDir(outputDirPath)
	if err != nil {
		log.Fatalf("Failed to create target directory at path %s", outputDirPath)
	}

	// Create manifests dir within the output dir if it doesn't exist
	manifestsDir := filepath.Join(outputDirPath, provisioning.ManifestsDirName)
	err = provisioning.EnsureDir(manifestsDir)
	if err != nil {
		log.Fatalf("Failed to create manifests directory at path %s", manifestsDir)
	}

	// Create tls dir within the output dir if it doesn't exist
	tlsDir := filepath.Join(outputDirPath, provisioning.TLSDirName)
	err = provisioning.EnsureDir(tlsDir)
	if err != nil {
		log.Fatalf("Failed to create tls directory at path %s", tlsDir)
	}
}

// NewCreateAllCmd combines create-identity-provider and create-managed-identities commands
func NewCreateAllCmd() *cobra.Command {
	createAllCmd := &cobra.Command{
		Use:              "create-all --name NAME --region REGION --subscription-id SUBSCRIPTION_ID --credentials-requests-dir CRED_REQ_DIR --dnszone-resource-group-name DNSZONE_RESOURCE_GROUP_NAME",
		Short:            "Create OIDC issuer and managed identities",
		Run:              createAllCmd,
		PersistentPreRun: initEnvForCreateAllCmd,
	}

	// Required parameters
	createAllCmd.PersistentFlags().StringVar(
		&CreateAllOpts.Name,
		"name",
		"",
		"User-defined name for all created Azure resources. This user-defined name can be separate from the cluster's infra-id. "+
			fmt.Sprintf("Azure resources created by ccoctl will be tagged with '%s_NAME = %s'", ownedAzureResourceTagKeyPrefix, ownedAzureResourceTagValue),
	)
	createAllCmd.MarkPersistentFlagRequired("name")
	createAllCmd.PersistentFlags().StringVar(&CreateAllOpts.Region, "region", "", "Azure region in which to create identity provider infrastructure")
	createAllCmd.MarkPersistentFlagRequired("region")
	createAllCmd.PersistentFlags().StringVar(&CreateAllOpts.SubscriptionID, "subscription-id", "", "Azure Subscription ID within which to create identity provider infrastructure")
	createAllCmd.MarkPersistentFlagRequired("subscription-id")
	createAllCmd.PersistentFlags().StringVar(&CreateAllOpts.CredRequestDir, "credentials-requests-dir", "", "Directory containing Azure CredentialsRequests files used to create user-assigned managed identities (can be created by running 'oc adm release extract --credentials-requests --cloud=azure' against an OpenShift release image)")
	createAllCmd.MarkPersistentFlagRequired("credentials-requests-dir")
	createAllCmd.PersistentFlags().StringVar(&CreateAllOpts.DNSZoneResourceGroupName, "dnszone-resource-group-name", "", "The existing Azure resource group which contains the DNS zone that will be used for the cluster's base domain. The cluster ingress operator will be scoped to allow management of DNS records in the DNS Zone resource group.")
	createAllCmd.MarkPersistentFlagRequired("dnszone-resource-group-name")

	// Optional parameters
	createAllCmd.PersistentFlags().StringVar(
		&CreateAllOpts.OIDCResourceGroupName,
		"oidc-resource-group-name",
		"",
		"The Azure resource group in which to create OIDC infrastructure including a storage account, blob storage container and user-assigned managed identities. "+
			"A resource group will be created (with a name derived from the --name parameter) if an oidc-resource-group-name parameter was not provided",
	)
	createAllCmd.PersistentFlags().StringVar(
		&CreateAllOpts.InstallationResourceGroupName,
		"installation-resource-group-name",
		"",
		"The Azure resource group which will be used for future cluster installation. "+
			"Managed identities will be scoped such that they can manage resources in this resource group. "+
			"The OpenShift installer requires that the resource group provided for installation resources be initially empty so this resource group must "+
			"contain no resources if the resource group was previously created. "+
			"A resource group will be created (with name derived from the --name parameter) if an installation-resource-group-name parameter was not provided. "+
			"Note that this resource group must be provided as the installation resource group when installing the OpenShift cluster.",
	)
	createAllCmd.PersistentFlags().StringVar(
		&CreateAllOpts.StorageAccountName,
		"storage-account-name",
		"",
		"The name of the Azure storage account in which to create OIDC issuer infrastructure. "+
			"A storage account will be created with a name derived from the --name parameter if a --storage-account-name parameter was not provided. "+
			"The storage account will be created within the OIDC resource group identified by the --oidc-resource-group-name parameter. "+
			"If pre-existing, the storage account must exist within the OIDC resource group identified by the --oidc-resource-group-name parameter. "+
			"Azure storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.",
	)
	createAllCmd.PersistentFlags().StringVar(
		&CreateAllOpts.BlobContainerName,
		"blob-container-name",
		"",
		"The name of the Azure blob container in which to upload OIDC discovery documents. "+
			"A blob container will be created with a name derived from the --name parameter if a --blob-container-name parameter was not provided. "+
			"The blob container will be created within the OIDC resource group identified by the --oidc-resource-group-name parameter "+
			"and storage account identified by --storage-account-name.",
	)
	createAllCmd.PersistentFlags().StringVar(&CreateAllOpts.PublicKeyPath, "public-key-file", "", "Path to public ServiceAccount signing key")
	createAllCmd.PersistentFlags().StringVar(&CreateAllOpts.OutputDir, "output-dir", "", "Directory to place generated manifest files. Defaults to the current directory.")
	createAllCmd.PersistentFlags().StringToStringVar(&CreateAllOpts.UserTags, "user-tags", map[string]string{}, "User tags to be applied to Azure resources, multiple tags may be specified comma-separated for example: --user-tags key1=value1,key2=value2")

	return createAllCmd
}
