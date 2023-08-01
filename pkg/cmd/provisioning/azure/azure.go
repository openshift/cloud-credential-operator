package azure

import (
	"github.com/spf13/cobra"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
)

type azureOptions struct {
	CredRequestDir     string
	IssuerURL          string
	Name               string
	PublicKeyPath      string
	Region             string
	StorageAccountName string
	BlobContainerName  string
	SubscriptionID     string
	TenantID           string
	OutputDir          string
	DryRun             bool
	EnableTechPreview  bool

	// UserTags is the map of user provided tags to be applied to Azure resources created by ccoctl.
	// For example:
	// userTags := map[string]string{"openshift.io_cloud-credential-operator": "owned"}
	UserTags map[string]string

	// InstallationResourceGroupName is the name of the Azure resource group which
	// will be used for installer provisioned infrastructure (IPI). This Azure resource
	// group will be created by ccoctl such that any permissions granted to managed identities created by ccoctl may
	// be scoped within the Azure resource group identified by InstallationResourceGroupName.
	InstallationResourceGroupName string

	// OIDCResourceGroupName is the name of the Azure resource group which will contain OIDC
	// and user-assigned managed identity resources. The resource group provided to the OpenShift
	// installer for installer provisioned infrastructure (IPI) may not contain any resources so the
	// resource group identified by OIDCResourceGroupName will be their home.
	// Reference: https://github.com/openshift/installer/blob/85138dd3c4e9c27c4bd4fbe3588af7712404347b/pkg/asset/installconfig/azure/validation.go#L558-L570
	OIDCResourceGroupName string

	// DNSZoneResourceGroupName is the name of the Azure resource group in which the OpenShift
	// cluster's base domain DNS zone exists. The permissions granted to the managed identity created
	// for the ingress operator will be scoped to the DNSZoneResourceGroupName.
	DNSZoneResourceGroupName string

	// DeleteResourceGroup is a bool indicating that the OIDC resource group should be deleted when
	// ccoctl azure delete is invoked with the --delete-oidc-resource-group flag
	DeleteOIDCResourceGroup bool
}

// NewAzureCmd implements the "azure" subcommand for credentials provisioning
func NewAzureCmd() *cobra.Command {
	createCmd := &cobra.Command{
		Use:   "azure",
		Short: "Manage credentials objects for Azure",
		Long:  "Creating/updating/deleting cloud credentials objects for Azure",
	}

	createCmd.AddCommand(provisioning.NewCreateKeyPairCmd())
	createCmd.AddCommand(NewCreateOIDCIssuerCmd())
	createCmd.AddCommand(NewCreateManagedIdentitiesCmd())
	createCmd.AddCommand(NewCreateAllCmd())
	createCmd.AddCommand(NewDeleteCmd())

	return createCmd
}
