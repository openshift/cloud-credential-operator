package nutanix

import (
	"github.com/spf13/cobra"
)

type options struct {
	TargetDir                 string
	CredRequestDir            string
	CredentialsSourceFilePath string
	EnableTechPreview         bool
}

// NewNutanixCmd implements the "nutanix" subcommand for the credentials provisioning
func NewNutanixCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nutanix",
		Short: "Manage credentials objects for Nutanix",
		Long:  "Creating cloud credentials objects for Nutanix",
	}

	cmd.AddCommand(createSharedSecretsCmd())

	return cmd
}
