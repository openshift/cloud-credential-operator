package ibmcloud

import (
	"github.com/spf13/cobra"
)

type options struct {
	TargetDir      string
	CredRequestDir string
}

// NewIBMCloudCmd implements the "ibmcloud" subcommand for the credentials provisioning
func NewIBMCloudCmd() *cobra.Command {
	createCmd := &cobra.Command{
		Use:   "ibmcloud",
		Short: "Manage credentials objects for IBM Cloud",
		Long:  "Creating/deleting cloud credentials objects for IBM Cloud",
	}

	createCmd.AddCommand(NewCreateSharedSecretsCmd())

	return createCmd
}
