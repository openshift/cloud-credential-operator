package ibmcloud

import (
	"github.com/spf13/cobra"
)

type options struct {
	TargetDir         string
	Name              string
	CredRequestDir    string
	ResourceGroupName string
}

// NewIBMCloudCmd implements the "ibmcloud" subcommand for the credentials provisioning
func NewIBMCloudCmd() *cobra.Command {
	createCmd := &cobra.Command{
		Use:   "ibmcloud",
		Short: "Manage credentials objects for IBM Cloud",
		Long:  "Creating/deleting cloud credentials objects for IBM Cloud",
	}

	createCmd.AddCommand(NewCreateServiceIDCmd())

	return createCmd
}
