package alibabacloud

import (
	"github.com/spf13/cobra"
)

type options struct {
	TargetDir         string
	Name              string
	Region            string
	CredRequestDir    string
	EnableTechPreview bool
}

// NewAliababaCloudCmd implements the "alibabacloud" subcommand for the credentials provisioning
func NewAliababaCloudCmd() *cobra.Command {
	createCmd := &cobra.Command{
		Use:   "alibabacloud",
		Short: "Manage credentials objects for alibaba cloud",
		Long:  "Creating/deleting cloud credentials objects for alibaba cloud",
	}

	createCmd.AddCommand(NewCreateRAMUsersCmd())
	createCmd.AddCommand(NewDeleteRAMUsersCmd())

	return createCmd
}
