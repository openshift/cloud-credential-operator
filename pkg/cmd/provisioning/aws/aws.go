package aws

import (
	"github.com/spf13/cobra"
)

type options struct {
	TargetDir           string
	PublicKeyPath       string
	Region              string
	Name                string
	CredRequestDir      string
	IdentityProviderARN string
	DryRun              bool
}

// NewAWSCmd implements the "aws" subcommand for the credentials provisioning
func NewAWSCmd() *cobra.Command {
	createCmd := &cobra.Command{
		Use:   "aws",
		Short: "Manage credentials objects for AWS cloud",
		Long:  "Creating/updating/deleting cloud credentials objects for AWS cloud",
	}

	createCmd.AddCommand(NewCreateKeyPairCmd())
	createCmd.AddCommand(NewCreateIdentityProviderCmd())
	createCmd.AddCommand(NewCreateIAMRolesCmd())
	createCmd.AddCommand(NewCreateAllCmd())
	createCmd.AddCommand(NewDeleteCmd())

	return createCmd
}
