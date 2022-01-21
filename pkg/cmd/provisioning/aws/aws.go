package aws

import (
	"github.com/spf13/cobra"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
)

type options struct {
	TargetDir              string
	PublicKeyPath          string
	Region                 string
	Name                   string
	CredRequestDir         string
	IdentityProviderARN    string
	PermissionsBoundaryARN string
	DryRun                 bool
	EnableTechPreview      bool
}

// NewAWSCmd implements the "aws" subcommand for the credentials provisioning
func NewAWSCmd() *cobra.Command {
	createCmd := &cobra.Command{
		Use:   "aws",
		Short: "Manage credentials objects for AWS cloud",
		Long:  "Creating/updating/deleting cloud credentials objects for AWS cloud",
	}

	createCmd.AddCommand(provisioning.NewCreateKeyPairCmd())
	createCmd.AddCommand(NewCreateIdentityProviderCmd())
	createCmd.AddCommand(NewCreateIAMRolesCmd())
	createCmd.AddCommand(NewCreateAllCmd())
	createCmd.AddCommand(NewDeleteCmd())

	return createCmd
}

func awsSession(region string) (*session.Session, error) {
	cfg := awssdk.Config{
		Region: awssdk.String(region),
	}

	return session.NewSessionWithOptions(session.Options{
		Config:            cfg,
		SharedConfigState: session.SharedConfigEnable,
	})
}
