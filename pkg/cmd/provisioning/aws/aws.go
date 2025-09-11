package aws

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/openshift/cloud-credential-operator/pkg/aws"
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
	CreatePrivateS3Bucket  bool
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

func newAWSClient(region string) (aws.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return nil, err
	}

	awsClient, err := aws.NewClientFromConfig(cfg, "")
	if err != nil {
		return nil, err
	}

	return awsClient, nil
}
