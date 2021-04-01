package provisioning

import (
	"fmt"
	"log"
	"path"

	"github.com/spf13/cobra"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"

	"github.com/openshift/cloud-credential-operator/pkg/aws"
)

func allCmd(cmd *cobra.Command, args []string) {
	cfg := &awssdk.Config{
		Region: awssdk.String(CreateOpts.Region),
	}

	s, err := session.NewSession(cfg)
	if err != nil {
		log.Fatal(err)
	}

	awsClient := aws.NewClientFromSession(s)

	publicKeyPath := CreateOpts.PublicKeyPath
	if publicKeyPath == "" {
		publicKeyPath = path.Join(CreateOpts.TargetDir, publicKeyFile)
	}

	if err := createKeys(CreateOpts.TargetDir); err != nil {
		log.Fatalf("Failed to create public/private key pair: %s", err)
	}

	identityProviderARN, err := createIdentityProvider(awsClient, CreateOpts.NamePrefix, CreateOpts.Region, publicKeyPath, CreateOpts.TargetDir, false)
	fmt.Printf("ARN: %+v\n", identityProviderARN)
	if err != nil {
		log.Fatalf("Failed to create Identity provider: %s", err)
	}

	err = createIAMRoles(awsClient, identityProviderARN, CreateOpts.NamePrefix, CreateOpts.CredRequestDir, CreateOpts.TargetDir, false)
	if err != nil {
		log.Fatalf("Failed to process IAM Roles: %s", err)
	}
}

// NewAllSetup provides the "create all" subcommand
func NewAllSetup() *cobra.Command {
	allSetupCmd := &cobra.Command{
		Use: "all",
		Run: allCmd,
	}

	allSetupCmd.PersistentFlags().StringVar(&CreateOpts.NamePrefix, "name-prefix", "", "User-defined name prefix for all created AWS resources (can be separate from the cluster's infra-id)")
	allSetupCmd.MarkPersistentFlagRequired("name-prefix")
	allSetupCmd.PersistentFlags().StringVar(&CreateOpts.Region, "region", "", "AWS region where the S3 OpenID Connect endpoint will be created")
	allSetupCmd.MarkPersistentFlagRequired("region")
	allSetupCmd.PersistentFlags().StringVar(&CreateOpts.CredRequestDir, "credentials-requests-dir", "", "Directory containing files of CredentialsRequests to create IAM Roles for (can be created by running 'oc adm release extract --credentials-requests --cloud=aws' against an OpenShift release image)")
	allSetupCmd.MarkPersistentFlagRequired("credentials-requests-dir")

	return allSetupCmd
}
