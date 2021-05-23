package aws

import (
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/spf13/cobra"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"

	"github.com/openshift/cloud-credential-operator/pkg/aws"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
)

var (
	// CreateAllOpts captures the options that affect creation/updating
	// of the generated objects.
	CreateAllOpts = options{
		TargetDir: "",
	}
)

func createAllCmd(cmd *cobra.Command, args []string) {
	cfg := &awssdk.Config{
		Region: awssdk.String(CreateAllOpts.Region),
	}

	s, err := session.NewSession(cfg)
	if err != nil {
		log.Fatal(err)
	}

	awsClient := aws.NewClientFromSession(s)

	publicKeyPath := CreateAllOpts.PublicKeyPath
	if publicKeyPath == "" {
		publicKeyPath = path.Join(CreateAllOpts.TargetDir, publicKeyFile)
	}

	if err := createKeys(CreateAllOpts.TargetDir); err != nil {
		log.Fatalf("Failed to create public/private key pair: %s", err)
	}

	identityProviderARN, err := createIdentityProvider(awsClient, CreateAllOpts.Name, CreateAllOpts.Region, publicKeyPath, CreateAllOpts.TargetDir, false)
	if err != nil {
		log.Fatalf("Failed to create Identity provider: %s", err)
	}

	err = createIAMRoles(awsClient, identityProviderARN, CreateAllOpts.PermissionsBoundaryARN, CreateAllOpts.Name, CreateAllOpts.CredRequestDir, CreateAllOpts.TargetDir, false)
	if err != nil {
		log.Fatalf("Failed to process IAM Roles: %s", err)
	}
}

// initEnvForCreateAllCmd will ensure the destination directory is ready to receive the generated
// files, and will create the directory if necessary.
func initEnvForCreateAllCmd(cmd *cobra.Command, args []string) {
	if CreateAllOpts.TargetDir == "" {
		pwd, err := os.Getwd()
		if err != nil {
			log.Fatalf("Failed to get current directory: %s", err)
		}

		CreateAllOpts.TargetDir = pwd
	}

	fPath, err := filepath.Abs(CreateAllOpts.TargetDir)
	if err != nil {
		log.Fatalf("Failed to resolve full path: %s", err)
	}

	// create target dir if necessary
	err = provisioning.EnsureDir(fPath)
	if err != nil {
		log.Fatalf("failed to create target directory at %s", fPath)
	}

	// create manifests dir if necessary
	manifestsDir := filepath.Join(fPath, manifestsDirName)
	err = provisioning.EnsureDir(manifestsDir)
	if err != nil {
		log.Fatalf("failed to create manifests directory at %s", manifestsDir)
	}

	// create tls dir if necessary
	tlsDir := filepath.Join(fPath, tlsDirName)
	err = provisioning.EnsureDir(tlsDir)
	if err != nil {
		log.Fatalf("failed to create tls directory at %s", tlsDir)
	}
}

// NewCreateAllCmd provides the "create-all" subcommand
func NewCreateAllCmd() *cobra.Command {
	createAllCmd := &cobra.Command{
		Use:              "create-all",
		Short:            "Create all the required credentials objects",
		Run:              createAllCmd,
		PersistentPreRun: initEnvForCreateAllCmd,
	}

	createAllCmd.PersistentFlags().StringVar(&CreateAllOpts.Name, "name", "", "User-defined name for all created AWS resources (can be separate from the cluster's infra-id)")
	createAllCmd.MarkPersistentFlagRequired("name")
	createAllCmd.PersistentFlags().StringVar(&CreateAllOpts.Region, "region", "", "AWS region where the S3 OpenID Connect endpoint will be created")
	createAllCmd.MarkPersistentFlagRequired("region")
	createAllCmd.PersistentFlags().StringVar(&CreateAllOpts.PermissionsBoundaryARN, "permissions-boundary-arn", "", "ARN of IAM policy to use as the permissions boundary for created roles")
	createAllCmd.PersistentFlags().StringVar(&CreateAllOpts.CredRequestDir, "credentials-requests-dir", "", "Directory containing files of CredentialsRequests to create IAM Roles for (can be created by running 'oc adm release extract --credentials-requests --cloud=aws' against an OpenShift release image)")
	createAllCmd.MarkPersistentFlagRequired("credentials-requests-dir")
	createAllCmd.PersistentFlags().StringVar(&CreateAllOpts.TargetDir, "output-dir", "", "Directory to place generated files (defaults to current directory)")

	return createAllCmd
}
