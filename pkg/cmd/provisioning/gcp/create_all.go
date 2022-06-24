package gcp

import (
	"context"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
	"github.com/openshift/cloud-credential-operator/pkg/gcp"
)

var (
	// CreateAllOpts captures the options that affect creation/updating
	// of the generated objects.
	CreateAllOpts = options{
		TargetDir: "",
	}
)

func createAllCmd(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	creds, err := loadCredentials(ctx)
	if err != nil {
		log.Fatalf("Failed to load credentials: %s", err)
	}

	var gcpClient gcp.Client

	if len(creds.JSON) != 0 {
		gcpClient, err = gcp.NewClient(CreateAllOpts.Project, creds.JSON)
		if err != nil {
			log.Fatalf("Failed to initiate GCP client: %s", err)
		}

	} else {
		gcpClient, err = gcp.NewClient_GCE(CreateAllOpts.Project, creds)
		if err != nil {
			log.Fatalf("Failed to initiate GCP client: %s", err)
		}
	}
	publicKeyPath := CreateAllOpts.PublicKeyPath
	if publicKeyPath == "" {
		publicKeyPath = path.Join(CreateAllOpts.TargetDir, provisioning.PublicKeyFile)
	}

	if err := provisioning.CreateKeys(CreateAllOpts.TargetDir); err != nil {
		log.Fatalf("Failed to create public/private key pair: %s", err)
	}

	if err = createWorkloadIdentityPool(ctx, gcpClient, CreateAllOpts.Name, CreateAllOpts.Project, CreateAllOpts.TargetDir, false); err != nil {
		log.Fatalf("Failed to create workload identity pool: %s", err)
	}

	if err = createWorkloadIdentityProvider(ctx, gcpClient, CreateAllOpts.Name, CreateAllOpts.Region, CreateAllOpts.Project, CreateAllOpts.Name, publicKeyPath, CreateAllOpts.TargetDir, false); err != nil {
		log.Fatalf("Failed to create workload identity provider: %s", err)
	}

	if err = createServiceAccounts(ctx, gcpClient, CreateAllOpts.Name, CreateAllOpts.Name, CreateAllOpts.Name, CreateAllOpts.CredRequestDir,
		CreateAllOpts.TargetDir, CreateAllOpts.EnableTechPreview, false); err != nil {
		log.Fatalf("Failed to create IAM service accounts: %s", err)
	}
}

// validationForCreateAllCmd will validate the arguments to the command, ensure the destination directory
// is ready to receive the generated files, and will create the directory if necessary.
func validationForCreateAllCmd(cmd *cobra.Command, args []string) {
	if len(CreateWorkloadIdentityPoolOpts.Name) > 32 {
		log.Fatalf("Name can be at most 32 characters long")
	}

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
	manifestsDir := filepath.Join(fPath, provisioning.ManifestsDirName)
	err = provisioning.EnsureDir(manifestsDir)
	if err != nil {
		log.Fatalf("failed to create manifests directory at %s", manifestsDir)
	}

	// create tls dir if necessary
	tlsDir := filepath.Join(fPath, provisioning.TLSDirName)
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
		PersistentPreRun: validationForCreateAllCmd,
	}

	createAllCmd.PersistentFlags().StringVar(&CreateAllOpts.Name, "name", "", "User-defined name for all created Google cloud resources (can be separate from the cluster's infra-id)")
	createAllCmd.MarkPersistentFlagRequired("name")
	createAllCmd.PersistentFlags().StringVar(&CreateAllOpts.Region, "region", "us", "Google cloud region where the Google Storage Bucket holding the OpenID Connect configuration will be created")
	createAllCmd.PersistentFlags().StringVar(&CreateAllOpts.Project, "project", "", "ID of the Google cloud project")
	createAllCmd.MarkPersistentFlagRequired("project")
	createAllCmd.PersistentFlags().StringVar(&CreateAllOpts.CredRequestDir, "credentials-requests-dir", "", "Directory containing files of CredentialsRequests to create gcp service accounts for (can be created by running 'oc adm release extract --credentials-requests --cloud=gcp' against an OpenShift release image)")
	createAllCmd.MarkPersistentFlagRequired("credentials-requests-dir")
	createAllCmd.PersistentFlags().StringVar(&CreateAllOpts.TargetDir, "output-dir", "", "Directory to place generated files (defaults to current directory)")
	createAllCmd.PersistentFlags().BoolVar(&CreateAllOpts.EnableTechPreview, "enable-tech-preview", false, "Opt into processing CredentialsRequests marked as tech-preview")

	return createAllCmd
}
