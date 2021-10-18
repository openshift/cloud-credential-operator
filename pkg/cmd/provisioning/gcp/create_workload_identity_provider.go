package gcp

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	iamCloud "cloud.google.com/go/iam"
	"cloud.google.com/go/storage"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	iampb "google.golang.org/genproto/googleapis/iam/v1"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
	"github.com/openshift/cloud-credential-operator/pkg/gcp"
)

var (
	// CreateWorkloadIdentityProviderOpts captures the options that affect creation of the workload identity provider
	CreateWorkloadIdentityProviderOpts = options{
		Name:                 "",
		Region:               "",
		Project:              "",
		PublicKeyPath:        "",
		WorkloadIdentityPool: "",
	}
)

const (
	// createOidcBucketScriptName is the name of the script used to create OIDC bucket in google cloud
	createOidcBucketScriptName = "02-create-oidc-bucket.sh"
	// createOidcBucketCmd is a gsutil cli command to create oidc bucket
	createOidcBucketCmd = "gsutil mb -b on -l %s -p %s gs://%s"
	// makeBucketPubliclyReadableCmd is a gsutil cli command to make all objects in a bucket readable to everyone on the
	// public internet
	makeBucketPubliclyReadableCmd = "gsutil iam ch allUsers:objectViewer gs://%s"
	// Identity Provider files
	gcpOidcConfigurationFilename = "03-openid-configuration"
	gcpOidcKeysFilename          = "04-keys.json"
	// createIdentityProviderScriptName is the name of the script used to create workload identity provider in google cloud
	createIdentityProviderScriptName = "05-create-workload-identity-provider.sh"
	// createIdentityProviderCmd is gcloud cli command to create workload identity provider
	createIdentityProviderCmd = "gcloud iam workload-identity-pools providers create-oidc %s --location=global --workload-identity-pool=%s --display-name=%s --description=\"%s\" --issuer-uri=%s --allowed-audiences=%s --attribute-mapping=\"google.subject=assertion.sub\""
	// openShiftAudience is the only acceptable value for the `aud` field (audience) in the OIDC token shared by
	// OpenShift components
	openShiftAudience = "openshift"
)

func createWorkloadIdentityProviderCmd(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	creds, err := loadCredentials(ctx)
	if err != nil {
		log.Fatalf("Failed to load credentials: %s", err)
	}

	gcpClient, err := gcp.NewClient(CreateWorkloadIdentityProviderOpts.Project, creds.JSON)
	if err != nil {
		log.Fatal(err)
	}

	publicKeyPath := CreateWorkloadIdentityProviderOpts.PublicKeyPath
	if publicKeyPath == "" {
		publicKeyPath = filepath.Join(CreateWorkloadIdentityProviderOpts.TargetDir, provisioning.PublicKeyFile)
	}

	err = createWorkloadIdentityProvider(ctx, gcpClient, CreateWorkloadIdentityProviderOpts.Name, CreateWorkloadIdentityProviderOpts.Region, CreateWorkloadIdentityProviderOpts.Project, CreateWorkloadIdentityProviderOpts.WorkloadIdentityPool, publicKeyPath, CreateWorkloadIdentityProviderOpts.TargetDir, CreateWorkloadIdentityProviderOpts.DryRun)
	if err != nil {
		log.Fatal(err)
	}
}

func createWorkloadIdentityProvider(ctx context.Context, client gcp.Client, name, region, project, workloadIdentityPool string, publicKeyPath, targetDir string, generateOnly bool) error {
	// Create a storage bucket
	bucketName := fmt.Sprintf("%s-oidc", name)
	if err := createOIDCBucket(ctx, client, bucketName, region, project, targetDir, generateOnly); err != nil {
		return err
	}
	issuerURL := fmt.Sprintf("https://storage.googleapis.com/%s", bucketName)

	// Create the OIDC config file
	if err := createOIDCConfiguration(ctx, client, bucketName, issuerURL, targetDir, generateOnly); err != nil {
		return err
	}

	// Create the OIDC key list
	if err := createJSONWebKeySet(ctx, client, publicKeyPath, bucketName, targetDir, generateOnly); err != nil {
		return err
	}

	// Create the workload identity provider
	err := createIdentityProvider(ctx, client, name, project, issuerURL, workloadIdentityPool, targetDir, generateOnly)
	if err != nil {
		return err
	}

	// Create the installer manifest file
	if err := provisioning.CreateClusterAuthentication(issuerURL, targetDir); err != nil {
		return err
	}

	return nil
}

func createOIDCBucket(ctx context.Context, client gcp.Client, bucketName, region, project, targetDir string, generateOnly bool) error {
	if generateOnly {
		createOidcBucketScript := provisioning.CreateShellScript([]string{createOidcBucketCmd, makeBucketPubliclyReadableCmd})
		createOidcBucketScriptFilepath := filepath.Join(targetDir, createOidcBucketScriptName)
		script := fmt.Sprintf(createOidcBucketScript, region, project, bucketName, bucketName)
		log.Printf("Saving shell script to create OIDC bucket locally at %s", createOidcBucketScriptFilepath)
		if err := ioutil.WriteFile(createOidcBucketScriptFilepath, []byte(script), fileModeCcoctlDryRun); err != nil {
			return errors.Wrap(err, fmt.Sprintf("Failed to save shell script to create OIDC bucket locally at %s", createOidcBucketScriptFilepath))
		}
	} else {
		bucketAttrs := &storage.BucketAttrs{
			Name:                     bucketName,
			Location:                 region,
			UniformBucketLevelAccess: storage.UniformBucketLevelAccess{Enabled: true},
		}

		err := client.CreateBucket(ctx, bucketName, project, bucketAttrs)
		if err != nil {
			if gerr, ok := err.(*googleapi.Error); ok {
				if gerr.Code == 409 && strings.Contains(gerr.Message, "You already own this bucket") {
					log.Printf("Bucket %s already exists and is owned by the user", bucketName)
				} else {
					return errors.Wrap(gerr, "failed to create a bucket to store OpenID Connect configuration")
				}
			} else {
				return errors.Wrap(err, "failed to create a bucket to store OpenID Connect configuration")
			}
		} else {
			log.Print("Bucket ", bucketName, " created")
		}

		policy, err := client.GetBucketPolicy(ctx, bucketName)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("Failed to fetch IAM policy for bucket %s", bucketName))
		}
		role := "roles/storage.objectViewer"
		policy.Bindings = append(policy.Bindings, &iampb.Binding{
			Role:    role,
			Members: []string{iamCloud.AllUsers},
		})
		if err := client.SetBucketPolicy(ctx, bucketName, policy); err != nil {
			return fmt.Errorf("Bucket(%q).IAM().SetPolicy: %v", bucketName, err)
		}
		log.Printf("Bucket %s is set to be publicly readable", bucketName)
	}

	return nil
}

func createOIDCConfiguration(ctx context.Context, client gcp.Client, bucketName, issuerURL, targetDir string, generateOnly bool) error {
	discoveryDocumentJSON := fmt.Sprintf(provisioning.DiscoveryDocumentTemplate, issuerURL, issuerURL, provisioning.KeysURI)
	if generateOnly {
		discoveryDocumentFilepath := filepath.Join(targetDir, gcpOidcConfigurationFilename)
		log.Printf("Saving discovery document locally at %s", discoveryDocumentFilepath)
		if err := ioutil.WriteFile(discoveryDocumentFilepath, []byte(discoveryDocumentJSON), fileModeCcoctlDryRun); err != nil {
			return errors.Wrap(err, fmt.Sprintf("Failed to save discovery document locally at %s", discoveryDocumentFilepath))
		}
	} else {
		err := client.PutObject(ctx, bucketName, provisioning.DiscoveryDocumentURI, []byte(discoveryDocumentJSON))
		if err != nil {
			return errors.Wrapf(err, "failed to upload discovery document in the bucket %s", bucketName)
		}
		log.Printf("OpenID Connect discovery document in the S3 bucket %s at %s updated", bucketName, provisioning.DiscoveryDocumentURI)
	}
	return nil
}

func createJSONWebKeySet(ctx context.Context, client gcp.Client, publicKeyFilepath, bucketName, targetDir string, generateOnly bool) error {
	jwks, err := provisioning.BuildJsonWebKeySet(publicKeyFilepath)
	if err != nil {
		return errors.Wrap(err, "failed to build JSON web key set from the public key")
	}

	if generateOnly {
		JWKSFilePath := filepath.Join(targetDir, gcpOidcKeysFilename)
		log.Printf("Saving JSON web key set (JWKS) locally at %s", JWKSFilePath)
		if err := ioutil.WriteFile(JWKSFilePath, jwks, fileModeCcoctlDryRun); err != nil {
			return errors.Wrap(err, fmt.Sprintf("Failed to save JSON web key set (JWKS) locally at %s", JWKSFilePath))
		}
	} else {
		err = client.PutObject(ctx, bucketName, provisioning.KeysURI, jwks)
		if err != nil {
			return errors.Wrapf(err, "failed to upload JSON web key set (JWKS) in the S3 bucket %s", bucketName)
		}
		log.Printf("JSON web key set (JWKS) in the S3 bucket %s at %s updated", bucketName, provisioning.KeysURI)
	}
	return nil
}

func createIdentityProvider(ctx context.Context, client gcp.Client, name, project, issuerURL, workloadIdentityPool, targetDir string, generateOnly bool) error {
	if generateOnly {
		createIdentityProviderScript := provisioning.CreateShellScript([]string{createIdentityProviderCmd})
		createIdentityProviderScriptFilepath := filepath.Join(targetDir, createIdentityProviderScriptName)
		script := fmt.Sprintf(createIdentityProviderScript, name, workloadIdentityPool, name, createdByCcoctl, issuerURL, openShiftAudience)
		log.Printf("Saving shell script to create workload identity provider locally at %s", createIdentityProviderScriptFilepath)
		if err := ioutil.WriteFile(createIdentityProviderScriptFilepath, []byte(script), fileModeCcoctlDryRun); err != nil {
			return errors.Wrap(err, fmt.Sprintf("Failed to save shell script to create workload identity provider locally at %s", createIdentityProviderScriptFilepath))
		}
	} else {
		provider := &iam.WorkloadIdentityPoolProvider{
			Name:        name,
			DisplayName: name,
			Description: createdByCcoctl,
			State:       "ACTIVE",
			Disabled:    false,
			Oidc: &iam.Oidc{
				AllowedAudiences: []string{openShiftAudience},
				IssuerUri:        issuerURL,
			},
			AttributeMapping: map[string]string{
				// when token exchange happens, sub from oidc token shared by operator pod will be mapped to google.subject
				// field of google auth token. The field is used to allow fine-grained access to gcp service accounts.
				// The format is `system:serviceaccount:<service_account_namespace>:<service_account_name>`
				"google.subject": "assertion.sub",
			},
		}

		_, err := client.CreateWorkloadIdentityProvider(ctx, fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s", project, workloadIdentityPool), name, provider)
		if err != nil {
			return errors.Wrapf(err, "failed to create workload identity provider %s", name)
		}
		log.Printf("workload identity provider created with name %s", name)
	}
	return nil
}

// validationForCreateWorkloadIdentityProviderCmd will validate the arguments to the command, ensure the destination directory
// is ready to receive the generated files, and will create the directory if necessary.
func validationForCreateWorkloadIdentityProviderCmd(cmd *cobra.Command, args []string) {
	if len(CreateWorkloadIdentityPoolOpts.Name) > 32 {
		log.Fatalf("Name can be at most 32 characters long")
	}

	if CreateWorkloadIdentityProviderOpts.TargetDir == "" {
		pwd, err := os.Getwd()
		if err != nil {
			log.Fatalf("Failed to get current directory: %s", err)
		}

		CreateWorkloadIdentityProviderOpts.TargetDir = pwd
	}

	fPath, err := filepath.Abs(CreateWorkloadIdentityProviderOpts.TargetDir)
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
}

// NewCreateWorkloadIdentityProviderCmd provides the "create-workload-identity-provider" subcommand
func NewCreateWorkloadIdentityProviderCmd() *cobra.Command {
	createWorkloadIdentityProviderCmd := &cobra.Command{
		Use:              "create-workload-identity-provider",
		Short:            "Create workload identity provider",
		Run:              createWorkloadIdentityProviderCmd,
		PersistentPreRun: validationForCreateWorkloadIdentityProviderCmd,
	}

	createWorkloadIdentityProviderCmd.PersistentFlags().StringVar(&CreateWorkloadIdentityProviderOpts.Name, "name", "", "User-defined name for all created Google cloud resources (can be separate from the cluster's infra-id)")
	createWorkloadIdentityProviderCmd.MarkPersistentFlagRequired("name")
	createWorkloadIdentityProviderCmd.PersistentFlags().StringVar(&CreateWorkloadIdentityProviderOpts.Region, "region", "us", "Google cloud region where the Google Storage Bucket holding the OpenID Connect configuration will be created")
	createWorkloadIdentityProviderCmd.PersistentFlags().StringVar(&CreateWorkloadIdentityProviderOpts.Project, "project", "", "ID of the Google cloud project")
	createWorkloadIdentityProviderCmd.MarkPersistentFlagRequired("project")
	createWorkloadIdentityProviderCmd.PersistentFlags().StringVar(&CreateWorkloadIdentityProviderOpts.WorkloadIdentityPool, "workload-identity-pool", "", "Pool to create this provider in")
	createWorkloadIdentityProviderCmd.MarkPersistentFlagRequired("workload-identity-pool")
	createWorkloadIdentityProviderCmd.PersistentFlags().StringVar(&CreateWorkloadIdentityProviderOpts.PublicKeyPath, "public-key-file", "", "Path to public ServiceAccount signing key")
	createWorkloadIdentityProviderCmd.PersistentFlags().BoolVar(&CreateWorkloadIdentityProviderOpts.DryRun, "dry-run", false, "Skip creating objects, and just save what would have been created into files")
	createWorkloadIdentityProviderCmd.PersistentFlags().StringVar(&CreateWorkloadIdentityProviderOpts.TargetDir, "output-dir", "", "Directory to place generated files (defaults to current directory)")

	return createWorkloadIdentityProviderCmd
}
