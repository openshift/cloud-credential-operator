package gcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	iamadminpb "google.golang.org/genproto/googleapis/iam/admin/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
	"github.com/openshift/cloud-credential-operator/pkg/gcp"
	"github.com/openshift/cloud-credential-operator/pkg/gcp/actuator"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

const (
	// secretManifestsTemplate ia template of a gcp credentials secret manifest
	secretManifestsTemplate = `apiVersion: v1
data:
  service_account.json: %s
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque`

	// credentialsConfigTemplate is a template of the client credentials configuration required to impersonate IAM service
	// account
	credentialsConfigTemplate = `{
  	"type": "external_account",
  	"audience": "//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
  	"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  	"token_url": "https://sts.googleapis.com/v1/token",
  	"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
  	"credential_source": {
    	"file": "%s",
    	"format": {
      		"type": "text"
    	}
	}
}`
	// createServiceAccountCmd is a gcloud cli command to create service account
	createServiceAccountCmd = "gcloud iam service-accounts create %s --display-name=%s"
	// addPolicyBindingForProjectCmd is a gcloud cli command to add IAM policy binding for project
	addPolicyBindingForProjectCmd = "gcloud projects add-iam-policy-binding %s --member=%s --role=%s"
	// addPolicyBindingForSvcAcctCmd is a gcloud cli command to add IAM policy binding for IAM service account
	addPolicyBindingForSvcAcctCmd = "gcloud iam service-accounts add-iam-policy-binding <POPULATE_SERVICE_ACCOUNT_EMAIL> --member=%s --role=%s"
	// generateCredentialsConfigCmd is a gcloud cli command to create a credentials configuration required to impersonate
	// IAM service account
	generateCredentialsConfigCmd = "gcloud iam workload-identity-pools create-cred-config projects/%s/locations/global/workloadIdentityPools/%s/providers/%s --service-account=<POPULATE_SERVICE_ACCOUNT_EMAIL> --output-file=%s --credential-source-file=/var/run/secrets/openshift/serviceaccount/token --credential-source-type=text"
	// workloadIdentityUserRole is a role attached to service account that allows impersonation using workload identity
	workloadIdentityUserRole = "roles/iam.workloadIdentityUser"
	// createIAMServiceAccountScriptName is the name of the script to create IAM service account
	createIAMServiceAccountScriptName = "06-%d-create-%s-sa.sh"
	// addIAMPolicyBindingScriptName is the name of the script to add policy bindings to service account/project
	addIAMPolicyBindingScriptName = "07-%d-add-iam-policy-binding-for-%s-sa.sh"
	// generateCredentialsConfigScriptName is the name of the script to generate credentials config required to
	// impersonate service account
	generateCredentialsConfigScriptName = "08-%d-generate-credentials-config-for-%s-sa.sh"
)

var (
	// CreateServiceAccountsOpts captures the options that affect creation/updating
	// of the service accounts.
	CreateServiceAccountsOpts = options{
		TargetDir: "",
	}
)

func createServiceAccounts(ctx context.Context, client gcp.Client, name, workloadIdentityPool, workloadIdentityProvider, credReqDir, targetDir string, generateOnly bool) error {
	// Process directory
	credRequests, err := provisioning.GetListOfCredentialsRequests(credReqDir)
	if err != nil {
		return errors.Wrap(err, "Failed to process files containing CredentialsRequests")
	}

	// Create service accounts
	if err := processCredentialsRequests(ctx, client, credRequests, name, workloadIdentityPool, workloadIdentityProvider, targetDir, generateOnly); err != nil {
		return errors.Wrap(err, "Failed while processing each CredentialsRequest")
	}

	return nil
}

func processCredentialsRequests(ctx context.Context, client gcp.Client, credReqs []*credreqv1.CredentialsRequest, name, workloadIdentityPool, workloadIdentityProvider, targetDir string, generateOnly bool) error {
	project := client.GetProjectName()
	for i, cr := range credReqs {
		_, err := createServiceAccount(ctx, client, name, cr, i, workloadIdentityPool, workloadIdentityProvider, project, targetDir, generateOnly)
		if err != nil {
			return err
		}

	}
	return nil
}

func createServiceAccount(ctx context.Context, client gcp.Client, name string, credReq *credreqv1.CredentialsRequest, serviceAccountNum int, workloadIdentityPool, workloadIdentityProvider, project, targetDir string, generateOnly bool) (string, error) {
	// The credReq must have a non zero-length list of ServiceAccountNames
	// that can be used to restrict which k8s ServiceAccounts can use the GCP ServiceAccount.
	if len(credReq.Spec.ServiceAccountNames) == 0 {
		return "", fmt.Errorf("CredentialsRequest %s/%s must provide at least one ServiceAccount in .spec.ServiceAccountNames", credReq.Namespace, credReq.Name)
	}

	// The service account id has a max length of 30 chars
	// split it into 12-11-5 where the resuling string becomes:
	// <infraName chopped to 12 chars>-<crName chopped to 11 chars>-<random 5 chars>
	serviceAccountID, err := utils.GenerateUniqueNameWithFieldLimits(name, 12, credReq.Name, 11)
	if err != nil {
		return "", errors.Wrap(err, "Error generating service account ID")
	}
	// The service account name field has a 100 char max, so generate a name consisting of the
	// infraName chopped to 50 chars + the crName chopped to 49 chars (separated by a '-').
	serviceAccountName, err := utils.GenerateNameWithFieldLimits(name, 50, credReq.Name, 49)
	if err != nil {
		return "", errors.Wrap(err, "Error generating service account name")
	}
	serviceAccountName = serviceAccountName[:len(serviceAccountName)-6] // chop off the trailing random chars

	// Decode GCPProviderSpec
	codec, err := credreqv1.NewCodec()
	if err != nil {
		return "", errors.Wrap(err, "Failed to create credReq codec")
	}

	gcpProviderSpec := credreqv1.GCPProviderSpec{}
	if err := codec.DecodeProviderSpec(credReq.Spec.ProviderSpec, &gcpProviderSpec); err != nil {
		return "", errors.Wrap(err, "Failed to decode the provider spec")
	}

	if gcpProviderSpec.Kind != "GCPProviderSpec" {
		return "", fmt.Errorf("CredentialsRequest %s/%s is not of type GCP", credReq.Namespace, credReq.Name)
	}

	projectNum, err := getProjectNumber(ctx, client, project)
	if err != nil {
		return "", errors.Wrap(err, "Failed to get project number")
	}

	identityProviderBindingNames := getIdentityProviderBindingNames(projectNum, workloadIdentityPool, credReq.Spec.SecretRef.Namespace, credReq.Spec.ServiceAccountNames)

	var encodedCredentialsConfig string
	switch generateOnly {
	case true:
		// Create shell script to create IAM service account
		createSvcAcctScript := createShellScript([]string{
			fmt.Sprintf(createServiceAccountCmd, serviceAccountID, serviceAccountName),
		})
		createSvcAcctScriptName := fmt.Sprintf(createIAMServiceAccountScriptName, serviceAccountNum, serviceAccountName)
		createSvcAcctScriptFullPath := filepath.Join(targetDir, createSvcAcctScriptName)
		log.Printf("Saving script to create service account %s locally at %s", serviceAccountName, createSvcAcctScriptFullPath)
		if err := ioutil.WriteFile(createSvcAcctScriptFullPath, []byte(createSvcAcctScript), fileModeCcoctlDryRun); err != nil {
			return "", errors.Wrap(err, fmt.Sprintf("Failed to save script to create service account %s locally at %s", serviceAccountName, createSvcAcctScriptFullPath))
		}

		// Create shell script to add policy/role bindings for service accounts/project
		svcAcctBindingName := "serviceAccount:<POPULATE_SERVICE_ACCOUNT_EMAIL>"
		var addPolicyBindingCmds []string
		for _, role := range gcpProviderSpec.PredefinedRoles {
			addPolicyBindingCmds = append(addPolicyBindingCmds, fmt.Sprintf(addPolicyBindingForProjectCmd, project, svcAcctBindingName, role))
		}
		// commands to add bindings for workload identity user role to service account
		for _, identityPoolBindingName := range identityProviderBindingNames {
			addPolicyBindingCmds = append(addPolicyBindingCmds, fmt.Sprintf(addPolicyBindingForSvcAcctCmd, identityPoolBindingName, workloadIdentityUserRole))
		}
		addPolicyBindingScript := createShellScript(addPolicyBindingCmds)
		addPolicyBindingScriptName := fmt.Sprintf(addIAMPolicyBindingScriptName, serviceAccountNum, serviceAccountName)
		addPolicyBindingScriptFullPath := filepath.Join(targetDir, addPolicyBindingScriptName)
		log.Printf("Saving script to add policy bindings for service account %s locally at %s", serviceAccountName, addPolicyBindingScriptFullPath)
		if err := ioutil.WriteFile(addPolicyBindingScriptFullPath, []byte(addPolicyBindingScript), fileModeCcoctlDryRun); err != nil {
			return "", errors.Wrap(err, fmt.Sprintf("Failed to save script to add policy bindings for service account %s locally at %s", serviceAccountName, addPolicyBindingScriptFullPath))
		}

		// Create shell script to create client credentials configuration files that operators pods can use to impersonate
		// the IAM service account
		credentialsConfigFilePath := filepath.Join(targetDir, "credentials_configurations", fmt.Sprintf("%s_credentials_config.json", serviceAccountName))
		generateCredentialsConfigScript := createShellScript([]string{
			fmt.Sprintf(generateCredentialsConfigCmd, project, workloadIdentityPool, workloadIdentityProvider, credentialsConfigFilePath),
		})
		generateCredentialsConfigScriptName := fmt.Sprintf(generateCredentialsConfigScriptName, serviceAccountNum, serviceAccountName)
		generateCredentialsConfigScriptFullPath := filepath.Join(targetDir, generateCredentialsConfigScriptName)
		log.Printf("Saving script to generate credentials config for service account %s locally at %s", serviceAccountName, generateCredentialsConfigScriptFullPath)
		if err := ioutil.WriteFile(generateCredentialsConfigScriptFullPath, []byte(generateCredentialsConfigScript), fileModeCcoctlDryRun); err != nil {
			return "", errors.Wrap(err, fmt.Sprintf("Failed to save script to generate credentials config for service account %s locally at %s", serviceAccountName, generateCredentialsConfigScriptFullPath))
		}

		// secrets are not populated with credentials in generate mode, you need to create client credentials config
		// using 'gcloud iam workload-identity-pools create-cred-config' command, base64 encode resulting json and
		// populate service_account.json field in the secret manifests
		encodedCredentialsConfig = ""
		if err := writeCredReqSecret(credReq, targetDir, encodedCredentialsConfig, generateCredentialsConfigScriptFullPath); err != nil {
			return "", errors.Wrap(err, "Failed to save Secret for install manifests")
		}

		return "", nil

	default:
		var serviceAccount *iamadminpb.ServiceAccount
		serviceAccount, err = actuator.GetServiceAccount(client, serviceAccountID)
		if err != nil {
			if status.Code(err) == codes.NotFound {
				createdByCcoctlForSvcAcct := fmt.Sprintf("%s for service account %s", createdByCcoctl, serviceAccountName)
				serviceAccount, err = actuator.CreateServiceAccount(client, serviceAccountID, serviceAccountName, createdByCcoctlForSvcAcct, project)
				if err != nil {
					return "", errors.Wrap(err, "Failed to create IAM service account")
				}
				log.Printf("IAM Service account %s created", serviceAccount.DisplayName)
			} else {
				return "", err
			}
		} else {
			log.Printf("Existing IAM service account %s found", serviceAccount.DisplayName)
		}

		// Add member <-> role bindings for the project
		svcAcctBindingName := actuator.ServiceAccountBindingName(serviceAccount)
		err = actuator.EnsurePolicyBindingsForProject(client, gcpProviderSpec.PredefinedRoles, svcAcctBindingName)
		if err != nil {
			return "", errors.Wrap(err, fmt.Sprintf("Failed to add predefined roles for IAM service account %s", serviceAccount.DisplayName))
		}

		// Add member <-> role bindings for the IAM service account
		for _, identityProvideBindingName := range identityProviderBindingNames {
			err = actuator.EnsurePolicyBindingsForServiceAccount(client, serviceAccount, []string{workloadIdentityUserRole}, identityProvideBindingName)
			if err != nil {
				return "", errors.Wrap(err, fmt.Sprintf("Failed to add workload identity user role for IAM service account %s", serviceAccount.DisplayName))
			}
		}

		projectNumStr := fmt.Sprint(projectNum)
		credentialsConfig := fmt.Sprintf(credentialsConfigTemplate, projectNumStr, workloadIdentityPool, workloadIdentityProvider, serviceAccount.Email, provisioning.OidcTokenPath)
		encodedCredentialsConfig = base64.StdEncoding.EncodeToString([]byte(credentialsConfig))
	}

	if err := writeCredReqSecret(credReq, targetDir, encodedCredentialsConfig, ""); err != nil {
		return "", errors.Wrap(err, "Failed to save secret for install manifests")
	}
	return "", nil
}

// createShellScript creates a shell script given commands to execute
func createShellScript(commands []string) string {
	return fmt.Sprintf("#!/bin/sh\n%s", strings.Join(commands, "\n"))
}

// getProjectNumber fetches project number given project name
func getProjectNumber(ctx context.Context, client gcp.Client, projectName string) (int64, error) {
	project, err := client.GetProject(ctx, projectName)
	if err != nil {
		return 0, err
	}
	return project.ProjectNumber, nil
}

// getIdentityProviderBindingNames generates member names for binding IAM service account to workload identity provider
func getIdentityProviderBindingNames(projectNum int64, workloadIdentityPool, namespace string, serviceAccountNames []string) []string {
	var members []string
	for _, sa := range serviceAccountNames {
		members = append(members, fmt.Sprintf(`principal://iam.googleapis.com/projects/%d/locations/global/workloadIdentityPools/%s/subject/system:serviceaccount:%s:%s`,
			projectNum, workloadIdentityPool, namespace, sa))
	}
	return members
}

// writeCredReqSecret will take a credentialsRequest and a base 64 encoded credentials configuration to create
// a Secret manifest.
func writeCredReqSecret(cr *credreqv1.CredentialsRequest, targetDir, encodedCredentialsConfig, generateCredentialsConfigScriptPath string) error {
	manifestsDir := filepath.Join(targetDir, provisioning.ManifestsDirName)

	fileName := fmt.Sprintf("%s-%s-credentials.yaml", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name)
	filePath := filepath.Join(manifestsDir, fileName)

	fileData := fmt.Sprintf(secretManifestsTemplate, encodedCredentialsConfig, cr.Spec.SecretRef.Name, cr.Spec.SecretRef.Namespace)

	// encodedCredentialsConfig would be an empty string if ccoctl is run in --dry-run mode
	// so lets make sure we have an invalid Secret until the user
	// has populated the Secret manually.
	if encodedCredentialsConfig == "" {
		fileData = fileData + fmt.Sprintf("\nPOPULATE service_account.json FIELD WITH BASE 64 ENCODED CREDENTIALS CONFIG JSON GENERATED FROM SCRIPT %s", generateCredentialsConfigScriptPath)
	}

	if err := ioutil.WriteFile(filePath, []byte(fileData), 0600); err != nil {
		return errors.Wrap(err, "Failed to save Secret file")
	}

	log.Printf("Saved credentials configuration to: %s", filePath)

	return nil
}

func createServiceAccountsCmd(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	creds, err := loadCredentials(ctx)
	if err != nil {
		log.Fatalf("Failed to load credentials: %s", err)
	}

	gcpClient, err := gcp.NewClient(CreateWorkloadIdentityProviderOpts.Project, creds.JSON)
	if err != nil {
		log.Fatal(err)
	}

	err = createServiceAccounts(ctx, gcpClient, CreateServiceAccountsOpts.Name, CreateServiceAccountsOpts.WorkloadIdentityPool, CreateServiceAccountsOpts.WorkloadIdentityProvider, CreateServiceAccountsOpts.CredRequestDir, CreateServiceAccountsOpts.TargetDir, CreateServiceAccountsOpts.DryRun)
	if err != nil {
		log.Fatal(err)
	}
}

// initEnvForCreateServiceAccountsCmd will ensure the destination directory is ready to receive the generated
// files, and will create the directory if necessary.
func initEnvForCreateServiceAccountsCmd(cmd *cobra.Command, args []string) {
	if CreateServiceAccountsOpts.TargetDir == "" {
		pwd, err := os.Getwd()
		if err != nil {
			log.Fatalf("Failed to get current directory: %s", err)
		}

		CreateServiceAccountsOpts.TargetDir = pwd
	}

	fPath, err := filepath.Abs(CreateServiceAccountsOpts.TargetDir)
	if err != nil {
		log.Fatalf("Failed to resolve full path: %s", err)
	}

	// create target dir if necessary
	err = provisioning.EnsureDir(fPath)
	if err != nil {
		log.Fatalf("Failed to create target directory at %s", fPath)
	}

	// create manifests dir if necessary
	manifestsDir := filepath.Join(fPath, provisioning.ManifestsDirName)
	err = provisioning.EnsureDir(manifestsDir)
	if err != nil {
		log.Fatalf("Failed to create manifests directory at %s", manifestsDir)
	}
}

// NewCreateServiceAccountsCmd provides the "create-service-accounts" subcommand
func NewCreateServiceAccountsCmd() *cobra.Command {
	createServiceAccountsCmd := &cobra.Command{
		Use:              "create-service-accounts",
		Short:            "Create service accounts",
		Run:              createServiceAccountsCmd,
		PersistentPreRun: initEnvForCreateServiceAccountsCmd,
	}

	createServiceAccountsCmd.PersistentFlags().StringVar(&CreateServiceAccountsOpts.Name, "name", "", "User-defined name for all created google cloud resources (can be separate from the cluster's infra-id)")
	createServiceAccountsCmd.MarkPersistentFlagRequired("name")
	createServiceAccountsCmd.PersistentFlags().StringVar(&CreateServiceAccountsOpts.CredRequestDir, "credentials-requests-dir", "", "Directory containing files of CredentialsRequests to create gcp service accounts for (can be created by running 'oc adm release extract --credentials-requests --cloud=gcp' against an OpenShift release image)")
	createServiceAccountsCmd.MarkPersistentFlagRequired("credentials-requests-dir")
	createServiceAccountsCmd.PersistentFlags().StringVar(&CreateServiceAccountsOpts.WorkloadIdentityPool, "workload-identity-pool", "", "ID of workload identity pool (can be created with the 'create-workload-identity-pool' sub-command)")
	createServiceAccountsCmd.MarkPersistentFlagRequired("workload-identity-pool")
	createServiceAccountsCmd.PersistentFlags().StringVar(&CreateServiceAccountsOpts.WorkloadIdentityProvider, "workload-identity-provider", "", "ID of workload identity provider (can be created with the 'create-workload-identity-pool' sub-command)")
	createServiceAccountsCmd.MarkPersistentFlagRequired("workload-identity-provider")
	createServiceAccountsCmd.PersistentFlags().StringVar(&CreateWorkloadIdentityProviderOpts.Project, "project", "", "ID of the google cloud project")
	createServiceAccountsCmd.MarkPersistentFlagRequired("project")
	createServiceAccountsCmd.PersistentFlags().BoolVar(&CreateServiceAccountsOpts.DryRun, "dry-run", false, "Skip creating objects, and just save what would have been created into files")
	createServiceAccountsCmd.PersistentFlags().StringVar(&CreateServiceAccountsOpts.TargetDir, "output-dir", "", "Directory to place generated files (defaults to current directory)")

	return createServiceAccountsCmd
}
