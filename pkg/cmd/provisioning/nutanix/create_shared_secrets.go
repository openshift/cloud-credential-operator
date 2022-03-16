package nutanix

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
)

const (
	manifestsDirName = "manifests"

	secretManifestsTemplate = `apiVersion: v1
kind: Secret
metadata:
   name: %s
   namespace: %s
type: Opaque
data:
  NUTANIX_ENDPOINT: %s
  NUTANIX_PORT: %s
  NUTANIX_USER: %s
  NUTANIX_PASSWORD: %s`

	endpointKeyEnvVar = "NUTANIX_ENDPOINT"
	usernameKeyEnvVar = "NUTANIX_USER"
	passwordKeyEnvVar = "NUTANIX_PASSWORD"
	portKeyEnvVar     = "NUTANIX_PORT"
)

type Credentials struct {
	NutanixEndpoint string `json:"NUTANIX_ENDPOINT"`
	NutanixUser     string `json:"NUTANIX_USER"`
	NutanixPassword string `json:"NUTANIX_PASSWORD"`
	NutanixPort     string `json:"NUTANIX_PORT"`
}

var (
	// CreateSharedSecretsOpts captures the options that affect creation of the generated
	// objects.
	CreateSharedSecretsOpts = options{
		TargetDir:         "",
		EnableTechPreview: false,
	}
)

// createSharedSecretsCmd implements the "create-secrets" command for the credentials provisioning
func createSharedSecretsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:              "create-shared-secrets",
		Short:            "Create credentials objects",
		Long:             "Creating objects related to cloud credentials",
		RunE:             createSecretsCmd,
		PersistentPreRun: initEnvForCreateCmd,
	}

	cmd.PersistentFlags().StringVar(&CreateSharedSecretsOpts.CredRequestDir, "credentials-requests-dir", "", "Directory containing files of CredentialsRequests (can be created by running 'oc adm release extract --credentials-requests --cloud=nutanix' against an OpenShift release image)")
	cmd.MarkPersistentFlagRequired("credentials-requests-dir")
	cmd.PersistentFlags().StringVar(&CreateSharedSecretsOpts.TargetDir, "output-dir", "", "Directory to place generated files (defaults to current directory)")
	cmd.PersistentFlags().BoolVar(&CreateSharedSecretsOpts.EnableTechPreview, "enable-tech-preview", false, "Opt into processing CredentialsRequests marked as tech-preview")

	return cmd
}

func createSecretsCmd(cmd *cobra.Command, args []string) error {
	endpoint := os.Getenv(endpointKeyEnvVar)
	if endpoint == "" {
		return fmt.Errorf("%s environment variable not set", endpointKeyEnvVar)
	}
	port := os.Getenv(portKeyEnvVar)
	if port == "" {
		return fmt.Errorf("%s environment variable not set", portKeyEnvVar)
	}
	uname := os.Getenv(usernameKeyEnvVar)
	if uname == "" {
		return fmt.Errorf("%s environment variable not set", usernameKeyEnvVar)
	}
	pass := os.Getenv(passwordKeyEnvVar)
	if pass == "" {
		return fmt.Errorf("%s environment variable not set", passwordKeyEnvVar)
	}

	err := createSecrets(CreateSharedSecretsOpts.CredRequestDir, CreateSharedSecretsOpts.TargetDir, endpoint, port, uname, pass, CreateSharedSecretsOpts.EnableTechPreview)
	if err != nil {
		return errors.Wrap(err, "Failed to create credentials secrets")
	}
	return nil
}

func createSecrets(credReqDir, targetDir, endpoint, port, username, password string, enableTechPreview bool) error {
	credRequests, err := provisioning.GetListOfCredentialsRequests(credReqDir, enableTechPreview)
	if err != nil {
		return errors.Wrap(err, "Failed to process files containing CredentialsRequests")
	}

	for _, cr := range credRequests {
		if err := processCredReq(cr, targetDir, endpoint, port, username, password); err != nil {
			return errors.Wrap(err, "Failed to process CredentialsReqeust")
		}
	}
	return nil
}

func writeCredReqSecret(cr *credreqv1.CredentialsRequest, targetDir, endpoint, port, username, password string) error {
	manifestsDir := filepath.Join(targetDir, manifestsDirName)

	fileName := fmt.Sprintf("%s-%s-credentials.yaml", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name)
	filePath := filepath.Join(manifestsDir, fileName)

	b64Endpoint := base64.StdEncoding.EncodeToString([]byte(endpoint))
	b64Port := base64.StdEncoding.EncodeToString([]byte(port))
	b64Username := base64.StdEncoding.EncodeToString([]byte(username))
	b64Password := base64.StdEncoding.EncodeToString([]byte(password))

	fileData := fmt.Sprintf(secretManifestsTemplate, cr.Spec.SecretRef.Name, cr.Spec.SecretRef.Namespace, b64Endpoint, b64Port, b64Username, b64Password)

	if err := ioutil.WriteFile(filePath, []byte(fileData), 0600); err != nil {
		return errors.Wrap(err, "Failed to save Secret file")
	}

	log.Printf("Saved credentials configuration to: %s", filePath)

	return nil
}

func processCredReq(cr *credreqv1.CredentialsRequest, targetDir, endpoint, port, username, password string) error {
	// Decode NutanixProviderSpec
	codec, err := credreqv1.NewCodec()
	if err != nil {
		return errors.Wrap(err, "Failed to create credReq codec")
	}

	nutanixProviderSpec := credreqv1.NutanixProviderSpec{}
	if err := codec.DecodeProviderSpec(cr.Spec.ProviderSpec, &nutanixProviderSpec); err != nil {
		return errors.Wrap(err, "Failed to decode the provider spec")
	}

	if nutanixProviderSpec.Kind != "NutanixProviderSpec" {
		return fmt.Errorf("CredentialsRequest %s/%s is not of type Nutanix", cr.Namespace, cr.Name)
	}

	return writeCredReqSecret(cr, targetDir, endpoint, port, username, password)
}

// initEnvForCreateCmd will ensure the destination directory is ready to
// receive the generated files, and will create the directory if necessary.
func initEnvForCreateCmd(cmd *cobra.Command, args []string) {
	if CreateSharedSecretsOpts.TargetDir == "" {
		pwd, err := os.Getwd()
		if err != nil {
			log.Fatalf("Failed to get current directory: %s", err)
		}

		CreateSharedSecretsOpts.TargetDir = pwd
	}

	fPath, err := filepath.Abs(CreateSharedSecretsOpts.TargetDir)
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
}
