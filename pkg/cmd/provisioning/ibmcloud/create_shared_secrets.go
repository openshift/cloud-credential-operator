package ibmcloud

import (
	b64 "encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/util/yaml"

	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
)

const (
	secretManifestsTemplate = `apiVersion: v1
data:
  ibmcloud_api_key: %s
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque`

	manifestsDirName = "manifests"
)

// APIKeyEnvVar is the environment variable name containing an IBM Cloud API key
const APIKeyEnvVar = "IC_API_KEY"

var (
	// CreateOpts captures the options that affect creation of the generated
	// objects.
	CreateOpts = options{
		TargetDir: "",
	}
)

// NewCreateSharedSecretsCmd implements the "create-shared-secrets" command for the credentials provisioning
func NewCreateSharedSecretsCmd() *cobra.Command {
	createSecretsCmd := &cobra.Command{
		Use:              "create-shared-secrets",
		Short:            "Create credentials objects",
		Long:             "Creating secrets from credentials requests using the API key in the IC_API_KEY environment variable",
		RunE:             createSharedSecretsCmd,
		PersistentPreRun: initEnvForCreateCmd,
	}

	createSecretsCmd.PersistentFlags().StringVar(&CreateOpts.CredRequestDir, "credentials-requests-dir", "", "Directory containing files of CredentialsRequests (can be created by running 'oc adm release extract --credentials-requests --cloud=ibmcloud' against an OpenShift release image)")
	createSecretsCmd.MarkPersistentFlagRequired("credentials-requests-dir")
	createSecretsCmd.PersistentFlags().StringVar(&CreateOpts.TargetDir, "output-dir", "", "Directory to place generated files (defaults to current directory)")

	return createSecretsCmd
}

func createSharedSecretsCmd(cmd *cobra.Command, args []string) error {
	apiKey := os.Getenv(APIKeyEnvVar)
	if apiKey == "" {
		return fmt.Errorf("%s environment variable not set", APIKeyEnvVar)
	}

	err := createSharedSecrets(CreateOpts.CredRequestDir, CreateOpts.TargetDir, apiKey)
	if err != nil {
		return err
	}
	return nil
}

func createSharedSecrets(credReqDir string, targetDir string, apiKey string) error {
	credRequests, err := getListOfCredentialsRequests(credReqDir)
	if err != nil {
		return errors.Wrap(err, "Failed to process files containing CredentialsRequests")
	}

	for _, cr := range credRequests {
		if err := processCredReq(cr, targetDir, apiKey); err != nil {
			return errors.Wrap(err, "Failed to process CredentialsReqeust")
		}
	}
	return nil
}

func getListOfCredentialsRequests(dir string) ([]*credreqv1.CredentialsRequest, error) {
	credRequests := []*credreqv1.CredentialsRequest{}
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		f, err := os.Open(filepath.Join(dir, file.Name()))
		if err != nil {
			return nil, errors.Wrap(err, "Failed to open file")
		}
		defer f.Close()
		decoder := yaml.NewYAMLOrJSONDecoder(f, 4096)
		for {
			cr := &credreqv1.CredentialsRequest{}
			if err := decoder.Decode(cr); err != nil {
				if err == io.EOF {
					break
				}
				return nil, errors.Wrap(err, "Failed to decode to CredentialsRequest")
			}
			credRequests = append(credRequests, cr)
		}

	}

	return credRequests, nil
}

func processCredReq(cr *credreqv1.CredentialsRequest, targetDir, apiKey string) error {
	// Decode IBMCloudProviderSpec
	codec, err := credreqv1.NewCodec()
	if err != nil {
		return errors.Wrap(err, "Failed to create credReq codec")
	}

	ibmcloudProviderProviderSpec := credreqv1.IBMCloudProviderSpec{}
	if err := codec.DecodeProviderSpec(cr.Spec.ProviderSpec, &ibmcloudProviderProviderSpec); err != nil {
		return errors.Wrap(err, "Failed to decode the provider spec")
	}

	if ibmcloudProviderProviderSpec.Kind != "IBMCloudProviderSpec" {
		return fmt.Errorf("CredentialsRequest %s/%s is not of type IBM Cloud", cr.Namespace, cr.Name)
	}

	return writeCredReqSecret(cr, targetDir, apiKey)
}

func writeCredReqSecret(cr *credreqv1.CredentialsRequest, targetDir, apiKey string) error {
	manifestsDir := filepath.Join(targetDir, manifestsDirName)

	fileName := fmt.Sprintf("%s-%s-credentials.yaml", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name)
	filePath := filepath.Join(manifestsDir, fileName)

	fileData := fmt.Sprintf(secretManifestsTemplate, b64.StdEncoding.EncodeToString([]byte(apiKey)), cr.Spec.SecretRef.Name, cr.Spec.SecretRef.Namespace)

	if err := ioutil.WriteFile(filePath, []byte(fileData), 0600); err != nil {
		return errors.Wrap(err, "Failed to save Secret file")
	}

	log.Printf("Saved credentials configuration to: %s", filePath)

	return nil
}

// initEnvForCreateCmd will ensure the destination directory is ready to
// receive the generated files, and will create the directory if necessary.
func initEnvForCreateCmd(cmd *cobra.Command, args []string) {
	if CreateOpts.TargetDir == "" {
		pwd, err := os.Getwd()
		if err != nil {
			log.Fatalf("Failed to get current directory: %s", err)
		}

		CreateOpts.TargetDir = pwd
	}

	fPath, err := filepath.Abs(CreateOpts.TargetDir)
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
