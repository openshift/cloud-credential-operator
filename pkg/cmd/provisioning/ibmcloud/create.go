package ibmcloud

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/util/yaml"
)

const (
	secretManifestsTemplate = `apiVersion: v1
stringData:
  ibmcloud_api_key: %s
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque`

	manifestsDirName = "manifests"
)

var (
	// CreateOpts captures the options that affect creation of the generated
	// objects.
	CreateOpts = options{
		TargetDir: "",
	}
)

// NewCreateCmd implements the "create" command for the credentials provisioning
func NewCreateCmd() *cobra.Command {
	createCmd := &cobra.Command{
		Use:              "create",
		Short:            "Create credentials objects",
		Long:             "Creating objects related to cloud credentials",
		Run:              createCmd,
		PersistentPreRun: initEnvForCreateCmd,
	}

	createCmd.PersistentFlags().StringVar(&CreateOpts.CredRequestDir, "credentials-requests-dir", "", "Directory containing files of CredentialsRequests (can be created by running 'oc adm release extract --credentials-requests --cloud=ibmcloud' against an OpenShift release image)")
	createCmd.MarkPersistentFlagRequired("credentials-requests-dir")
	createCmd.PersistentFlags().StringVar(&CreateOpts.TargetDir, "output-dir", "", "Directory to place generated files (defaults to current directory)")

	return createCmd
}

func createCmd(cmd *cobra.Command, args []string) {
	apiKey := os.Getenv("IC_API_KEY")
	if apiKey == "" {
		log.Fatal(fmt.Errorf("IC_API_KEY environment variable not set"))
	}

	err := create(CreateOpts.CredRequestDir, CreateOpts.TargetDir, apiKey)
	if err != nil {
		log.Fatal(err)
	}
}

func create(credReqDir string, targetDir string, apiKey string) error {
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

	fileData := fmt.Sprintf(secretManifestsTemplate, apiKey, cr.Spec.SecretRef.Name, cr.Spec.SecretRef.Namespace)

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
