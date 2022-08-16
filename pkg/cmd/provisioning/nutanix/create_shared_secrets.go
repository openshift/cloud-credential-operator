package nutanix

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"

	"github.com/nutanix-cloud-native/prism-go-client/environment/providers/kubernetes"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

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
  credentials: %s`
)

var (
	// CreateSharedSecretsOpts captures the options that affect creation of the generated
	// objects.
	CreateSharedSecretsOpts = options{
		TargetDir:                 "",
		CredentialsSourceFilePath: "",
		EnableTechPreview:         false,
	}
)

// createSharedSecretsCmd implements the "create-secrets" command for the credentials provisioning
func createSharedSecretsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:              "create-shared-secrets",
		Short:            "Create credentials objects",
		Long:             "Creating secret objects related to cloud credentials. ",
		RunE:             createSecretsCmd,
		PersistentPreRun: initEnvForCreateCmd,
	}

	cmd.PersistentFlags().StringVar(&CreateSharedSecretsOpts.CredRequestDir, "credentials-requests-dir", "", "Directory containing files of CredentialsRequests (can be created by running 'oc adm release extract --credentials-requests --cloud=nutanix' against an OpenShift release image)")
	cmd.MarkPersistentFlagRequired("credentials-requests-dir")
	cmd.PersistentFlags().StringVar(&CreateSharedSecretsOpts.CredentialsSourceFilePath, "credentials-source-filepath", "", "The filepath of the nutanix credentials data. If not specified, will use the default path ~/.nutanix/credentials")
	cmd.PersistentFlags().StringVar(&CreateSharedSecretsOpts.TargetDir, "output-dir", "", "Directory to place generated files (defaults to current directory)")
	cmd.PersistentFlags().BoolVar(&CreateSharedSecretsOpts.EnableTechPreview, "enable-tech-preview", false, "Opt into processing CredentialsRequests marked as tech-preview")

	return cmd
}

func createSecretsCmd(cmd *cobra.Command, args []string) error {
	filePath := CreateSharedSecretsOpts.CredentialsSourceFilePath
	if filePath == "" {
		currentUser, err := user.Current()
		if err != nil {
			return errors.New("failed to get the current user for the default credentials-source-filepath; use the option --credentials-source-filepath to specify the filepath of the credentials data file")
		}
		if currentUser.HomeDir == "" {
			return errors.New("failed to get the current user's homeDir for the default credentials-source-filepath; use the option --credentials-source-filepath to specify the filepath of the credentials data file")
		}
		filePath = filepath.Join(currentUser.HomeDir, ".nutanix", "credentials")
	}

	creds, err := getCredentialsFromFile(filePath)
	if err != nil {
		return errors.Wrapf(err, "credentials data read from file %s is invalid", filePath)
	}

	if err := createSecrets(CreateSharedSecretsOpts.CredRequestDir, CreateSharedSecretsOpts.TargetDir, creds, CreateSharedSecretsOpts.EnableTechPreview); err != nil {
		return errors.Wrap(err, "failed to create credentials secrets")
	}

	return nil
}

// Retrieve the credentials data
func getCredentialsFromFile(filePath string) (*kubernetes.NutanixCredentials, error) {
	if _, err := os.Stat(filePath); err != nil {
		return nil, errors.Wrapf(err, "source credentials file %s does not exist", filePath)
	}

	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read the credentials file %s", filePath)
	}

	creds := &kubernetes.NutanixCredentials{}
	if err = yaml.Unmarshal(bytes, creds); err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal the credentials data read from file %s", filePath)
	}

	retCreds := &kubernetes.NutanixCredentials{}
	for _, cred := range creds.Credentials {
		switch cred.Type {
		case kubernetes.BasicAuthCredentialType:
			basicAuthCreds := &kubernetes.BasicAuthCredential{}
			if err = yaml.Unmarshal(cred.Data, basicAuthCreds); err != nil {
				return nil, errors.Wrap(err, "failed to unmarshal the basic-auth data")
			}
			if basicAuthCreds.PrismCentral.Username == "" || basicAuthCreds.PrismCentral.Password == "" {
				return nil, errors.New("prism central username and/or password are not set correctly")
			}

			credsJsonBytes, err := json.Marshal(*basicAuthCreds)
			if err != nil {
				return nil, errors.Wrap(err, "failed to convert the basic_auth type credentials object to json")
			}
			retCreds.Credentials = append(retCreds.Credentials, kubernetes.Credential{
				Type: kubernetes.BasicAuthCredentialType,
				Data: credsJsonBytes,
			})

		default:
			return nil, errors.Errorf("unsupported credentials type: %v", cred.Type)
		}
	}

	return retCreds, nil
}

func createSecrets(credReqDir, targetDir string, creds *kubernetes.NutanixCredentials, enableTechPreview bool) error {
	credRequests, err := provisioning.GetListOfCredentialsRequests(credReqDir, enableTechPreview)
	if err != nil {
		return errors.Wrap(err, "failed to process files containing CredentialsRequests")
	}

	if len(credRequests) == 0 {
		return errors.Errorf("no CredentialsRequest manifests found in %q", credReqDir)
	}

	for _, cr := range credRequests {
		if cr.Spec.ProviderSpec == nil {
			continue
		}
		if err := processCredReq(cr, targetDir, creds); err != nil {
			return errors.Wrap(err, "failed to process CredentialsReqeust")
		}
	}
	return nil
}

func writeCredReqSecret(cr *credreqv1.CredentialsRequest, targetDir string, creds *kubernetes.NutanixCredentials) error {
	manifestsDir := filepath.Join(targetDir, manifestsDirName)
	fileName := fmt.Sprintf("%s-%s-credentials.yaml", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name)
	filePath := filepath.Join(manifestsDir, fileName)
	credsJsonBytes, err := json.Marshal(creds.Credentials)
	if err != nil {
		return errors.Wrap(err, "failed to convert the credentials object to json")
	}

	b64CredsJson := base64.StdEncoding.EncodeToString(credsJsonBytes)
	fileData := fmt.Sprintf(secretManifestsTemplate, cr.Spec.SecretRef.Name, cr.Spec.SecretRef.Namespace, b64CredsJson)
	if err := ioutil.WriteFile(filePath, []byte(fileData), 0600); err != nil {
		return errors.Wrap(err, "failed to save secret manifest")
	}

	log.Printf("Saved credentials configuration to: %s", filePath)
	return nil
}

func processCredReq(cr *credreqv1.CredentialsRequest, targetDir string, creds *kubernetes.NutanixCredentials) error {
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
		return errors.Errorf("CredentialsRequest %s/%s is not of type Nutanix", cr.Namespace, cr.Name)
	}

	return writeCredReqSecret(cr, targetDir, creds)
}

// initEnvForCreateCmd will ensure the destination directory is ready to
// receive the generated files, and will create the directory if necessary.
func initEnvForCreateCmd(cmd *cobra.Command, args []string) {
	if CreateSharedSecretsOpts.TargetDir == "" {
		pwd, err := os.Getwd()
		if err != nil {
			log.Fatalf("failed to get current directory: %s", err)
		}

		CreateSharedSecretsOpts.TargetDir = pwd
	}

	fPath, err := filepath.Abs(CreateSharedSecretsOpts.TargetDir)
	if err != nil {
		log.Fatalf("failed to resolve full path: %s", err)
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
