package nutanix

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"gopkg.in/square/go-jose.v2/json"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
)

const (
	manifestsDirName = "manifests"

	secretManifestsTemplate = `apiVersion: v1
data:
  credentials: %s
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque`

	BasicAuthCredentialType CredentialType = "basic_auth"
)

type CredentialType string

type NutanixCredentials struct {
	Credentials []Credential `json:"credentials"`
}

type Credential struct {
	Type CredentialType           `json:"type"`
	Data *k8sruntime.RawExtension `json:"data"`
}

type BasicAuthCredential struct {
	// The Basic Auth (username, password) for the Prism Central
	PrismCentral PrismCentralBasicAuth `json:"prismCentral"`

	// The Basic Auth (username, password) for the Prism Elements (clusters).
	// Currently only one Prism Element (cluster) is used for each openshift cluster.
	// Later this may spread to multiple Prism Element (cluster).
	PrismElements []PrismElementBasicAuth `json:"prismElements"`
}

type PrismCentralBasicAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type PrismElementBasicAuth struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

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
		homePath := GetHomePath()
		if homePath == "" {
			return errors.New("The default source credential file path is invalid")
		}
		filePath = filepath.Join(homePath, ".nutanix", "credentials")
	}

	if _, err := os.Stat(filePath); err != nil {
		return fmt.Errorf("The source credentials file %s does not exist.", filePath)
	}

	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("Failed to read the credentials file %s. %v", filePath, err)
	}

	creds := &NutanixCredentials{}
	if err = yaml.Unmarshal(bytes, creds); err != nil {
		return fmt.Errorf("Failed to convert the credentials data read from file %s. %v", filePath, err)
	}

	retCreds, err := getCredentialsData(creds)
	if err != nil {
		return errors.Wrapf(err, "The credentials data read from file %s is invalid.", filePath)
	}

	err = createSecrets(CreateSharedSecretsOpts.CredRequestDir, CreateSharedSecretsOpts.TargetDir, retCreds, CreateSharedSecretsOpts.EnableTechPreview)
	if err != nil {
		return errors.Wrap(err, "Failed to create credentials secrets")
	}

	return nil
}

// Retrieve the credentials data
func getCredentialsData(creds *NutanixCredentials) (*NutanixCredentials, error) {
	var err error
	retCreds := &NutanixCredentials{}
	for _, cred := range creds.Credentials {
		switch cred.Type {
		case BasicAuthCredentialType:
			basicAuthCreds := &BasicAuthCredential{}
			if err = yaml.Unmarshal(cred.Data.Raw, basicAuthCreds); err != nil {
				return nil, errors.Wrap(err, "Failed to convert the basic-auth data.")
			}
			if basicAuthCreds.PrismCentral.Username == "" || basicAuthCreds.PrismCentral.Password == "" {
				return nil, errors.New("The Prism Central username and/or password are not set correctly.")
			}
			if len(basicAuthCreds.PrismElements) == 0 || basicAuthCreds.PrismElements[0].Name == "" ||
				basicAuthCreds.PrismElements[0].Username == "" || basicAuthCreds.PrismElements[0].Password == "" {
				return nil, errors.New("The Prism Element (cluster) username and/or password are not set correctly.")
			}

			credsJsonBytes, err := json.Marshal(*basicAuthCreds)
			if err != nil {
				return nil, errors.Errorf("Failed to convert the basic_auth type credentials object to json. %v", err)
			}
			retCreds.Credentials = append(retCreds.Credentials, Credential{
				Type: BasicAuthCredentialType,
				Data: &k8sruntime.RawExtension{Raw: credsJsonBytes},
			})

		default:
			return nil, fmt.Errorf("Unsupported credentials type: %v", cred.Type)
		}
	}

	log.Printf("There are %d valid credentials", len(retCreds.Credentials))
	return retCreds, nil
}

func createSecrets(credReqDir, targetDir string, creds *NutanixCredentials, enableTechPreview bool) error {
	credRequests, err := provisioning.GetListOfCredentialsRequests(credReqDir, enableTechPreview)
	if err != nil {
		return errors.Wrap(err, "Failed to process files containing CredentialsRequests")
	}

	for _, cr := range credRequests {
		if err := processCredReq(cr, targetDir, creds); err != nil {
			return errors.Wrap(err, "Failed to process CredentialsReqeust")
		}
	}
	return nil
}

func writeCredReqSecret(cr *credreqv1.CredentialsRequest, targetDir string, creds *NutanixCredentials) error {
	manifestsDir := filepath.Join(targetDir, manifestsDirName)

	fileName := fmt.Sprintf("%s-%s-credentials.yaml", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name)
	filePath := filepath.Join(manifestsDir, fileName)

	credsJsonBytes, err := json.Marshal(creds.Credentials)
	if err != nil {
		return errors.Errorf("Failed to convert the credentials object to json. %v", err)
	}
	b64CredsJson := base64.StdEncoding.EncodeToString(credsJsonBytes)

	fileData := fmt.Sprintf(secretManifestsTemplate, string(b64CredsJson),
		cr.Spec.SecretRef.Name, cr.Spec.SecretRef.Namespace)

	if err := ioutil.WriteFile(filePath, []byte(fileData), 0600); err != nil {
		return errors.Wrap(err, "Failed to save Secret file")
	}

	log.Printf("Saved credentials configuration to: %s", filePath)

	return nil
}

func processCredReq(cr *credreqv1.CredentialsRequest, targetDir string, creds *NutanixCredentials) error {
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

	return writeCredReqSecret(cr, targetDir, creds)
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

// GetHomePath return home directory according to the system.
// if the environmental virables does not exist, will return empty
func GetHomePath() string {
	if runtime.GOOS == "windows" {
		path, ok := os.LookupEnv("USERPROFILE")
		if !ok {
			return ""
		}
		return path
	}
	path, ok := os.LookupEnv("HOME")
	if !ok {
		return ""
	}
	return path
}
