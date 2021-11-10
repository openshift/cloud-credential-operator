package alibabacloud

import (
	"encoding/json"
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/openshift/cloud-credential-operator/pkg/alibabacloud"
	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

const (
	secretManifestsTemplate = `apiVersion: v1
data:
  access_key_id: %s
  access_key_secret: %s
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque`

	// Https for ram client scheme
	Https = "https"
	// Custom is ram policy type
	Custom = "Custom"
)

var (
	// AttachRAMPolicyOpts captures the options that affect creation/updating
	// of the RAM Roles.
	AttachRAMPolicyOpts = options{
		TargetDir: "",
	}
)

type ComponenntSecretInfo struct {
	componentAccessKeyId     string
	componentAccessKeySecret string
	targetDir                string
	userName                 string
}

func attachRAMPolicy(client alibabacloud.Client, name, credReqDir string, componenntSecretInfo ComponenntSecretInfo) error {
	// Process directory
	credRequests, err := provisioning.GetListOfCredentialsRequests(credReqDir)
	if err != nil {
		return errors.Wrap(err, "Failed to process files containing CredentialsRequests")
	}

	// Create RAM Roles (with policies)
	if err := processCredentialsRequests(client, credRequests, name, componenntSecretInfo); err != nil {
		return errors.Wrap(err, "Failed while processing each CredentialsRequest")
	}

	return nil
}

func processCredentialsRequests(client alibabacloud.Client, credReqs []*credreqv1.CredentialsRequest, name string, componenntSecretInfo ComponenntSecretInfo) error {
	for _, cr := range credReqs {
		// infraName-targetNamespace-targetSecretName
		err := createAndAttachPolicy(client, name, cr, componenntSecretInfo)
		if err != nil {
			return err
		}
	}
	return nil
}

func attachRAMPolicyCmd(cmd *cobra.Command, args []string) {
	client, err := alibabacloud.NewClient(AttachRAMPolicyOpts.Region, AttachRAMPolicyOpts.RootAccessKeyId, AttachRAMPolicyOpts.RootAccessKeySecret)
	if err != nil {
		log.Fatal(err)
	}
	var componentSecretInfo = ComponenntSecretInfo{
		componentAccessKeyId:     AttachRAMPolicyOpts.ComponentAccessKeyId,
		componentAccessKeySecret: AttachRAMPolicyOpts.ComponentAccessKeySecret,
		targetDir:                AttachRAMPolicyOpts.TargetDir,
		userName:                 AttachRAMPolicyOpts.UserName,
	}
	if componentSecretInfo.componentAccessKeyId == "" || componentSecretInfo.componentAccessKeySecret == "" || componentSecretInfo.userName == "" {
		log.Fatal(errors.New("invalid empty value for component-access-key/component-access-secret or user-name"))
	}
	err = attachRAMPolicy(client, AttachRAMPolicyOpts.Name, AttachRAMPolicyOpts.CredRequestDir, componentSecretInfo)
	if err != nil {
		log.Fatal(err)
	}
}

func createAndAttachPolicy(client alibabacloud.Client, name string, credReq *credreqv1.CredentialsRequest, componenntSecretInfo ComponenntSecretInfo) error {
	policyName := fmt.Sprintf("%s-%s-policy", name, credReq.Spec.SecretRef.Name)

	// Decode Alibaba CloudProviderSpec
	codec, err := credreqv1.NewCodec()
	if err != nil {
		return errors.Wrap(err, "Failed to create credReq codec")
	}

	alibabaProviderSpec := credreqv1.AlibabaCloudProviderSpec{}
	if err := codec.DecodeProviderSpec(credReq.Spec.ProviderSpec, &alibabaProviderSpec); err != nil {
		return errors.Wrap(err, "Failed to decode the provider spec")
	}

	if alibabaProviderSpec.Kind != "AlibabaCloudProviderSpec" {
		return fmt.Errorf("CredentialsRequest %s/%s is not of type Alibaba Cloud", credReq.Namespace, credReq.Name)
	}

	err = createComponentPolicy(client, policyName, alibabaProviderSpec.StatementEntries)
	if err != nil {
		return err
	}
	log.Printf("ram policy %s has created", policyName)

	err = attachComponentPolicy(client, componenntSecretInfo.userName, policyName)
	if err != nil {
		return err
	}
	log.Printf("policy %s has attached on user %s", policyName, componenntSecretInfo.userName)

	if err := writeCredReqSecret(credReq, componenntSecretInfo); err != nil {
		return errors.Wrap(err, "failed to save Secret for install manifests")
	}
	return nil
}

// StatementEntry is a simple type used to serialize to Alibaba Cloud' PolicyDocument format.
type StatementEntry struct {
	Effect   string
	Action   []string
	Resource string
	// Must "omitempty" otherwise we send unacceptable JSON to the Alibaba Cloud API when no
	// condition is defined.
	Condition credreqv1.RAMPolicyCondition `json:",omitempty"`
}

// PolicyDocument is a simple type used to serialize to Alibaba Cloud' PolicyDocument format.
type PolicyDocument struct {
	Version   string
	Statement []StatementEntry
}

func createComponentPolicy(client alibabacloud.Client, policyName string, statements []credreqv1.AlibabaStatementEntry) error {
	policyDocument := PolicyDocument{
		Version:   "1",
		Statement: []StatementEntry{},
	}

	for _, entry := range statements {
		policyDocument.Statement = append(policyDocument.Statement,
			StatementEntry{
				Effect:    entry.Effect,
				Action:    entry.Action,
				Resource:  entry.Resource,
				Condition: entry.PolicyCondition,
			})
	}

	policyBytes, err := json.Marshal(&policyDocument)
	if err != nil {
		log.Fatalf("Failed to marshal the policy to JSON: %s", err)
	}

	req := ram.CreatePolicyRequest{}
	req.Scheme = Https
	req.PolicyName = policyName
	req.PolicyDocument = string(policyBytes)
	_, err = client.CreatePolicy(&req)
	return err
}

func attachComponentPolicy(client alibabacloud.Client, user, policyName string) error {
	req := ram.AttachPolicyToUserRequest{}
	req.Scheme = Https
	req.PolicyName = policyName
	req.UserName = user
	req.PolicyType = Custom
	_, err := client.AttachPolicyToUser(&req)
	return err
}

// writeCredReqSecret will take a credentialsRequest and return
// a Secret with the AK/SK of a ram user who has grant component permission defined in credentialsRequest.
func writeCredReqSecret(cr *credreqv1.CredentialsRequest, componenntSecretInfo ComponenntSecretInfo) error {
	manifestsDir := filepath.Join(componenntSecretInfo.targetDir, provisioning.ManifestsDirName)

	fileName := fmt.Sprintf("%s-%s-credentials.yaml", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name)
	filePath := filepath.Join(manifestsDir, fileName)

	fileData := fmt.Sprintf(secretManifestsTemplate, componenntSecretInfo.componentAccessKeyId, componenntSecretInfo.componentAccessKeySecret, cr.Spec.SecretRef.Name, cr.Spec.SecretRef.Namespace)

	if err := ioutil.WriteFile(filePath, []byte(fileData), 0600); err != nil {
		return errors.Wrap(err, "Failed to save Secret file")
	}

	log.Printf("Saved credentials configuration to: %s", filePath)

	return nil
}

// initEnvForAttachRAMPolicyCmd will ensure the destination directory is ready to receive the generated
// files, and will create the directory if necessary.
func initEnvForAttachRAMPolicyCmd(cmd *cobra.Command, args []string) {
	if AttachRAMPolicyOpts.TargetDir == "" {
		pwd, err := os.Getwd()
		if err != nil {
			log.Fatalf("Failed to get current directory: %s", err)
		}

		AttachRAMPolicyOpts.TargetDir = pwd
	}

	fPath, err := filepath.Abs(AttachRAMPolicyOpts.TargetDir)
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

// NewCreateRAMPolicyCmd provides the "attach-ram-policy" subcommand
func NewAttachRAMPolicyCmd() *cobra.Command {
	attachRAMPolicyCmd := &cobra.Command{
		Use:              "attach-ram-policy",
		Short:            "Attach RAM Policy",
		Run:              attachRAMPolicyCmd,
		PersistentPreRun: initEnvForAttachRAMPolicyCmd,
	}

	attachRAMPolicyCmd.PersistentFlags().StringVar(&AttachRAMPolicyOpts.Name, "name", "", "User-define name for all created Alibaba Cloud resources (can be separate from the cluster's infra-id)")
	attachRAMPolicyCmd.MarkPersistentFlagRequired("name")
	attachRAMPolicyCmd.PersistentFlags().StringVar(&AttachRAMPolicyOpts.CredRequestDir, "credentials-requests-dir", "", "Directory containing files of CredentialsRequests to create RAM AK for (can be created by running 'oc adm release extract --credentials-requests --cloud=alibabacloud' against an OpenShift release image)")
	attachRAMPolicyCmd.MarkPersistentFlagRequired("credentials-requests-dir")
	attachRAMPolicyCmd.PersistentFlags().StringVar(&AttachRAMPolicyOpts.RootAccessKeyId, "root-access-key", "", "The root user ak with ram permission such as CreatePolicy/AttachPolicyToUser")
	attachRAMPolicyCmd.MarkPersistentFlagRequired("root-access-key")
	attachRAMPolicyCmd.PersistentFlags().StringVar(&AttachRAMPolicyOpts.RootAccessKeySecret, "root-access-key-secret", "", "The root user sk with ram permission such as CreatePolicy/AttachPolicyToUser")
	attachRAMPolicyCmd.MarkPersistentFlagRequired("root-access-key-secret")
	attachRAMPolicyCmd.PersistentFlags().StringVar(&AttachRAMPolicyOpts.UserName, "user-name", "", "The specific ram user name, the user would attach all permission defined in CredentialsRequests")
	attachRAMPolicyCmd.MarkPersistentFlagRequired("user-name")
	attachRAMPolicyCmd.PersistentFlags().StringVar(&AttachRAMPolicyOpts.ComponentAccessKeyId, "component-access-key", "", "The created component user ak with ram permission defined in CredentialsRequests")
	attachRAMPolicyCmd.MarkPersistentFlagRequired("component-access-key")
	attachRAMPolicyCmd.PersistentFlags().StringVar(&AttachRAMPolicyOpts.ComponentAccessKeySecret, "component-access-secret", "", "The created component user sk with ram permission defined in CredentialsRequests")
	attachRAMPolicyCmd.MarkPersistentFlagRequired("component-access-secret")
	attachRAMPolicyCmd.PersistentFlags().StringVar(&AttachRAMPolicyOpts.Region, "region", "", "Alibaba Cloud region endpoint only required for GovCloud")
	attachRAMPolicyCmd.PersistentFlags().StringVar(&AttachRAMPolicyOpts.TargetDir, "output-dir", "", "Directory to place generated files (defaults to current directory)")

	return attachRAMPolicyCmd
}
