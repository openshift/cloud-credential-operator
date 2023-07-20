package alibabacloud

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	alibabaerrors "github.com/aliyun/alibaba-cloud-sdk-go/sdk/errors"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"

	"github.com/openshift/cloud-credential-operator/pkg/alibabacloud"
	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
)

const (
	secretManifestsTemplate = `apiVersion: v1
stringData:
  credentials: |-
    [default]
    type = access_key
    access_key_id = %s
    access_key_secret = %s
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque`

	// ramPolicyType is the default policy type used for created Policies
	ramPolicyType = "Custom"
	// autoRotateStrategy will delete the earliest inactive policy version
	autoRotateStrategy = "DeleteOldestNonDefaultVersionWhenLimitExceeded"
	// ccoctlResourcePrefix is the prefix of the tag key applied to the Alibaba Cloud ram user created by ccoctl
	ccoctlResourcePrefix = "openshift.io/ccoctl"
)

var (
	// CreateRAMUsersOpts captures the options that affect creation/updating
	// of the RAM Uers/Policies.
	CreateRAMUsersOpts = options{
		Region:         "",
		TargetDir:      "",
		Name:           "",
		CredRequestDir: "",
	}
)

func createRAMUsersCmd(cmd *cobra.Command, args []string) {
	client, err := alibabacloud.NewClient(CreateRAMUsersOpts.Region)
	if err != nil {
		log.Fatalf("Failed to create a client: %v", err)
	}

	err = createRAMUsers(client, CreateRAMUsersOpts.Name, CreateRAMUsersOpts.CredRequestDir,
		CreateRAMUsersOpts.TargetDir, CreateRAMUsersOpts.EnableTechPreview)
	if err != nil {
		log.Fatalf(err.Error())
	}
}

// createRAMUsers will create a ram user for the given credenital request and attach the specific ram policy
func createRAMUsers(client alibabacloud.Client, name, credReqDir, targetDir string, enableTechPreview bool) error {
	// Process directory
	credRequests, err := provisioning.GetListOfCredentialsRequests(credReqDir, enableTechPreview)
	if err != nil {
		return errors.Wrap(err, "Failed to process files containing CredentialsRequests")
	}

	// Create RAM Roles (with policies)
	if err := processNewCredentialsRequests(client, credRequests, name, targetDir); err != nil {
		return errors.Wrap(err, "Failed while processing each CredentialsRequest")
	}

	return nil
}

// StatementEntry is a simple type used to serialize to Alibaba Cloud' PolicyDocument format.
type StatementEntry struct {
	Effect   string
	Action   []string
	Resource string
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
				Effect:   entry.Effect,
				Action:   entry.Action,
				Resource: entry.Resource,
			})
	}

	policyBytes, err := json.Marshal(&policyDocument)
	if err != nil {
		log.Fatalf("Failed to marshal the policy to JSON: %s", err)
	}

	req := ram.CreateGetPolicyRequest()
	req.PolicyName = policyName
	req.PolicyType = ramPolicyType
	_, err = client.GetPolicy(req)
	if err != nil {
		aErr, ok := err.(*alibabaerrors.ServerError)
		if ok && aErr.ErrorCode() == errorPolicyNotExists {
			//create new policy
			log.Printf("Ready for creating new ram policy %s", policyName)
			preq := ram.CreateCreatePolicyRequest()
			preq.PolicyName = policyName
			preq.PolicyDocument = string(policyBytes)
			preq.Description = "Created by OpenShift ccoctl"
			_, err = client.CreatePolicy(preq)
			if err == nil {
				return nil
			}
		}
		log.Fatalf("Failed to create new ram policy %s, err is %v", policyName, err)
	}
	//create new policy with new version and set it to the default one
	vreq := ram.CreateCreatePolicyVersionRequest()
	vreq.PolicyName = policyName
	vreq.PolicyDocument = string(policyBytes)
	vreq.RotateStrategy = autoRotateStrategy
	vreq.SetAsDefault = "true"
	_, err = client.CreatePolicyVersion(vreq)
	return err
}

// attachComponentPolicy will attach the given policy to the preset component user
func attachComponentPolicy(client alibabacloud.Client, user, policyName string) error {
	req := ram.CreateAttachPolicyToUserRequest()
	req.PolicyName = policyName
	req.UserName = user
	req.PolicyType = ramPolicyType
	_, err := client.AttachPolicyToUser(req)
	if err != nil {
		aErr, ok := err.(*alibabaerrors.ServerError)
		if ok && aErr.ErrorCode() == errorUserAleadyAttachedPolicy {
			return nil
		}
	}
	return err
}

func processNewCredentialsRequests(client alibabacloud.Client, credReqs []*credreqv1.CredentialsRequest, name, targetDir string) error {
	for _, cr := range credReqs {
		err := createUserAndAttachPolicy(client, name, targetDir, cr)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("Failed to create user and attach policy for CredentialsRequest %s", cr.Name))
		}
	}
	return nil
}

func createUser(client alibabacloud.Client, name string, credReq *credreqv1.CredentialsRequest) (string, error) {
	userName := fmt.Sprintf("%s-%s-%s", name, credReq.Spec.SecretRef.Namespace, credReq.Spec.SecretRef.Name)
	shortName, displayName := generateRAMUserName(userName)

	userReq := ram.CreateCreateUserRequest()
	userReq.UserName = shortName
	userReq.DisplayName = displayName
	userReq.Comments = fmt.Sprintf("%s/%s", ccoctlResourcePrefix, name)
	user, err := client.CreateUser(userReq)
	if err != nil {
		aErr, ok := err.(*alibabaerrors.ServerError)
		if ok && aErr.ErrorCode() == errorUserAlreadyExists {
			log.Printf("RAM User %s already exists, continuing", shortName)
			return shortName, nil
		} else {
			return "", errors.Wrap(err, "Failed to create RAM user")
		}
	}

	log.Printf("Created RAM User: %s", user.User.UserName)
	return user.User.UserName, nil
}

func generateUserAccessKeys(client alibabacloud.Client, userName string) (*ram.CreateAccessKeyResponse, error) {
	accessKeyReq := ram.CreateCreateAccessKeyRequest()
	accessKeyReq.UserName = userName
	accessKeyResp, err := client.CreateAccessKey(accessKeyReq)
	if err != nil {
		aErr, ok := err.(*alibabaerrors.ServerError)
		if ok && aErr.ErrorCode() == errorAKLimitExceeded {
			log.Printf("RAM User %s's accesskey number limit exceeded, will delete original accesskeys", userName)
			listKeyReq := ram.CreateListAccessKeysRequest()
			listKeyReq.UserName = userName
			listKeyRes, err := client.ListAccessKeys(listKeyReq)
			if err != nil {
				return nil, errors.Wrap(err, "Failed to list accesskeys")
			}
			//get the older one or the keys with in-active status to delete
			deleteKeys, err := getDeleteAccessKeys(listKeyRes.AccessKeys.AccessKey)
			if err != nil {
				return nil, errors.Wrap(err, "Failed to get the older ram accesskey")
			}
			for _, oneAK := range deleteKeys {
				log.Printf("Ready to delete user %s accesskey %s", userName, oneAK.AccessKeyId)
				deleteKeyReq := ram.CreateDeleteAccessKeyRequest()
				deleteKeyReq.UserName = userName
				deleteKeyReq.UserAccessKeyId = oneAK.AccessKeyId
				_, err := client.DeleteAccessKey(deleteKeyReq)
				if err != nil {
					return nil, err
				}
			}

			accessKeyResp, err = client.CreateAccessKey(accessKeyReq)
			if err != nil {
				return nil, err
			}
			log.Printf("Created access keys for RAM User: %s", userName)
			return accessKeyResp, nil
		}
		return nil, errors.Wrap(err, "Failed to create RAM user access keys")
	}
	log.Printf("Created access keys for RAM User: %s", userName)
	return accessKeyResp, nil
}

func createUserAndAttachPolicy(client alibabacloud.Client, name, targetDir string, credReq *credreqv1.CredentialsRequest) error {
	policyName := generatePolicyName(fmt.Sprintf("%s-%s-%s-policy", name, credReq.Spec.SecretRef.Namespace, credReq.Spec.SecretRef.Name))

	// Decode Alibaba CloudProviderSpec
	alibabaProviderSpec := credreqv1.AlibabaCloudProviderSpec{}
	if err := credreqv1.Codec.DecodeProviderSpec(credReq.Spec.ProviderSpec, &alibabaProviderSpec); err != nil {
		return errors.Wrap(err, "Failed to decode the provider spec")
	}

	if alibabaProviderSpec.Kind != "AlibabaCloudProviderSpec" {
		return fmt.Errorf("CredentialsRequest %s/%s is not of type Alibaba Cloud", credReq.Namespace, credReq.Name)
	}

	ramUserName, err := createUser(client, name, credReq)
	if err != nil {
		return errors.Wrap(err, "Failed while creating RAM User")
	}

	err = createComponentPolicy(client, policyName, alibabaProviderSpec.StatementEntries)
	if err != nil {
		return refineMissingRegionIdErr(err)
	}
	log.Printf("RAM policy %s has created", policyName)

	err = attachComponentPolicy(client, ramUserName, policyName)
	if err != nil {
		return refineMissingRegionIdErr(err)
	}
	log.Printf("Policy %s has attached on user %s", policyName, ramUserName)

	accessKeys, err := generateUserAccessKeys(client, ramUserName)
	if err != nil {
		return errors.Wrap(err, "Failed to generate RAM User access keys")
	}
	if err := writeCredReqSecret(credReq, targetDir, accessKeys.AccessKey.AccessKeyId, accessKeys.AccessKey.AccessKeySecret); err != nil {
		return errors.Wrap(err, "Failed to save Secret for install manifests")
	}

	return nil
}

// writeCredReqSecret will take a CredentialsRequest and return
// a Secret with the AK/SK of a ram user who has grant component permission defined in CredentialsRequest.
func writeCredReqSecret(cr *credreqv1.CredentialsRequest, targetDir, accessKeyId, accessKeySecret string) error {
	manifestsDir := filepath.Join(targetDir, provisioning.ManifestsDirName)

	fileName := fmt.Sprintf("%s-%s-credentials.yaml", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name)
	filePath := filepath.Join(manifestsDir, fileName)

	fileData := fmt.Sprintf(secretManifestsTemplate, accessKeyId, accessKeySecret, cr.Spec.SecretRef.Name, cr.Spec.SecretRef.Namespace)

	if err := ioutil.WriteFile(filePath, []byte(fileData), 0600); err != nil {
		return errors.Wrap(err, "Failed to save Secret file")
	}

	log.Printf("Saved credentials configuration to: %s", filePath)

	return nil
}

// initEnvForCreateRAMUsersCmd ensure destination directory is ready to receive the generated files, and will create the directory if necessary.
func initEnvForCreateRAMUsersCmd(cmd *cobra.Command, args []string) {
	if CreateRAMUsersOpts.TargetDir == "" {
		pwd, err := os.Getwd()
		if err != nil {
			log.Fatalf("Failed to get current directory: %s", err)
		}

		CreateRAMUsersOpts.TargetDir = pwd
	}

	fPath, err := filepath.Abs(CreateRAMUsersOpts.TargetDir)
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

// NewCreateRAMUsersCmd provides the "create-ram-users" subcommand
func NewCreateRAMUsersCmd() *cobra.Command {
	createRAMUsersCmd := &cobra.Command{
		Use:              "create-ram-users",
		Short:            "Create RAM Users and policies",
		Run:              createRAMUsersCmd,
		PersistentPreRun: initEnvForCreateRAMUsersCmd,
	}

	createRAMUsersCmd.PersistentFlags().StringVar(&CreateRAMUsersOpts.Name, "name", "", "User-defined name for all created Alibaba Cloud resources (can be separate from the cluster's infra-id)")
	createRAMUsersCmd.MarkPersistentFlagRequired("name")
	createRAMUsersCmd.PersistentFlags().StringVar(&CreateRAMUsersOpts.CredRequestDir, "credentials-requests-dir", "", "Directory containing files of CredentialsRequests to create RAM AK for (can be created by running 'oc adm release extract --credentials-requests --cloud=alibabacloud' against an OpenShift release image)")
	createRAMUsersCmd.MarkPersistentFlagRequired("credentials-requests-dir")
	createRAMUsersCmd.PersistentFlags().StringVar(&CreateRAMUsersOpts.Region, "region", "", "Alibaba Cloud region endpoint only required for GovCloud")
	createRAMUsersCmd.PersistentFlags().StringVar(&CreateRAMUsersOpts.TargetDir, "output-dir", "", "Directory to place generated files (defaults to current directory)")
	createRAMUsersCmd.PersistentFlags().BoolVar(&CreateRAMUsersOpts.EnableTechPreview, "enable-tech-preview", false, "Opt into processing CredentialsRequests marked as tech-preview")

	return createRAMUsersCmd
}
