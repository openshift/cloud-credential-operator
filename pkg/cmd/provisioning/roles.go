package provisioning

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"

	"k8s.io/apimachinery/pkg/util/yaml"

	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/aws"
)

const (
	rolePolicyDocmentTemplate = `{ "Version": "2012-10-17", "Statement": [ { "Effect": "Allow", "Principal": { "Federated": "%s" }, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": %s } ] }`

	roleTemplate = `{
	"RoleName": "%s",
	"AssumeRolePolicyDocument": "%s",
	"Description": "%s"
}`

	rolePolicyTemplate = `{
	"RoleName": "%s",
	"PolicyName": "%s",
	"PolicyDocument": "%s"
}`

	secretManifestsTemplate = `apiVersion: v1
stringData:
  credentials: |-
    [default]
    role_arn = %s
    web_identity_token_file = /var/run/secrets/openshift/serviceaccount/token
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque`
)

func createIAMRoles(client aws.Client, identityProviderARN, namePrefix, credReqDir, targetDir string, generateOnly bool) error {
	// Process directory
	credRequests, err := getListOfCredentialsRequests(credReqDir)
	if err != nil {
		return errors.Wrap(err, "Failed to process files containing CredentialsRequests")
	}

	// Create IAM Roles (with policies)
	if err := processCredentialsRequests(client, credRequests, identityProviderARN, namePrefix, targetDir, generateOnly); err != nil {
		return errors.Wrap(err, "Failed while processing each CredentialsRequest")
	}

	return nil
}

func processCredentialsRequests(awsClient aws.Client, credReqs []*credreqv1.CredentialsRequest, identityProviderARN, namePrefix, targetDir string, generateOnly bool) error {

	issuerURL, err := getIssuerURLFromIdentityProvider(awsClient, identityProviderARN)
	if err != nil {
		return err
	}

	for i, cr := range credReqs {
		// infraName-targetNamespace-targetSecretName
		_, err = createRole(awsClient, namePrefix, cr, i, identityProviderARN, issuerURL, targetDir, generateOnly)
		if err != nil {
			return err
		}

	}
	return nil
}

func createRole(awsClient aws.Client, namePrefix string, credReq *credreqv1.CredentialsRequest, roleNum int, oidcProviderARN, issuerURL, targetDir string, generateOnly bool) (string, error) {
	roleName := fmt.Sprintf("%s-%s-%s", namePrefix, credReq.Spec.SecretRef.Namespace, credReq.Spec.SecretRef.Name)

	// Decode AWSProviderSpec
	codec, err := credreqv1.NewCodec()
	if err != nil {
		return "", errors.Wrap(err, "Failed to create credReq codec")
	}

	awsProviderSpec := credreqv1.AWSProviderSpec{}
	if err := codec.DecodeProviderSpec(credReq.Spec.ProviderSpec, &awsProviderSpec); err != nil {
		return "", errors.Wrap(err, "Failed to decode the provider spec")
	}

	if awsProviderSpec.Kind != "AWSProviderSpec" {
		return "", fmt.Errorf("CredentialsRequest %s/%s is not of type AWS", credReq.Namespace, credReq.Name)
	}

	// Ensure role name is no longer than 64 charactters
	var shortenedRoleName string
	if len(roleName) > 64 {
		shortenedRoleName = roleName[0:64]
	} else {
		shortenedRoleName = roleName
	}

	rolePolicyDocument, err := createRolePolicyDocument(oidcProviderARN, issuerURL, credReq.Spec.ServiceAccountNames)
	if err != nil {
		return "", errors.Wrap(err, "Error while create Role policy document")
	}

	roleDescription := fmt.Sprintf("OpenShift role for %s/%s", credReq.Spec.SecretRef.Namespace, credReq.Spec.SecretRef.Name)

	rolePolicy := createRolePolicy(awsProviderSpec.StatementEntries)

	switch generateOnly {
	case true:
		// Generate Role
		// Need to escape all the double quotes in the generated JSON rolePolicyDocument
		// so that the JSON text file is valid
		escapedRolePolicyDoc := strings.Replace(rolePolicyDocument, "\"", "\\\"", -1)
		roleJSON := fmt.Sprintf(roleTemplate, shortenedRoleName, escapedRolePolicyDoc, roleDescription)
		roleFilename := fmt.Sprintf(roleFilenameFormat, roleNum, roleName)
		roleFullPath := filepath.Join(targetDir, roleFilename)
		if err := saveToFile(roleDescription, roleFullPath, []byte(roleJSON)); err != nil {
			return "", errors.Wrap(err, "failed to save Role content JSON")
		}

		// Generate Role Policy
		escapedRolePolicy := strings.Replace(rolePolicy, "\"", "\\\"", -1)
		rolePolicyJSON := fmt.Sprintf(rolePolicyTemplate, shortenedRoleName, shortenedRoleName, escapedRolePolicy)
		rolePolicyFilename := fmt.Sprintf(rolePolicyFilenameFormat, roleNum, roleName)
		rolePolicyFullPath := filepath.Join(targetDir, rolePolicyFilename)
		if err := saveToFile(roleDescription, rolePolicyFullPath, []byte(rolePolicyJSON)); err != nil {
			return "", errors.Wrap(err, "failed to save Role Policy content JSON")
		}

		if err := writeCredReqSecret(credReq, targetDir, ""); err != nil {
			return "", errors.Wrap(err, "failed to save Secret for install manifests")
		}

		return "", nil

	default:
		var role *iam.Role
		outRole, err := awsClient.GetRole(&iam.GetRoleInput{
			RoleName: awssdk.String(shortenedRoleName),
		})

		if err != nil {
			var aerr awserr.Error
			if errors.As(err, &aerr) {
				switch aerr.Code() {
				case iam.ErrCodeNoSuchEntityException:

					roleOutput, err := awsClient.CreateRole(&iam.CreateRoleInput{
						RoleName:                 awssdk.String(shortenedRoleName),
						Description:              awssdk.String(roleDescription),
						AssumeRolePolicyDocument: awssdk.String(rolePolicyDocument),
						Tags: []*iam.Tag{
							{
								Key:   awssdk.String(fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, namePrefix)),
								Value: awssdk.String(ownedCcoctlAWSResourceTagValue),
							},
						},
					})
					if err != nil {
						return "", errors.Wrap(err, "Failed to create role")
					}

					role = roleOutput.Role
					log.Printf("Role %s created", *role.Arn)

				default:
					return "", err
				}

			}
		} else {
			role = outRole.Role
			log.Printf("Existing role %s found", *role.Arn)

			// TODO: implement idemponent apply/update for role
			_, err = awsClient.UpdateAssumeRolePolicy(&iam.UpdateAssumeRolePolicyInput{
				RoleName:       role.RoleName,
				PolicyDocument: awssdk.String(rolePolicyDocument),
			})
			if err != nil {
				return "", errors.Wrap(err, "Faled to update Role Policy")
			}
			log.Printf("Updated Role policy document for role %s", *role.RoleName)
		}

		_, err = awsClient.PutRolePolicy(&iam.PutRolePolicyInput{
			PolicyName:     awssdk.String(shortenedRoleName),
			RoleName:       role.RoleName,
			PolicyDocument: awssdk.String(rolePolicy),
		})
		if err != nil {
			return "", errors.Wrap(err, "Failed to put role policy")
		}
		log.Printf("Updated Role policy for Role %s", *role.RoleName)

		if err := writeCredReqSecret(credReq, targetDir, *role.Arn); err != nil {
			return "", errors.Wrap(err, "failed to save Secret for install manifests")
		}

		return *role.Arn, nil
	}
}

func createRolePolicyDocument(oidcProviderARN, issuerURL string, serviceAccountNames []string) (string, error) {
	var conditionString string
	if len(serviceAccountNames) > 0 {
		var serviceAccountListString string
		for i, sa := range serviceAccountNames {
			if i == 0 {
				serviceAccountListString = fmt.Sprintf(`[ "system:serviceaccount:%s:%s" `, sa, sa)
			} else {
				serviceAccountListString = fmt.Sprintf(`%s , "system:serviceaccount:%s:%s"`, serviceAccountListString, sa, sa)
			}
		}
		serviceAccountListString += " ]"

		conditionString = fmt.Sprintf(` { "StringEquals": { "%s:sub": %s } }`, issuerURL, serviceAccountListString)
	} else {
		// TODO: maybe return an error once all CredentialsRequest start including ServiceAccountNames
		conditionString = fmt.Sprintf(`{ "StringEquals": { "%s:aud": "openshift" } }`, issuerURL)
	}
	policy := fmt.Sprintf(rolePolicyDocmentTemplate, oidcProviderARN, conditionString)

	return policy, nil
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

func getIssuerURLFromIdentityProvider(awsClient aws.Client, idProviderARN string) (string, error) {
	idProvider, err := awsClient.GetOpenIDConnectProvider(&iam.GetOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: awssdk.String(idProviderARN),
	})

	if err != nil {
		return "", errors.Wrap(err, "failed to get IAM Identity Provider")
	}

	return *idProvider.Url, nil
}

func iamRolesCmd(cmd *cobra.Command, args []string) {
	cfg := &awssdk.Config{}

	s, err := session.NewSession(cfg)
	if err != nil {
		log.Fatal(err)
	}

	awsClient := aws.NewClientFromSession(s)

	err = createIAMRoles(awsClient, CreateOpts.IdentityProviderARN, CreateOpts.NamePrefix, CreateOpts.CredRequestDir, CreateOpts.TargetDir, CreateOpts.DryRun)
	if err != nil {
		log.Fatal(err)
	}
}

// StatementEntry is a simple type used to serialize to AWS' PolicyDocument format.
type StatementEntry struct {
	Effect   string
	Action   []string
	Resource string
	// Must "omitempty" otherwise we send unacceptable JSON to the AWS API when no
	// condition is defined.
	Condition credreqv1.IAMPolicyCondition `json:",omitempty"`
}

// PolicyDocument is a simple type used to serialize to AWS' PolicyDocument format.
type PolicyDocument struct {
	Version   string
	Statement []StatementEntry
}

func createRolePolicy(statements []credreqv1.StatementEntry) string {
	policyDocument := PolicyDocument{
		Version:   "2012-10-17",
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

	b, err := json.Marshal(&policyDocument)
	if err != nil {
		log.Fatalf("Failed to marshal the policy to JSON: %s", err)
	}

	return string(b)
}

// writeCredReqSecret will take a credentialsRequest and a Role ARN and store
// a Secret with an AWS config in the 'credentials' field of the Secret.
func writeCredReqSecret(cr *credreqv1.CredentialsRequest, targetDir, roleARN string) error {
	manifestsDir := filepath.Join(targetDir, manifestsDirName)

	fileName := fmt.Sprintf("%s-%s-credentials.yaml", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name)
	filePath := filepath.Join(manifestsDir, fileName)

	fileData := fmt.Sprintf(secretManifestsTemplate, roleARN, cr.Spec.SecretRef.Name, cr.Spec.SecretRef.Namespace)

	// roleARN would be an empty string if ccoctl was in --dry-run mode
	// so lets make sure we have an invalide Secret until the user
	// has populated the Secret manually.
	if roleARN == "" {
		fileData = fileData + "\nPOPULATE ROLE ARN AND DELETE THIS LINE"
	}

	if err := ioutil.WriteFile(filePath, []byte(fileData), 0600); err != nil {
		return errors.Wrap(err, "Failed to save Secret file")
	}

	log.Printf("Saved credentials configuration to: %s", filePath)

	return nil
}

// NewIAMRolesSetup provides the "create iam-roles" subcommand
func NewIAMRolesSetup() *cobra.Command {
	iamRolesSetupCmd := &cobra.Command{
		Use: "iam-roles",
		Run: iamRolesCmd,
	}

	iamRolesSetupCmd.PersistentFlags().StringVar(&CreateOpts.NamePrefix, "name-prefix", "", "User-define name prefix for all created AWS resources (can be separate from the cluster's infra-id)")
	iamRolesSetupCmd.MarkPersistentFlagRequired("name-prefix")
	iamRolesSetupCmd.PersistentFlags().StringVar(&CreateOpts.CredRequestDir, "credentials-requests-dir", "", "Directory containing files of CredentialsRequests to create IAM Roles for (can be created by running 'oc adm release extract --credentials-requests --cloud=aws' against an OpenShift release image)")
	iamRolesSetupCmd.MarkPersistentFlagRequired("credentials-requests-dir")
	iamRolesSetupCmd.PersistentFlags().StringVar(&CreateOpts.IdentityProviderARN, "identity-provider-arn", "", "ARN of IAM Identity provider for IAM Role trust relationship (can be created with the 'create identity-provider' sub-command)")
	iamRolesSetupCmd.MarkPersistentFlagRequired("identity-provider-arn")
	iamRolesSetupCmd.PersistentFlags().BoolVar(&CreateOpts.DryRun, "dry-run", false, "Skip creating objects, and just save what would have been created into files")

	return iamRolesSetupCmd
}
