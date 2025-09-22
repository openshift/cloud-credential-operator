package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/aws"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
)

const (
	rolePolicyDocmentTemplate = `{ "Version": "2012-10-17", "Statement": [ { "Effect": "Allow", "Principal": { "Federated": "%s" }, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": %s } ] }`

	secretManifestsTemplate = `apiVersion: v1
stringData:
  credentials: |-
    [default]
    sts_regional_endpoints = regional
    role_arn = %s
    web_identity_token_file = %s
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque`

	// Generated role files
	roleFilenameFormat       = "05-%d-%s-role.json"
	rolePolicyFilenameFormat = "06-%d-%s-policy.json"
	// fileModeCcoctlDryRun represents a mode and permission bits of the files created by ccoctl in dry run
	fileModeCcoctlDryRun = 0644
)

var (
	// CreateIAMRolesOpts captures the options that affect creation/updating
	// of the IAM Roles.
	CreateIAMRolesOpts = options{
		TargetDir:         "",
		EnableTechPreview: false,
	}
)

func createIAMRoles(client aws.Client, identityProviderARN, PermissionsBoundaryARN, name, credReqDir, targetDir string, enableTechPreview, generateOnly bool) error {
	// Process directory
	credRequests, err := provisioning.GetListOfCredentialsRequests(credReqDir, enableTechPreview)
	if err != nil {
		return errors.Wrap(err, "Failed to process files containing CredentialsRequests")
	}

	// Create IAM Roles (with policies)
	if err := processCredentialsRequests(client, credRequests, identityProviderARN, PermissionsBoundaryARN, name, targetDir, generateOnly); err != nil {
		return errors.Wrap(err, "Failed while processing each CredentialsRequest")
	}

	return nil
}

func processCredentialsRequests(awsClient aws.Client, credReqs []*credreqv1.CredentialsRequest, identityProviderARN, PermissionsBoundaryARN, name, targetDir string, generateOnly bool) error {

	issuerURL, err := getIssuerURLFromIdentityProvider(awsClient, identityProviderARN, generateOnly)
	if err != nil {
		return err
	}

	for i, cr := range credReqs {
		// infraName-targetNamespace-targetSecretName
		_, err = createRole(awsClient, name, cr, i, identityProviderARN, issuerURL, PermissionsBoundaryARN, targetDir, generateOnly)
		if err != nil {
			return err
		}

	}
	return nil
}

func createRole(awsClient aws.Client, name string, credReq *credreqv1.CredentialsRequest, roleNum int, oidcProviderARN, issuerURL, PermissionsBoundaryARN, targetDir string, generateOnly bool) (string, error) {
	roleName := fmt.Sprintf("%s-%s-%s", name, credReq.Spec.SecretRef.Namespace, credReq.Spec.SecretRef.Name)

	// Decode AWSProviderSpec
	awsProviderSpec := credreqv1.AWSProviderSpec{}
	if err := credreqv1.Codec.DecodeProviderSpec(credReq.Spec.ProviderSpec, &awsProviderSpec); err != nil {
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

	rolePolicyDocument, err := createRolePolicyDocument(oidcProviderARN, issuerURL, credReq.Spec.SecretRef.Namespace, credReq.Spec.ServiceAccountNames)
	if err != nil {
		return "", errors.Wrapf(err, "error while creating Role policy document for %s", credReq.Name)
	}

	roleDescription := fmt.Sprintf("OpenShift role for %s/%s", credReq.Spec.SecretRef.Namespace, credReq.Spec.SecretRef.Name)

	rolePolicy := createRolePolicy(awsProviderSpec.StatementEntries)

	switch generateOnly {
	case true:
		// Generate Role
		// Generated JSON must be valid input for AWS IAM CreateRole API
		roleTemplate := map[string]interface{}{
			"RoleName":                 shortenedRoleName,
			"Description":              roleDescription,
			"AssumeRolePolicyDocument": rolePolicyDocument,
			"Tags": []map[string]string{
				{
					"Key":   fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, name),
					"Value": ownedCcoctlAWSResourceTagValue,
				},
				{
					"Key":   nameTagKey,
					"Value": name,
				},
			},
		}
		if PermissionsBoundaryARN != "" {
			roleTemplate["PermissionsBoundary"] = PermissionsBoundaryARN
		}
		roleJSON, err := json.Marshal(&roleTemplate)
		if err != nil {
			return "", errors.Wrap(err, "failed to convert Role to JSON")
		}
		roleFilename := fmt.Sprintf(roleFilenameFormat, roleNum, roleName)
		roleFullPath := filepath.Join(targetDir, roleFilename)
		log.Printf("Saving %s locally at %s", roleDescription, roleFullPath)
		if err := ioutil.WriteFile(roleFullPath, roleJSON, fileModeCcoctlDryRun); err != nil {
			return "", errors.Wrap(err, fmt.Sprintf("Failed to save %s locally at %s", roleDescription, roleFullPath))
		}

		// Generate Role Policy
		// Generated JSON must be valid input for AWS IAM PutRolePolicy API
		rolePolicyTemplate := map[string]string{
			"PolicyDocument": rolePolicy,
			"PolicyName":     shortenedRoleName,
			"RoleName":       shortenedRoleName,
		}
		rolePolicyJSON, err := json.Marshal(&rolePolicyTemplate)
		if err != nil {
			return "", errors.Wrap(err, "failed to convert Role Policy to JSON")
		}
		rolePolicyFilename := fmt.Sprintf(rolePolicyFilenameFormat, roleNum, roleName)
		rolePolicyFullPath := filepath.Join(targetDir, rolePolicyFilename)
		log.Printf("Saving policy for %s locally at %s", roleDescription, rolePolicyFullPath)
		if err := ioutil.WriteFile(rolePolicyFullPath, rolePolicyJSON, fileModeCcoctlDryRun); err != nil {
			return "", errors.Wrap(err, fmt.Sprintf("Failed to save policy for %s locally at %s", roleDescription, rolePolicyFullPath))
		}

		if err := writeCredReqSecret(credReq, targetDir, ""); err != nil {
			return "", errors.Wrap(err, "failed to save Secret for install manifests")
		}

		return "", nil

	default:
		var role *iamtypes.Role
		outRole, err := awsClient.GetRole(context.Background(), &iam.GetRoleInput{
			RoleName: awssdk.String(shortenedRoleName),
		})

		if err != nil {
			var aerr *iamtypes.NoSuchEntityException
			if !errors.As(err, &aerr) {
				return "", err
			}
			roleInput := &iam.CreateRoleInput{
				RoleName:                 awssdk.String(shortenedRoleName),
				Description:              awssdk.String(roleDescription),
				AssumeRolePolicyDocument: awssdk.String(rolePolicyDocument),
				Tags: []iamtypes.Tag{
					{
						Key:   awssdk.String(fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, name)),
						Value: awssdk.String(ownedCcoctlAWSResourceTagValue),
					},
					{
						Key:   awssdk.String(nameTagKey),
						Value: awssdk.String(name),
					},
				},
			}
			if PermissionsBoundaryARN != "" {
				roleInput.PermissionsBoundary = awssdk.String(PermissionsBoundaryARN)
			}
			roleOutput, err := awsClient.CreateRole(context.Background(), roleInput)
			if err != nil {
				return "", errors.Wrap(err, "Failed to create role")
			}

			role = roleOutput.Role
			log.Printf("Role %s created", *role.Arn)

			if err := writeCredReqSecret(credReq, targetDir, *role.Arn); err != nil {
				return "", errors.Wrap(err, "failed to save Secret for install manifests")
			}
		} else {
			role = outRole.Role
			log.Printf("Existing role %s found", *role.Arn)
			// Write secret manifest when the role already exists
			// https://issues.redhat.com/browse/CCO-335
			if err := writeCredReqSecret(credReq, targetDir, *role.Arn); err != nil {
				return "", errors.Wrap(err, "failed to save Secret for install manifests")
			}
		}

		_, err = awsClient.PutRolePolicy(context.Background(), &iam.PutRolePolicyInput{
			PolicyName:     awssdk.String(shortenedRoleName),
			RoleName:       role.RoleName,
			PolicyDocument: awssdk.String(rolePolicy),
		})
		if err != nil {
			return "", errors.Wrap(err, "Failed to put role policy")
		}
		log.Printf("Updated Role policy for Role %s", *role.RoleName)

		return *role.Arn, nil
	}
}

func createRolePolicyDocument(oidcProviderARN, issuerURL, namespace string, serviceAccountNames []string) (string, error) {
	var conditionString string
	if len(serviceAccountNames) > 0 {
		var serviceAccountListString string
		for i, sa := range serviceAccountNames {
			if i == 0 {
				serviceAccountListString = fmt.Sprintf(`[ "system:serviceaccount:%s:%s" `, namespace, sa)
			} else {
				serviceAccountListString = fmt.Sprintf(`%s , "system:serviceaccount:%s:%s"`, serviceAccountListString, namespace, sa)
			}
		}
		serviceAccountListString += " ]"

		conditionString = fmt.Sprintf(` { "StringEquals": { "%s:sub": %s } }`, issuerURL, serviceAccountListString)
	} else {
		// TODO: maybe return an error once all CredentialsRequest start including ServiceAccountNames
		// We used to support leaving the list of ServiceAccounts blank in the CredentialsRequest while
		// we transitioned all the existing CredReqs. That work is complete, and we should not
		// create Role policies that limit the Role by audience any more.
		// Return an error indicating that ccoctl requires the ServiceAccount list to be populated.
		return "", fmt.Errorf("CredentialsRequest must provide ServieAccounts to bind the Role policy to")
	}
	policy := fmt.Sprintf(rolePolicyDocmentTemplate, oidcProviderARN, conditionString)

	return policy, nil
}

func getIssuerURLFromIdentityProvider(awsClient aws.Client, idProviderARN string, dryRun bool) (string, error) {
	if dryRun {
		return "<enter_issuer_url_here>", nil
	}

	idProvider, err := awsClient.GetOpenIDConnectProvider(context.Background(), &iam.GetOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: awssdk.String(idProviderARN),
	})

	if err != nil {
		return "", errors.Wrap(err, "failed to get IAM Identity Provider")
	}

	return *idProvider.Url, nil
}

func createIAMRolesCmd(cmd *cobra.Command, args []string) {
	awsClient, err := newAWSClient(CreateAllOpts.Region)
	if err != nil {
		log.Fatal(err)
	}

	err = createIAMRoles(awsClient, CreateIAMRolesOpts.IdentityProviderARN, CreateIAMRolesOpts.PermissionsBoundaryARN, CreateIAMRolesOpts.Name,
		CreateIAMRolesOpts.CredRequestDir, CreateIAMRolesOpts.TargetDir, CreateIAMRolesOpts.EnableTechPreview, CreateIAMRolesOpts.DryRun)
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
	manifestsDir := filepath.Join(targetDir, provisioning.ManifestsDirName)

	fileName := fmt.Sprintf("%s-%s-credentials.yaml", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name)
	filePath := filepath.Join(manifestsDir, fileName)

	fileData := fmt.Sprintf(secretManifestsTemplate, roleARN, provisioning.OidcTokenPath, cr.Spec.SecretRef.Name, cr.Spec.SecretRef.Namespace)

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

// initEnvForCreateIAMRolesCmd will ensure the destination directory is ready to receive the generated
// files, and will create the directory if necessary.
func initEnvForCreateIAMRolesCmd(cmd *cobra.Command, args []string) {
	if CreateIAMRolesOpts.TargetDir == "" {
		pwd, err := os.Getwd()
		if err != nil {
			log.Fatalf("Failed to get current directory: %s", err)
		}

		CreateIAMRolesOpts.TargetDir = pwd
	}

	fPath, err := filepath.Abs(CreateIAMRolesOpts.TargetDir)
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

// NewCreateIAMRolesCmd provides the "create-iam-roles" subcommand
func NewCreateIAMRolesCmd() *cobra.Command {
	createIAMRolesCmd := &cobra.Command{
		Use:              "create-iam-roles",
		Short:            "Create IAM roles",
		Run:              createIAMRolesCmd,
		PersistentPreRun: initEnvForCreateIAMRolesCmd,
	}

	createIAMRolesCmd.PersistentFlags().StringVar(&CreateIAMRolesOpts.Name, "name", "", "User-define name for all created AWS resources (can be separate from the cluster's infra-id)")
	createIAMRolesCmd.MarkPersistentFlagRequired("name")
	createIAMRolesCmd.PersistentFlags().StringVar(&CreateIAMRolesOpts.CredRequestDir, "credentials-requests-dir", "", "Directory containing files of CredentialsRequests to create IAM Roles for (can be created by running 'oc adm release extract --credentials-requests --cloud=aws' against an OpenShift release image)")
	createIAMRolesCmd.MarkPersistentFlagRequired("credentials-requests-dir")
	createIAMRolesCmd.PersistentFlags().StringVar(&CreateIAMRolesOpts.IdentityProviderARN, "identity-provider-arn", "", "ARN of IAM Identity provider for IAM Role trust relationship (can be created with the 'create identity-provider' sub-command)")
	createIAMRolesCmd.MarkPersistentFlagRequired("identity-provider-arn")
	createIAMRolesCmd.PersistentFlags().StringVar(&CreateIAMRolesOpts.PermissionsBoundaryARN, "permissions-boundary-arn", "", "ARN of IAM policy to use as the permissions boundary for created roles")
	createIAMRolesCmd.PersistentFlags().StringVar(&CreateIAMRolesOpts.Region, "region", "", "AWS region endpoint only required for GovCloud")
	createIAMRolesCmd.PersistentFlags().BoolVar(&CreateIAMRolesOpts.DryRun, "dry-run", false, "Skip creating objects, and just save what would have been created into files")
	createIAMRolesCmd.PersistentFlags().StringVar(&CreateIAMRolesOpts.TargetDir, "output-dir", "", "Directory to place generated files (defaults to current directory)")
	createIAMRolesCmd.PersistentFlags().BoolVar(&CreateIAMRolesOpts.EnableTechPreview, "enable-tech-preview", false, "Opt into processing CredentialsRequests marked as tech-preview")

	return createIAMRolesCmd
}
