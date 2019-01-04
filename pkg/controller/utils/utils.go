package utils

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	ccv1beta1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1beta1"
	ccaws "github.com/openshift/cloud-credential-operator/pkg/aws"
	"github.com/openshift/cloud-credential-operator/pkg/controller/assets"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

// credMintingActions is a list of AWS verbs needed to run in the mode where the
// cloud-credential-operator can mint new creds to satisfy CredentialRequest CRDs
var (
	CredMintingActions = []string{
		"iam:CreateAccessKey",
		"iam:CreateUser",
		"iam:DeleteAccessKey",
		"iam:DeleteUser",
		"iam:DeleteUserPolicy",
		"iam:GetUser",
		"iam:ListAccessKeys",
		"iam:PutUserPolicy",
		"iam:TagUser",
	}

	credentailRequestScheme = runtime.NewScheme()
	credentialRequestCodec  = serializer.NewCodecFactory(credentailRequestScheme)
)

func init() {
	if err := ccv1beta1.AddToScheme(credentailRequestScheme); err != nil {
		panic(err)
	}
}

// CheckCloudCredCreation will see whether we have enough permissions to create new sub-creds
func CheckCloudCredCreation(awsClient ccaws.Client, logger log.FieldLogger) (bool, error) {
	return checkCreateCredPermissions(awsClient, CredMintingActions, logger)
}

// checkPermissionsAgainstStatementList will test to see whether the list of actions in the provided
// list of StatementEntries can work with the credentials used by the passed-in awsClient
func checkPermissionsAgainstStatementList(awsClient ccaws.Client, statementEntries []ccv1beta1.StatementEntry, logger log.FieldLogger) (bool, error) {
	currentUsername, err := awsClient.GetUser(nil)
	if err != nil {
		return false, fmt.Errorf("error querying current username: %v", err)
	}

	allowList := []*string{}
	// FIXME: Assuming only 'Allow's in the statement list
	for _, statement := range statementEntries {
		for _, action := range statement.Action {
			allowList = append(allowList, aws.String(action))
		}
	}

	// Check whether the current creds can perform the list of actions
	// (assumes Resource: "*")
	results, err := awsClient.SimulatePrincipalPolicy(&iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: currentUsername.User.Arn,
		ActionNames:     allowList,
	})
	if err != nil {
		return false, fmt.Errorf("error simulating policy: %v", err)
	}

	// Either they are all allowed and we return 'true', or it's a failure
	allClear := true
	for _, result := range results.EvaluationResults {
		if *result.EvalDecision != "allowed" {
			// Don't return on the first failure, so we can log the full list
			// of failed/denied actions
			logger.Warningf("Action not allowed with tested creds: %v", *result.EvalActionName)
			allClear = false
		}
	}

	if !allClear {
		logger.Warningf("Tested creds not able to perform all requested actions")
		return false, nil
	}

	return true, nil
}

// checkCreateCredPermissions will take the static list of Actions needed to run in
// cred-minting mode and see if the provided awsClient creds
func checkCreateCredPermissions(awsClient ccaws.Client, actionList []string, logger log.FieldLogger) (bool, error) {
	statementList := []ccv1beta1.StatementEntry{
		{
			Action:   actionList,
			Resource: "*",
			Effect:   "Allow",
		},
	}

	return checkPermissionsAgainstStatementList(awsClient, statementList, logger)
}

// CheckCloudCredPassthrough will see if the provided creds are good enough to pass through
// to other components as-is based on the generated list of permissions needed from the static
// manifests in the repo
func CheckCloudCredPassthrough(awsClient ccaws.Client, logger log.FieldLogger) (bool, error) {
	statementList := []ccv1beta1.StatementEntry{}

	// Read in the static assets containing all the needed CredentialRequests/permissions
	assetList := assets.AssetNames()
	for _, oneAsset := range assetList {
		crBytes, err := assets.Asset(oneAsset)
		if err != nil {
			return false, fmt.Errorf("error parsing CredentialRequest object: %v", err)
		}

		statements, err := getCredentialRequestStatements(crBytes)
		if err != nil {
			return false, fmt.Errorf("error processing CredentialRequest: %v", err)
		}

		statementList = append(statementList, statements...)
	}

	return checkPermissionsAgainstStatementList(awsClient, statementList, logger)
}

func readCredentialRequest(cr []byte) (*ccv1beta1.CredentialsRequest, error) {

	newObj, err := runtime.Decode(credentialRequestCodec.UniversalDecoder(ccv1beta1.SchemeGroupVersion), cr)
	if err != nil {
		return nil, fmt.Errorf("error decoding credentialrequest: %v", err)
	}
	return newObj.(*ccv1beta1.CredentialsRequest), nil
}

func getCredentialRequestStatements(crBytes []byte) ([]ccv1beta1.StatementEntry, error) {
	statementList := []ccv1beta1.StatementEntry{}

	awsCodec, err := ccv1beta1.NewCodec()
	if err != nil {
		return statementList, fmt.Errorf("error creating credentialrequest codec: %v", err)
	}

	cr, err := readCredentialRequest(crBytes)
	if err != nil {
		return statementList, err
	}

	awsSpec, err := awsCodec.DecodeProviderSpec(cr.Spec.ProviderSpec, &ccv1beta1.AWSProviderSpec{})
	if err != nil {
		return statementList, fmt.Errorf("error decoding spec.ProviderSpec: %v", err)
	}

	statementList = append(statementList, awsSpec.StatementEntries...)

	return statementList, nil
}
