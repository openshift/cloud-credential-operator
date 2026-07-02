package aws

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"k8s.io/apimachinery/pkg/runtime"
)

const (
	// InfraResourceTagKeyPrefix is the IAM policy condition key prefix used to scope
	// actions to resources tagged with a cluster's infrastructure ID.
	InfraResourceTagKeyPrefix = "aws:ResourceTag/kubernetes.io/cluster/"

	// InfraResourceTagValue is the expected tag value for cluster-owned resources.
	InfraResourceTagValue = "owned"
)

// credMintingActions is a list of AWS verbs needed to run in the mode where the
// cloud-credential-operator can mint new creds to satisfy CredentialRequest CRDs
var (
	credMintingActions = []string{
		"iam:CreateAccessKey",
		"iam:CreateUser",
		"iam:DeleteAccessKey",
		"iam:DeleteUser",
		"iam:DeleteUserPolicy",
		"iam:GetUser",
		"iam:GetUserPolicy",
		"iam:ListAccessKeys",
		"iam:PutUserPolicy",
		"iam:TagUser",
		"iam:SimulatePrincipalPolicy", // needed so we can verify the above list of course
	}

	credPassthroughActions = []string{
		// so we can query whether we have the below list of creds
		"iam:GetUser",
		"iam:SimulatePrincipalPolicy",

		// openshift-ingress
		"elasticloadbalancing:DescribeLoadBalancers",
		"route53:ListHostedZones",
		"route53:ChangeResourceRecordSets",
		"tag:GetResources",

		// openshift-image-registry
		"s3:CreateBucket",
		"s3:DeleteBucket",
		"s3:PutBucketTagging",
		"s3:GetBucketTagging",
		"s3:PutEncryptionConfiguration",
		"s3:GetEncryptionConfiguration",
		"s3:PutLifecycleConfiguration",
		"s3:GetLifecycleConfiguration",
		"s3:GetBucketLocation",
		"s3:ListBucket",
		"s3:GetObject",
		"s3:PutObject",
		"s3:DeleteObject",
		"s3:ListBucketMultipartUploads",
		"s3:AbortMultipartUpload",

		// openshift-cluster-api
		"ec2:DescribeImages",
		"ec2:DescribeVpcs",
		"ec2:DescribeSubnets",
		"ec2:DescribeAvailabilityZones",
		"ec2:DescribeSecurityGroups",
		"ec2:RunInstances",
		"ec2:DescribeInstances",
		"ec2:TerminateInstances",
		"elasticloadbalancing:RegisterInstancesWithLoadBalancer",
		"elasticloadbalancing:DescribeLoadBalancers",
		"elasticloadbalancing:DescribeTargetGroups",
		"elasticloadbalancing:RegisterTargets",
		"ec2:DescribeVpcs",
		"ec2:DescribeSubnets",
		"ec2:DescribeAvailabilityZones",
		"ec2:DescribeSecurityGroups",
		"ec2:RunInstances",
		"ec2:DescribeInstances",
		"ec2:TerminateInstances",
		"elasticloadbalancing:RegisterInstancesWithLoadBalancer",
		"elasticloadbalancing:DescribeLoadBalancers",
		"elasticloadbalancing:DescribeTargetGroups",
		"elasticloadbalancing:RegisterTargets",

		// iam-ro
		"iam:GetUser",
		"iam:GetUserPolicy",
		"iam:ListAccessKeys",
	}

	// infraResourceTagScopedActions is the set of AWS actions for which the
	// aws:ResourceTag condition is known to work. Only these actions get the
	// cluster-scoping condition added to their Allow statements. Actions not
	// in this set are either known-incompatible (Describe/List/Create/S3/IAM/
	// Route53) or unrecognized. Unrecognized actions cause an error at policy
	// generation time.
	//
	// This list was compiled by cross-referencing every action in the
	// OpenShift payload's CredentialsRequests against the AWS Service
	// Authorization Reference (docs.aws.amazon.com/service-authorization).
	//
	// To update this list, file a bug against openshift/cloud-credential-operator
	// and modify this map in pkg/aws/utils.go.
	infraResourceTagScopedActions = map[string]bool{
		// EC2 — actions on existing, cluster-owned tagged resources
		"ec2:AttachVolume":                    true,
		"ec2:CreateSnapshot":                  true,
		"ec2:DeleteSnapshot":                  true,
		"ec2:DeleteVolume":                    true,
		"ec2:DetachVolume":                    true,
		"ec2:EnableFastSnapshotRestores":      true,
		"ec2:ModifyNetworkInterfaceAttribute": true,
		"ec2:ModifyVolume":                    true,
		"ec2:ReleaseHosts":                    true,
		"ec2:TerminateInstances":              true,
		// ELB — mutating actions on tagged resources
		"elasticloadbalancing:DeregisterTargets":                 true,
		"elasticloadbalancing:RegisterInstancesWithLoadBalancer": true,
		"elasticloadbalancing:RegisterTargets":                   true,
		// KMS — all actions on the key resource type support ResourceTag
		"kms:CreateGrant":                     true,
		"kms:Decrypt":                         true,
		"kms:DescribeKey":                     true,
		"kms:Encrypt":                         true,
		"kms:GenerateDataKey":                 true,
		"kms:GenerateDataKeyWithoutPlainText": true,
		"kms:ListGrants":                      true,
		"kms:ReEncrypt*":                      true,
		"kms:ReEncryptFrom":                   true,
		"kms:ReEncryptTo":                     true,
		"kms:RevokeGrant":                     true,
	}

	// infraResourceTagUnscopedActions is the set of AWS actions known to be
	// incompatible with the aws:ResourceTag condition. These are kept
	// separate from the scoped set so that unknown actions can be detected
	// (an action in neither set triggers an error).
	infraResourceTagUnscopedActions = map[string]bool{
		// EC2 — Describe/List (no resource-level permissions)
		"ec2:DescribeAvailabilityZones":         true,
		"ec2:DescribeCapacityReservations":      true,
		"ec2:DescribeDhcpOptions":               true,
		"ec2:DescribeImages":                    true,
		"ec2:DescribeInstanceStatus":            true,
		"ec2:DescribeInstanceTypeOfferings":     true,
		"ec2:DescribeInstanceTypes":             true,
		"ec2:DescribeInstances":                 true,
		"ec2:DescribeInternetGateways":          true,
		"ec2:DescribeLaunchTemplates":           true,
		"ec2:DescribeNetworkInterfaceAttribute": true,
		"ec2:DescribeNetworkInterfaces":         true,
		"ec2:DescribeRegions":                   true,
		"ec2:DescribeSecurityGroups":            true,
		"ec2:DescribeSnapshots":                 true,
		"ec2:DescribeSpotPriceHistory":          true,
		"ec2:DescribeSubnets":                   true,
		"ec2:DescribeTags":                      true,
		"ec2:DescribeVolumes":                   true,
		"ec2:DescribeVolumesModifications":      true,
		"ec2:DescribeVpcs":                      true,
		// EC2 — tagging actions must be unscoped: they are used to apply the
		// cluster ownership tag to newly created resources that do not yet carry
		// it, so an aws:ResourceTag condition is unsatisfiable at call time.
		"ec2:CreateTags": true,
		"ec2:DeleteTags": true,
		// EC2 — ENI IP assignment actions target network interfaces that
		// are not tagged with the cluster ownership tag.
		"ec2:AssignIpv6Addresses":        true,
		"ec2:AssignPrivateIpAddresses":   true,
		"ec2:UnassignIpv6Addresses":      true,
		"ec2:UnassignPrivateIpAddresses": true,
		// EC2 — Create/Delete for fleet resources (not cluster-tagged)
		"ec2:AllocateHosts":        true,
		"ec2:CreateFleet":          true,
		"ec2:CreateLaunchTemplate": true,
		"ec2:CreateVolume":         true,
		"ec2:DeleteLaunchTemplate": true,
		"ec2:RunInstances":         true,
		// S3 — none support aws:ResourceTag
		"s3:AbortMultipartUpload":       true,
		"s3:CreateBucket":               true,
		"s3:DeleteBucket":               true,
		"s3:DeleteObject":               true,
		"s3:GetBucketLocation":          true,
		"s3:GetBucketPublicAccessBlock": true,
		"s3:GetBucketTagging":           true,
		"s3:GetEncryptionConfiguration": true,
		"s3:GetLifecycleConfiguration":  true,
		"s3:GetObject":                  true,
		"s3:ListBucket":                 true,
		"s3:ListBucketMultipartUploads": true,
		"s3:ListMultipartUploadParts":   true,
		"s3:PutBucketPublicAccessBlock": true,
		"s3:PutBucketTagging":           true,
		"s3:PutEncryptionConfiguration": true,
		"s3:PutLifecycleConfiguration":  true,
		"s3:PutObject":                  true,
		// ELB — Describe (no resource-level permissions)
		"elasticloadbalancing:DescribeLoadBalancers": true,
		"elasticloadbalancing:DescribeTargetGroups":  true,
		"elasticloadbalancing:DescribeTargetHealth":  true,
		// IAM — none of these support aws:ResourceTag
		"iam:AddRoleToInstanceProfile":      true,
		"iam:CreateInstanceProfile":         true,
		"iam:CreateServiceLinkedRole":       true,
		"iam:DeleteInstanceProfile":         true,
		"iam:GetInstanceProfile":            true,
		"iam:GetUser":                       true,
		"iam:GetUserPolicy":                 true,
		"iam:ListAccessKeys":                true,
		"iam:ListInstanceProfiles":          true,
		"iam:PassRole":                      true,
		"iam:RemoveRoleFromInstanceProfile": true,
		"iam:TagInstanceProfile":            true,
		// Route53 — none support aws:ResourceTag
		"route53:ChangeResourceRecordSets": true,
		"route53:ListHostedZones":          true,
		"route53:ListTagsForResources":     true,
		// STS — AssumeRole does not support aws:ResourceTag
		"sts:AssumeRole": true,
		// Pricing API — no resource-level permissions
		"pricing:GetProducts": true,
		// SSM — parameter is not cluster-owned
		"ssm:GetParameter": true,
		// Resource Groups Tagging API
		"tag:GetResources": true,
	}

	credentailRequestScheme = runtime.NewScheme()
)

func init() {
	if err := minterv1.AddToScheme(credentailRequestScheme); err != nil {
		panic(err)
	}
}

// SupportsInfraResourceTagCondition checks whether an AWS action supports the
// aws:ResourceTag condition for cluster-scoped policy enforcement. Returns:
//   - (true, nil) if the action is in the allowlist
//   - (false, nil) if the action is known-incompatible
//   - (false, error) if the action is unrecognized
func SupportsInfraResourceTagCondition(action string) (bool, error) {
	if infraResourceTagScopedActions[action] {
		return true, nil
	}
	if infraResourceTagUnscopedActions[action] {
		return false, nil
	}
	return false, fmt.Errorf(
		"unrecognized AWS action %q has no aws:ResourceTag classification; "+
			"file a bug against openshift/cloud-credential-operator to add it "+
			"to infraResourceTagScopedActions or infraResourceTagUnscopedActions "+
			"in pkg/aws/utils.go", action)
}

// SimulateParams captures any additional details that should be used
// when simulating permissions.
type SimulateParams struct {
	Region string
}

// CheckCloudCredCreation will see whether we have enough permissions to create new sub-creds
func CheckCloudCredCreation(ctx context.Context, awsClient Client, logger log.FieldLogger) (bool, error) {
	// Empty SimulateParams{} b/c creating IAM users and assigning policies
	// are all IAM API alls which are not region-specific
	return CheckPermissionsAgainstActions(ctx, awsClient, credMintingActions, &SimulateParams{}, logger)
}

// getClientDetails will return the *iam.User associated with the provided client's credentials,
// a boolean indicating whether the user is the 'root' account, and any error encountered
// while trying to gather the info.
func getClientDetails(ctx context.Context, awsClient Client) (*iamtypes.User, bool, error) {
	rootUser := false

	user, err := awsClient.GetUser(ctx, &iam.GetUserInput{})
	if err != nil {
		return nil, rootUser, fmt.Errorf("error querying username: %v", err)
	}

	// Detect whether the AWS account's root user is being used
	parsed, err := arn.Parse(*user.User.Arn)
	if err != nil {
		return nil, rootUser, fmt.Errorf("error parsing user's ARN: %v", err)
	}
	if parsed.AccountID == *user.User.UserId {
		rootUser = true
	}

	return user.User, rootUser, nil
}

// CheckPermissionsUsingQueryClient will use queryClient to query whether the credentials in targetClient can perform the actions
// listed in the statementEntries. queryClient will need iam:GetUser and iam:SimulatePrincipalPolicy
func CheckPermissionsUsingQueryClient(ctx context.Context, queryClient, targetClient Client, statementEntries []minterv1.StatementEntry,
	params *SimulateParams, logger log.FieldLogger) (bool, error) {
	targetUser, isRoot, err := getClientDetails(ctx, targetClient)
	if err != nil {
		return false, fmt.Errorf("error gathering AWS credentials details: %v", err)
	}
	if isRoot {
		// warn about using the root creds, and just return that the creds are good enough
		logger.Warn("Using the AWS account root user is not recommended: https://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html")
		return true, nil
	}

	allowList := []string{}
	for _, statement := range statementEntries {
		allowList = append(allowList, statement.Action...)
	}

	input := &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: targetUser.Arn,
		ActionNames:     allowList,
		ContextEntries:  []iamtypes.ContextEntry{},
	}

	if params != nil {
		if params.Region != "" {
			input.ContextEntries = append(input.ContextEntries, iamtypes.ContextEntry{
				ContextKeyName:   awssdk.String("aws:RequestedRegion"),
				ContextKeyType:   iamtypes.ContextKeyTypeEnumString,
				ContextKeyValues: []string{params.Region},
			})
		}
		// NOTE: We intentionally do NOT inject aws:ResourceTag context here.
		// The simulation validates base IAM permissions, not minted policy
		// conditions. Injecting the tag makes create-action simulations
		// falsely pass (the resource doesn't exist yet at call time).
	}

	// Either all actions are allowed and we'll return 'true', or it's a failure
	allClear := true

	paginator := iam.NewSimulatePrincipalPolicyPaginator(queryClient, input)
	for paginator.HasMorePages() {
		response, err := paginator.NextPage(ctx)
		if err != nil {
			return false, fmt.Errorf("error simulating policy: %v", err)
		}

		for _, result := range response.EvaluationResults {
			if result.EvalDecision != iamtypes.PolicyEvaluationDecisionTypeAllowed {
				// Don't bail out after the first failure, so we can log the full list
				// of failed/denied actions
				logger.WithField("action", *result.EvalActionName).Warning("Action not allowed with tested creds")
				allClear = false
			}
		}
	}

	if !allClear {
		logger.Warningf("Tested creds not able to perform all requested actions")
		return false, nil
	}

	return true, nil

}

// CheckPermissionsAgainstStatementList will test to see whether the list of actions in the provided
// list of StatementEntries can work with the credentials used by the passed-in awsClient
func CheckPermissionsAgainstStatementList(ctx context.Context, awsClient Client, statementEntries []minterv1.StatementEntry,
	params *SimulateParams, logger log.FieldLogger) (bool, error) {
	return CheckPermissionsUsingQueryClient(ctx, awsClient, awsClient, statementEntries, params, logger)
}

// CheckPermissionsAgainstActions will take the static list of Actions to check whether the provided
// awsClient creds have sufficient permissions to perform the actions.
// Will return true/false indicating whether the permissions are sufficient.
func CheckPermissionsAgainstActions(ctx context.Context, awsClient Client, actionList []string, params *SimulateParams, logger log.FieldLogger) (bool, error) {
	statementList := []minterv1.StatementEntry{
		{
			Action:   actionList,
			Resource: "*",
			Effect:   "Allow",
		},
	}

	return CheckPermissionsAgainstStatementList(ctx, awsClient, statementList, params, logger)
}

// CheckCloudCredPassthrough will see if the provided creds are good enough to pass through
// to other components as-is based on the static list of permissions needed by the various
// users of CredentialsRequests
// TODO: move away from static list (to dynamic passthrough validation?)
func CheckCloudCredPassthrough(ctx context.Context, awsClient Client, params *SimulateParams, logger log.FieldLogger) (bool, error) {
	return CheckPermissionsAgainstActions(ctx, awsClient, credPassthroughActions, params, logger)
}
