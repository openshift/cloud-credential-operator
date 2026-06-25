package aws

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// payloadAWSAction pairs an action string from a payload CredentialsRequest
// with its expected scoping classification (true = scoped, false = unscoped).
type payloadAWSAction struct {
	action string
	scoped bool
}

// payloadAWSActions is the complete set of AWS IAM actions used in
// CredentialsRequest manifests across the OpenShift payload. Every action
// listed here must be classified in either infraResourceTagScopedActions or
// infraResourceTagUnscopedActions. If a new CredentialsRequest adds an
// action not on this list, add it here AND to the appropriate map in
// utils.go.
//
// Source: grep -r '"action"' across all openshift/*-operator
// CredentialsRequest manifests in the payload.
var payloadAWSActions = []payloadAWSAction{
	// aws-ebs-csi-driver-operator / openshift-machine-api-aws (shared)
	{"ec2:AttachVolume", true},
	{"ec2:CreateSnapshot", true},
	{"ec2:CreateTags", false},
	{"ec2:CreateVolume", false},
	{"ec2:DeleteSnapshot", true},
	{"ec2:DeleteTags", false},
	{"ec2:DeleteVolume", true},
	{"ec2:DescribeInstances", false},
	{"ec2:DescribeSnapshots", false},
	{"ec2:DescribeTags", false},
	{"ec2:DescribeVolumes", false},
	{"ec2:DescribeVolumesModifications", false},
	{"ec2:DetachVolume", true},
	{"ec2:ModifyVolume", true},
	{"ec2:DescribeAvailabilityZones", false},
	{"ec2:EnableFastSnapshotRestores", true},
	{"kms:ReEncrypt*", true},
	{"kms:Decrypt", true},
	{"kms:Encrypt", true},
	{"kms:GenerateDataKey", true},
	{"kms:GenerateDataKeyWithoutPlainText", true},
	{"kms:DescribeKey", true},
	{"kms:RevokeGrant", true},
	{"kms:CreateGrant", true},
	{"kms:ListGrants", true},

	// openshift-machine-api-aws
	{"ec2:AllocateHosts", false},
	{"ec2:CreateFleet", false},
	{"ec2:CreateLaunchTemplate", false},
	{"ec2:DeleteLaunchTemplate", false},
	{"ec2:DescribeCapacityReservations", false},
	{"ec2:DescribeDhcpOptions", false},
	{"ec2:DescribeImages", false},
	{"ec2:DescribeInstanceTypeOfferings", false},
	{"ec2:DescribeInstanceTypes", false},
	{"ec2:DescribeInternetGateways", false},
	{"ec2:DescribeLaunchTemplates", false},
	{"ec2:DescribeSecurityGroups", false},
	{"ec2:DescribeRegions", false},
	{"ec2:DescribeSpotPriceHistory", false},
	{"ec2:DescribeSubnets", false},
	{"ec2:DescribeVpcs", false},
	{"ec2:ReleaseHosts", true},
	{"ec2:RunInstances", false},
	{"ec2:TerminateInstances", true},
	{"elasticloadbalancing:DescribeLoadBalancers", false},
	{"elasticloadbalancing:DescribeTargetGroups", false},
	{"elasticloadbalancing:DescribeTargetHealth", false},
	{"elasticloadbalancing:RegisterInstancesWithLoadBalancer", true},
	{"elasticloadbalancing:RegisterTargets", true},
	{"elasticloadbalancing:DeregisterTargets", true},
	{"iam:AddRoleToInstanceProfile", false},
	{"iam:CreateInstanceProfile", false},
	{"iam:CreateServiceLinkedRole", false},
	{"iam:DeleteInstanceProfile", false},
	{"iam:GetInstanceProfile", false},
	{"iam:ListInstanceProfiles", false},
	{"iam:PassRole", false},
	{"iam:RemoveRoleFromInstanceProfile", false},
	{"iam:TagInstanceProfile", false},
	{"pricing:GetProducts", false},
	{"ssm:GetParameter", false},

	// openshift-ingress
	{"route53:ListHostedZones", false},
	{"route53:ListTagsForResources", false},
	{"route53:ChangeResourceRecordSets", false},
	{"tag:GetResources", false},
	{"sts:AssumeRole", false},

	// openshift-image-registry
	{"s3:CreateBucket", false},
	{"s3:DeleteBucket", false},
	{"s3:PutBucketTagging", false},
	{"s3:GetBucketTagging", false},
	{"s3:PutBucketPublicAccessBlock", false},
	{"s3:GetBucketPublicAccessBlock", false},
	{"s3:PutEncryptionConfiguration", false},
	{"s3:GetEncryptionConfiguration", false},
	{"s3:PutLifecycleConfiguration", false},
	{"s3:GetLifecycleConfiguration", false},
	{"s3:GetBucketLocation", false},
	{"s3:ListBucket", false},
	{"s3:GetObject", false},
	{"s3:PutObject", false},
	{"s3:DeleteObject", false},
	{"s3:ListBucketMultipartUploads", false},
	{"s3:AbortMultipartUpload", false},
	{"s3:ListMultipartUploadParts", false},

	// cloud-credential-operator-iam-ro
	{"iam:GetUser", false},
	{"iam:GetUserPolicy", false},
	{"iam:ListAccessKeys", false},

	// openshift-cloud-network-config-controller-aws
	{"ec2:DescribeInstanceStatus", false},
	{"ec2:DescribeNetworkInterfaceAttribute", false},
	{"ec2:DescribeNetworkInterfaces", false},
	{"ec2:ModifyNetworkInterfaceAttribute", true},
	{"ec2:AssignIpv6Addresses", false},
	{"ec2:AssignPrivateIpAddresses", false},
	{"ec2:UnassignIpv6Addresses", false},
	{"ec2:UnassignPrivateIpAddresses", false},
}

func TestPayloadActionsAreCovered(t *testing.T) {
	for _, pa := range payloadAWSActions {
		t.Run(pa.action, func(t *testing.T) {
			supported, err := SupportsInfraResourceTagCondition(pa.action)
			require.NoError(t, err, "action %q from payload CredentialsRequests is not classified — add it to infraResourceTagScopedActions or infraResourceTagUnscopedActions in pkg/aws/utils.go", pa.action)
			assert.Equal(t, pa.scoped, supported,
				"action %q classification mismatch: expected scoped=%v", pa.action, pa.scoped)
		})
	}
}

func TestSupportsInfraResourceTagCondition(t *testing.T) {
	t.Run("scoped action returns true", func(t *testing.T) {
		supported, err := SupportsInfraResourceTagCondition("ec2:TerminateInstances")
		require.NoError(t, err)
		assert.True(t, supported)
	})

	t.Run("unscoped action returns false", func(t *testing.T) {
		supported, err := SupportsInfraResourceTagCondition("ec2:DescribeInstances")
		require.NoError(t, err)
		assert.False(t, supported)
	})

	t.Run("unknown action returns error", func(t *testing.T) {
		_, err := SupportsInfraResourceTagCondition("foo:BarAction")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "foo:BarAction")
	})

	t.Run("all scoped and unscoped maps are disjoint", func(t *testing.T) {
		for action := range infraResourceTagScopedActions {
			assert.False(t, infraResourceTagUnscopedActions[action],
				"action %q appears in both scoped and unscoped maps", action)
		}
	})

	t.Run("no trailing whitespace in action keys", func(t *testing.T) {
		for action := range infraResourceTagScopedActions {
			assert.Equal(t, strings.TrimSpace(action), action,
				"scoped action %q has whitespace", action)
		}
		for action := range infraResourceTagUnscopedActions {
			assert.Equal(t, strings.TrimSpace(action), action,
				"unscoped action %q has whitespace", action)
		}
	})
}
