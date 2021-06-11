package aws

import (
	"fmt"
	"log"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/openshift/cloud-credential-operator/pkg/aws"
)

var (
	// DeleteOpts captures the options that affect deletion
	// of the generated objects.
	DeleteOpts = options{}
)

// deleteOIDCObjectsFromBucket deletes the OIDC objects from the S3 bucket
func deleteOIDCObjectsFromBucket(client aws.Client, bucketName, namePrefix string) error {
	objectsMetadata, err := client.ListObjects(&s3.ListObjectsInput{
		Bucket: awssdk.String(bucketName),
	})
	if err != nil {
		return errors.Wrapf(err, "failed to fetch list of Identity Provider objects in the bucket %s", bucketName)
	}

	for _, objectMetadata := range objectsMetadata.Contents {
		objectTags, err := client.GetObjectTagging(&s3.GetObjectTaggingInput{
			Key:    objectMetadata.Key,
			Bucket: awssdk.String(bucketName),
		})
		if err != nil {
			return errors.Wrapf(err, "failed to fetch tags of Identity Provider object %s in the bucket %s", *objectMetadata.Key, bucketName)
		}

		for _, tag := range objectTags.TagSet {
			if *tag.Key == fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, namePrefix) {
				_, err := client.DeleteObject(&s3.DeleteObjectInput{
					Key:    objectMetadata.Key,
					Bucket: awssdk.String(bucketName),
				})
				if err != nil {
					return errors.Wrapf(err, "failed to delete Identity Provider object %s in the bucket %s", *objectMetadata.Key, bucketName)
				}
				log.Printf("Identity Provider object %s deleted from the bucket %s", *objectMetadata.Key, bucketName)
				break
			}
		}
	}

	return nil
}

// deleteOIDCBucket deletes the OIDC S3 bucket
func deleteOIDCBucket(client aws.Client, bucketName, namePrefix string) error {
	bucketTags, err := client.GetBucketTagging(&s3.GetBucketTaggingInput{
		Bucket: awssdk.String(bucketName),
	})
	if err != nil {
		return errors.Wrapf(err, "failed to fetch tags of the bucket %s", bucketName)
	}

	for _, tag := range bucketTags.TagSet {
		if *tag.Key == fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, namePrefix) {
			_, err := client.DeleteBucket(&s3.DeleteBucketInput{
				Bucket: awssdk.String(bucketName),
			})
			if err != nil {
				return errors.Wrapf(err, "failed to delete the Identity Provider bucket %s", bucketName)
			}
			log.Printf("Identity Provider bucket %s deleted", bucketName)
			break
		}
	}

	return nil
}

// deleteIAMRoles deletes the IAM Roles created by ccoctl
func deleteIAMRoles(client aws.Client, namePrefix string, paginationMarker *string) error {
	// iam.ListRolesInput results are paginated to 100 items by default, if result is truncated we need to
	// fetch next set of items and perform delete operation
	roleList, err := client.ListRoles(&iam.ListRolesInput{
		Marker: paginationMarker,
	})
	if err != nil {
		return errors.Wrapf(err, "failed to fetch a list of IAM roles, pagination marker: %v", paginationMarker)
	}

	for _, roleMetadata := range roleList.Roles {
		roleOutput, err := client.GetRole(&iam.GetRoleInput{
			RoleName: roleMetadata.RoleName,
		})
		if err != nil {
			return errors.Wrapf(err, "failed to fetch IAM role %s", *roleMetadata.RoleName)
		}

		for _, tag := range roleOutput.Role.Tags {
			if *tag.Key == fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, namePrefix) {
				if err := deleteRolePolicies(client, *roleOutput.Role.RoleName); err != nil {
					return errors.Wrapf(err, "failed to delete policies associated with IAM Role %s", *roleOutput.Role.RoleName)
				}

				_, err := client.DeleteRole(&iam.DeleteRoleInput{
					RoleName: roleOutput.Role.RoleName,
				})
				if err != nil {
					return errors.Wrapf(err, "failed to delete IAM Role %s", *roleOutput.Role.RoleName)
				}
				log.Printf("IAM Role %s deleted", *roleOutput.Role.RoleName)
				break
			}
		}
	}

	if *roleList.IsTruncated {
		return deleteIAMRoles(client, namePrefix, roleList.Marker)
	}

	return nil
}

// deleteRolePolicies deletes the Polices associated with IAM Role created by ccoctl
func deleteRolePolicies(client aws.Client, roleName string) error {
	policies, err := client.ListRolePolicies(&iam.ListRolePoliciesInput{
		RoleName: awssdk.String(roleName),
	})
	if err != nil {
		return errors.Wrapf(err, "failed to fetch a list of policies associated with IAM role %s", roleName)
	}

	for _, policyName := range policies.PolicyNames {
		_, err := client.DeleteRolePolicy(&iam.DeleteRolePolicyInput{
			RoleName:   awssdk.String(roleName),
			PolicyName: policyName,
		})
		if err != nil {
			return errors.Wrapf(err, "failed to delete policy %s associated with IAM Role %s", *policyName, roleName)
		}
		log.Printf("Policy %s associated with IAM Role %s deleted", *policyName, roleName)
	}

	return nil
}

// deleteIAMIdentityProvider deletes the IAM Identity Provider
func deleteIAMIdentityProvider(client aws.Client, namePrefix string) error {
	oidcProviderList, err := client.ListOpenIDConnectProviders(&iam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		return errors.Wrap(err, "failed to fetch list of Identity Providers")
	}

	for _, provider := range oidcProviderList.OpenIDConnectProviderList {
		ok, err := isExistingIdentifyProvider(client, *provider.Arn, namePrefix)
		if err != nil {
			return errors.Wrapf(err, "failed to check for existing Identity Provider")
		}

		if ok {
			_, err := client.DeleteOpenIDConnectProvider(&iam.DeleteOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: awssdk.String(*provider.Arn),
			})
			if err != nil {
				return errors.Wrapf(err, "failed to delete Identity Provider with ARN %s", *provider.Arn)
			}
			log.Printf("Identity Provider with ARN %s deleted", *provider.Arn)
			break
		}
	}

	return nil
}

func deleteCmd(cmd *cobra.Command, args []string) {
	s, err := awsSession(DeleteOpts.Region)
	if err != nil {
		log.Fatal(err)
	}

	awsClient := aws.NewClientFromSession(s)
	bucketName := fmt.Sprintf("%s-oidc", DeleteOpts.Name)

	if err := deleteOIDCObjectsFromBucket(awsClient, bucketName, DeleteOpts.Name); err != nil {
		log.Print(err)
	}

	if err := deleteOIDCBucket(awsClient, bucketName, DeleteOpts.Name); err != nil {
		log.Print(err)
	}

	if err := deleteIAMRoles(awsClient, DeleteOpts.Name, nil); err != nil {
		log.Print(err)
	}

	if err := deleteIAMIdentityProvider(awsClient, DeleteOpts.Name); err != nil {
		log.Print(err)
	}
}

// NewDeleteCmd implements the "delete" command for the credentials provisioning
func NewDeleteCmd() *cobra.Command {
	deleteCmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete credentials objects",
		Long:  "Deleting objects related to cloud credentials",
		Run:   deleteCmd,
	}

	deleteCmd.PersistentFlags().StringVar(&DeleteOpts.Name, "name", "", "User-defined name for all created AWS resources (can be separate from the cluster's infra-id)")
	deleteCmd.MarkPersistentFlagRequired("name")
	deleteCmd.PersistentFlags().StringVar(&DeleteOpts.Region, "region", "", "AWS region where the resources were created")
	deleteCmd.MarkPersistentFlagRequired("region")

	return deleteCmd
}
