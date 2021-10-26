package gcp

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	iamadminpb "google.golang.org/genproto/googleapis/iam/admin/v1"

	"github.com/openshift/cloud-credential-operator/pkg/gcp"
	"github.com/openshift/cloud-credential-operator/pkg/gcp/actuator"
)

var (
	// DeleteOpts captures the options that affect deletion
	// of the generated objects.
	DeleteOpts = options{}
)

// deleteOIDCObjectsFromBucket deletes the objects in OIDC cloud storage bucket
func deleteOIDCObjectsFromBucket(ctx context.Context, client gcp.Client, bucketName, namePrefix string) error {
	objectAttrs, err := client.ListObjects(ctx, bucketName)
	if err != nil {
		return errors.Wrapf(err, "Failed to list objects from bucket %s", bucketName)
	}

	for _, attr := range objectAttrs {
		err := client.DeleteObject(ctx, bucketName, attr.Name)
		if err != nil {
			return errors.Wrapf(err, "Failed to delete object %s from bucket %s", attr.Name, bucketName)
		}
		log.Printf("Deleted object %s from bucket %s", attr.Name, bucketName)
	}

	return nil
}

// deleteOIDCBucket deletes the OIDC cloud storage bucket
func deleteOIDCBucket(ctx context.Context, client gcp.Client, bucketName, namePrefix string) error {
	err := client.DeleteBucket(ctx, bucketName)
	if err != nil {
		return errors.Wrapf(err, "Failed to delete the OIDC bucket %s", bucketName)
	}
	log.Printf("OIDC bucket %s deleted", bucketName)

	return nil
}

// deleteServiceAccounts deletes the IAM service accounts created by ccoctl
func deleteServiceAccounts(ctx context.Context, client gcp.Client, namePrefix string) error {
	projectName := client.GetProjectName()
	projectResourceName := fmt.Sprintf("projects/%s", projectName)
	listServiceAccountsRequest := &iamadminpb.ListServiceAccountsRequest{
		Name: projectResourceName,
	}

	svcAcctList, err := client.ListServiceAccounts(ctx, listServiceAccountsRequest)
	if err != nil {
		return errors.Wrapf(err, "Failed to fetch list of service accounts")
	}
	for _, svcAcct := range svcAcctList {
		if isCreatedByCcoctl(svcAcct.Email, namePrefix) || isCreatedByCcoctl(svcAcct.DisplayName, namePrefix) {
			svcAcctBindingName := actuator.ServiceAccountBindingName(svcAcct)
			err := actuator.RemovePolicyBindingsForProject(client, svcAcctBindingName)
			if err != nil {
				return errors.Wrapf(err, "Failed to remove project policy bindings for service account")
			}

			if err := actuator.DeleteServiceAccount(client, svcAcct); err != nil {
				return errors.Wrapf(err, "Failed to delete service account")
			}

			log.Printf("IAM Service account %s deleted", svcAcct.DisplayName)
		}
	}

	return nil
}

// isCreatedByCcoctl checks if the google cloud resource is created by ccoctl based on the name prefix
func isCreatedByCcoctl(identity, name string) bool {
	return strings.HasPrefix(identity, name+"-")
}

// deleteWorkloadIdentityPool deletes the workload identity pool along with the providers
func deleteWorkloadIdentityPool(ctx context.Context, client gcp.Client, poolName string) error {
	projectName := client.GetProjectName()
	poolResource := fmt.Sprintf("projects/%s/locations/global/workloadIdentityPools/%s", projectName, poolName)

	_, err := client.DeleteWorkloadIdentityPool(ctx, poolResource)
	if err != nil {
		return errors.Wrapf(err, "Failed to delete workload identity pool %s", poolName)
	}
	log.Printf("Workload identity pool %s deleted", poolName)
	return nil
}

func deleteCmd(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	creds, err := loadCredentials(ctx)
	if err != nil {
		log.Fatalf("Failed to load credentials: %s", err)
	}

	gcpClient, err := gcp.NewClient(DeleteOpts.Project, creds.JSON)
	if err != nil {
		log.Fatal(err)
	}

	bucketName := fmt.Sprintf("%s-oidc", DeleteOpts.Name)

	if err := deleteOIDCObjectsFromBucket(ctx, gcpClient, bucketName, DeleteOpts.Name); err != nil {
		log.Print(err)
	}

	if err := deleteOIDCBucket(ctx, gcpClient, bucketName, DeleteOpts.Name); err != nil {
		log.Print(err)
	}

	if err := deleteServiceAccounts(ctx, gcpClient, DeleteOpts.Name); err != nil {
		log.Print(err)
	}

	if err := deleteWorkloadIdentityPool(ctx, gcpClient, DeleteOpts.Name); err != nil {
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

	deleteCmd.PersistentFlags().StringVar(&DeleteOpts.Name, "name", "", "User-defined name for all created google cloud resources (can be separate from the cluster's infra-id)")
	deleteCmd.MarkPersistentFlagRequired("name")
	deleteCmd.PersistentFlags().StringVar(&DeleteOpts.Project, "project", "", "ID of the google cloud project")
	deleteCmd.MarkPersistentFlagRequired("project")

	return deleteCmd
}
