package ibmcloud

import (
	"fmt"
	"github.com/openshift/cloud-credential-operator/pkg/ibmcloud"
	"github.com/pkg/errors"

	//"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// NewDeleteServiceIDCmd provides the "delete-service-id" subcommand
func NewDeleteServiceIDCmd() *cobra.Command {
	deleteServiceIDCmd := &cobra.Command{
		Use:              "delete-service-id",
		Short:            "Delete Service ID",
		RunE:             deleteServiceIDCmd,
		PersistentPreRun: initEnvForCreateServiceIDCmd,
	}

	deleteServiceIDCmd.PersistentFlags().StringVar(&CreateOpts.Name, "name", "", "User-defined name for all created IBM Cloud resources (can be separate from the cluster's infra-id)")
	deleteServiceIDCmd.MarkPersistentFlagRequired("name")
	deleteServiceIDCmd.PersistentFlags().StringVar(&CreateOpts.CredRequestDir, "credentials-requests-dir", "", "Directory containing files of CredentialsRequests to delete IAM Roles for (can be created by running 'oc adm release extract --credentials-requests --cloud=ibmcloud' against an OpenShift release image)")
	deleteServiceIDCmd.MarkPersistentFlagRequired("credentials-requests-dir")
	deleteServiceIDCmd.PersistentFlags().BoolVar(&CreateOpts.Force, "force", false, "delete all the service account forcefully(will delete all the entries with the name)")

	return deleteServiceIDCmd
}

func deleteServiceIDCmd(cmd *cobra.Command, args []string) error {
	apiKey := getEnv(APIKeyEnvVars)
	if apiKey == "" {
		return fmt.Errorf("%s environment variable not set", APIKeyEnvVars)
	}

	params := &ibmcloud.ClientParams{
		InfraName: CreateOpts.Name,
	}

	ibmclient, err := ibmcloud.NewClient(apiKey, params)
	if err != nil {
		return err
	}

	apiKeyDetailsOptions := ibmclient.NewGetAPIKeysDetailsOptions()
	apiKeyDetailsOptions.SetIamAPIKey(apiKey)
	apiKeyDetails, _, err := ibmclient.GetAPIKeysDetails(apiKeyDetailsOptions)
	if err != nil {
		return errors.Wrap(err, "Failed to get Details for the given APIKey")
	}

	err = deleteServiceIDs(ibmclient, *apiKeyDetails.AccountID, CreateOpts.Name, CreateOpts.CredRequestDir, CreateOpts.Force)
	if err != nil {
		return err
	}

	return nil
}

func deleteServiceIDs(client ibmcloud.Client, accountID, name, credReqDir string, force bool) error {
	// Process directory
	credReqs, err := getListOfCredentialsRequests(credReqDir)
	if err != nil {
		return errors.Wrap(err, "Failed to process files containing CredentialsRequests")
	}

	var serviceIDs []*ServiceID

	for _, cr := range credReqs {
		serviceID := NewServiceID(client, name, accountID, "", cr)
		serviceIDs = append(serviceIDs, serviceID)
	}

	for _, serviceID := range serviceIDs {
		if err := serviceID.Delete(force); err != nil {
			return errors.Wrap(err, "Failed to delete the serviceIDs")
		}
	}

	return nil
}
