package azure

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"

	configv1 "github.com/openshift/api/config/v1"
)

func getAuthorizer(clientID, clientSecret, tenantID string, env azure.Environment, resourceEndpoint string) (autorest.Authorizer, error) {
	config := auth.NewClientCredentialsConfig(clientID, clientSecret, tenantID)
	config.Resource = resourceEndpoint
	config.AADEndpoint = env.ActiveDirectoryEndpoint
	return config.Authorizer()
}

type credentialMinterBuilder func(logger log.FieldLogger, clientID, clientSecret, tenantID, subscriptionID string) (*AzureCredentialsMinter, error)

type AzureCredentialsMinter struct {
	appClient      AppClient
	tenantID       string
	subscriptionID string
	logger         log.FieldLogger
}

func NewFakeAzureCredentialsMinter(logger log.FieldLogger, clientID, clientSecret, tenantID, subscriptionID string, appClient AppClient) (*AzureCredentialsMinter, error) {
	return &AzureCredentialsMinter{
		appClient:      appClient,
		tenantID:       tenantID,
		subscriptionID: subscriptionID,
		logger:         logger,
	}, nil
}

func NewAzureCredentialsMinter(logger log.FieldLogger, clientID, clientSecret string, cloudName configv1.AzureCloudEnvironment, tenantID, subscriptionID string) (*AzureCredentialsMinter, error) {
	env, err := azure.EnvironmentFromName(string(cloudName))
	if err != nil {
		return nil, fmt.Errorf("Unable to determine Azure environment: %w", err)
	}
	graphAuthorizer, err := getAuthorizer(clientID, clientSecret, tenantID, env, env.GraphEndpoint)
	if err != nil {
		return nil, fmt.Errorf("Unable to construct GraphEndpoint authorizer: %v", err)
	}

	return &AzureCredentialsMinter{
		appClient:      NewAppClient(env, tenantID, graphAuthorizer),
		tenantID:       tenantID,
		subscriptionID: subscriptionID,
		logger:         logger,
	}, nil
}

// DeleteAADApplication deletes an AAD application.
// If the application does not exist, it's no-op.
func (credMinter *AzureCredentialsMinter) DeleteAADApplication(ctx context.Context, aadAppName string) error {
	appItems, err := credMinter.appClient.List(ctx, fmt.Sprintf("displayName eq '%v'", aadAppName))
	if err != nil {
		return fmt.Errorf("unable to list AAD applications: %v", err)
	}

	switch len(appItems) {
	case 0:
		credMinter.logger.Infof("No AAD application %q found, doing nothing", aadAppName)
		return nil
	case 1:
		credMinter.logger.Infof("Deleting AAD application %q", aadAppName)
		if err := credMinter.appClient.Delete(ctx, *appItems[0].ObjectID); err != nil {
			if appItems[0].DisplayName != nil {
				return fmt.Errorf("unable to delete AAD application %v (%v): %v", *appItems[0].DisplayName, *appItems[0].ObjectID, err)
			}
			return fmt.Errorf("unable to delete AAD application %v: %v", appItems[0].ObjectID, err)
		}
		return nil
	default:
		return fmt.Errorf("found more than 1 AAD application with %q name, will do nothing", aadAppName)
	}
}
