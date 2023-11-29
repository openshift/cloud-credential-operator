package azure

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	azidentity "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/go-autorest/autorest/azure"
	azurekiota "github.com/microsoft/kiota-authentication-azure-go"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"

	configv1 "github.com/openshift/api/config/v1"
)

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
	var cloudConfig cloud.Configuration
	switch cloudName {
	case "AzureStackCloud":
		cloudConfig = cloud.Configuration{
			ActiveDirectoryAuthorityHost: env.ActiveDirectoryEndpoint,
			Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
				cloud.ResourceManager: {
					Audience: env.TokenAudience,
					Endpoint: env.ResourceManagerEndpoint,
				},
			},
		}
	case "AzureUSGovernmentCloud":
		cloudConfig = cloud.AzureGovernment
	case "AzureChinaCloud":
		cloudConfig = cloud.AzureChina
	default:
		cloudConfig = cloud.AzurePublic
	}

	options := azidentity.ClientSecretCredentialOptions{
		ClientOptions: azcore.ClientOptions{
			Cloud: cloudConfig,
		},
	}
	cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, &options)
	if err != nil {
		return nil, fmt.Errorf("Unable to acquire credentials: %v", err)
	}
	authorizer, err := azurekiota.NewAzureIdentityAuthenticationProvider(cred)
	if err != nil {
		return nil, fmt.Errorf("Unable to construct GraphEndpoint authorizer: %v", err)
	}
	adapter, err := msgraphsdk.NewGraphRequestAdapter(authorizer)
	if err != nil {
		return nil, fmt.Errorf("Unable to construct GraphRequest adapter: %v", err)
	}

	return &AzureCredentialsMinter{
		appClient:      NewAppClient(adapter),
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
		appId := appItems[0].GetId()
		if appId == nil {
			return fmt.Errorf("unable to delete AAD application %q: no ID found", aadAppName)
		}
		displayName := appItems[0].GetDisplayName()
		if err := credMinter.appClient.Delete(ctx, *appId); err != nil {
			if displayName != nil {
				return fmt.Errorf("unable to delete AAD application %v (%v): %v", *displayName, *appId, err)
			}
			return fmt.Errorf("unable to delete AAD application %v: %v", appId, err)
		}
		return nil
	default:
		return fmt.Errorf("found more than 1 AAD application with %q name, will do nothing", aadAppName)
	}
}
