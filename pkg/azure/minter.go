package azure

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/Azure/azure-sdk-for-go/services/authorization/mgmt/2015-07-01/authorization"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/Azure/go-autorest/autorest/to"
	uuid "github.com/satori/go.uuid"

	configv1 "github.com/openshift/api/config/v1"
)

func getAuthorizer(clientID, clientSecret, tenantID, resourceEndpoint string) (autorest.Authorizer, error) {
	config := auth.NewClientCredentialsConfig(clientID, clientSecret, tenantID)
	config.Resource = resourceEndpoint
	return config.Authorizer()
}

type credentialMinterBuilder func(logger log.FieldLogger, clientID, clientSecret, tenantID, subscriptionID string) (*AzureCredentialsMinter, error)

type AzureCredentialsMinter struct {
	appClient             AppClient
	spClient              ServicePrincipalClient
	roleAssignmentsClient RoleAssignmentsClient
	roleDefinitionClient  RoleDefinitionClient
	tenantID              string
	subscriptionID        string
	logger                log.FieldLogger
}

func NewFakeAzureCredentialsMinter(logger log.FieldLogger, clientID, clientSecret, tenantID, subscriptionID string, appClient AppClient, spClient ServicePrincipalClient, roleAssignmentsClient RoleAssignmentsClient, roleDefinitionClient RoleDefinitionClient) (*AzureCredentialsMinter, error) {
	return &AzureCredentialsMinter{
		appClient:             appClient,
		spClient:              spClient,
		tenantID:              tenantID,
		subscriptionID:        subscriptionID,
		roleAssignmentsClient: roleAssignmentsClient,
		roleDefinitionClient:  roleDefinitionClient,
		logger:                logger,
	}, nil
}

func NewAzureCredentialsMinter(logger log.FieldLogger, clientID, clientSecret string, cloudName configv1.AzureCloudEnvironment, tenantID, subscriptionID string) (*AzureCredentialsMinter, error) {
	env, err := azure.EnvironmentFromName(string(cloudName))
	if err != nil {
		return nil, fmt.Errorf("Unable to determine Azure environment: %w", err)
	}
	graphAuthorizer, err := getAuthorizer(clientID, clientSecret, tenantID, env.GraphEndpoint)
	if err != nil {
		return nil, fmt.Errorf("Unable to construct GraphEndpoint authorizer: %v", err)
	}

	rmAuthorizer, err := getAuthorizer(clientID, clientSecret, tenantID, env.ResourceManagerEndpoint)
	if err != nil {
		return nil, fmt.Errorf("Unable to construct ResourceManagerEndpoint authorizer: %v", err)
	}

	return &AzureCredentialsMinter{
		appClient:             NewAppClient(env, tenantID, graphAuthorizer),
		spClient:              NewServicePrincipalClient(env, tenantID, graphAuthorizer),
		roleAssignmentsClient: NewRoleAssignmentsClient(env, subscriptionID, rmAuthorizer),
		roleDefinitionClient:  NewRoleDefinitionClient(env, subscriptionID, rmAuthorizer),
		tenantID:              tenantID,
		subscriptionID:        subscriptionID,
		logger:                logger,
	}, nil
}

// CreateOrUpdateAADApplication creates a new AAD application. If the application
// already exist, new client secret is generated if requested.
func (credMinter *AzureCredentialsMinter) CreateOrUpdateAADApplication(ctx context.Context, aadAppName string, regenClientSecret bool) (*graphrbac.Application, string, error) {
	appItems, err := credMinter.appClient.List(ctx, fmt.Sprintf("displayName eq '%v'", aadAppName))
	if err != nil {
		return nil, "", fmt.Errorf("unable to list AAD applications: %v", err)
	}

	switch len(appItems) {
	case 0:
		credMinter.logger.Infof("Creating AAD application %q", aadAppName)
		secret := uuid.NewV4().String()
		app, err := credMinter.appClient.Create(ctx, graphrbac.ApplicationCreateParameters{
			DisplayName:             to.StringPtr(aadAppName),
			AvailableToOtherTenants: to.BoolPtr(false),
			PasswordCredentials: &[]graphrbac.PasswordCredential{
				{
					Value: &secret,
					// INFO(jchaloup): end date can be completely omitted
					// 1k years should be sufficient for a while
					EndDate: &date.Time{Time: time.Now().AddDate(1000, 0, 0)},
				},
			},
		})
		if err != nil {
			return nil, "", fmt.Errorf("unable to create AAD application: %v", err)
		}
		return &app, secret, nil
	case 1:
		credMinter.logger.Infof("Found AAD application %q", aadAppName)
		clientSecret := ""
		if regenClientSecret {
			secret := uuid.NewV4().String()
			err := credMinter.appClient.UpdatePasswordCredentials(ctx, *appItems[0].ObjectID, graphrbac.PasswordCredentialsUpdateParameters{
				Value: &[]graphrbac.PasswordCredential{
					{
						Value:   &secret,
						EndDate: &date.Time{Time: time.Now().AddDate(1, 0, 0)},
					},
				},
			})
			if err != nil {
				return nil, "", err
			}
			clientSecret = secret
		}
		return &appItems[0], clientSecret, nil
	default:
		return nil, "", fmt.Errorf("found %q AAD application with name %q, unable to proceed", len(appItems), aadAppName)
	}
}

// CreateOrGetServicePrincipal creates a new SP and returns it.
// Service principal that already exist is returned.
func (credMinter *AzureCredentialsMinter) CreateOrGetServicePrincipal(ctx context.Context, appID, infraName string) (*graphrbac.ServicePrincipal, error) {
	spItems, err := credMinter.spClient.List(ctx, fmt.Sprintf("appId eq '%v'", appID))
	if err != nil {
		return nil, err
	}

	switch len(spItems) {
	case 0:
		credMinter.logger.Infof("Creating service principal for AAD application %q", appID)
		var servicePrincipal *graphrbac.ServicePrincipal
		ownedTag := fmt.Sprintf("kubernetes.io_cluster.%s=owned", infraName)

		err := wait.PollImmediate(5*time.Second, 60*time.Second, func() (bool, error) {
			sp, err := credMinter.spClient.Create(ctx, graphrbac.ServicePrincipalCreateParameters{
				AppID:          to.StringPtr(appID),
				AccountEnabled: to.BoolPtr(true),
				Tags:           &[]string{ownedTag},
			})
			// ugh: Azure client library doesn't have the types registered to
			// unmarshal all the way down to this error code natively :-(
			if err != nil && strings.Contains(err.Error(), "NoBackingApplicationObject") {
				return false, nil
			}
			servicePrincipal = &sp
			return err == nil, nil
		})
		if err != nil {
			return nil, fmt.Errorf("unable to create service principal: %v", err)
		}
		return servicePrincipal, nil
	case 1:
		if spItems[0].DisplayName != nil {
			credMinter.logger.Infof("Found service principal %q", *spItems[0].DisplayName)
		}
		return &spItems[0], nil
	default:
		return nil, fmt.Errorf("found more than 1 service principals with %q appID, will do nothing", appID)
	}
}

// CleanseResourceScopedRoleAssignments deletes any role assignment of service principal not covered by (resourceGroups, targetRole) combinations
func (credMinter *AzureCredentialsMinter) CleanseResourceScopedRoleAssignments(ctx context.Context, resourceGroups []string, principalID, principalName string, targetRoles []string) error {
	assignments, err := credMinter.roleAssignmentsClient.List(ctx, fmt.Sprintf("principalId eq '%v'", principalID))
	if err != nil {
		return fmt.Errorf("unable to list role assignments for service principal %q: %v", principalName, err)
	}

	roleIDs := make(map[string]struct{})
	for _, targetRole := range targetRoles {
		roleDefItems, err := credMinter.roleDefinitionClient.List(ctx, "/", fmt.Sprintf("roleName eq '%v'", targetRole))
		if err != nil {
			return fmt.Errorf("unable to list role definition for %q: %v", targetRole, err)
		}
		switch len(roleDefItems) {
		case 0:
			return fmt.Errorf("no role found for name %q", targetRole)
		case 1:
			roleIDs[path.Base(*roleDefItems[0].ID)] = struct{}{}
		default:
			return fmt.Errorf("found %q role definitions for %q, expected one", len(roleDefItems), targetRole)
		}
	}

	groups := make(map[string]struct{})
	for _, rg := range resourceGroups {
		groups[rg] = struct{}{}
	}

	var toDelete []string
	for _, item := range assignments {
		if _, ok := roleIDs[path.Base(*item.Properties.RoleDefinitionID)]; !ok {
			toDelete = append(toDelete, *item.ID)
			continue
		}
		if _, ok := groups[path.Base(*item.Properties.Scope)]; !ok {
			toDelete = append(toDelete, *item.ID)
			continue
		}
	}

	for _, item := range toDelete {
		credMinter.logger.Infof("Deleting role assignment %q", item)
		if err := credMinter.roleAssignmentsClient.DeleteByID(ctx, item); err != nil {
			return fmt.Errorf("failed to delete role assignment %q: %v", item, err)
		}
	}

	return nil
}

// AssignResourceScopedRole assigns a resource scoped role to a service principal
func (credMinter *AzureCredentialsMinter) AssignResourceScopedRole(ctx context.Context, resourceGroups []string, principalID, principalName, targetRole string) error {
	roleDefItems, err := credMinter.roleDefinitionClient.List(ctx, "/", fmt.Sprintf("roleName eq '%v'", targetRole))
	if err != nil {
		return err
	}

	var roleDefinition *authorization.RoleDefinition
	switch len(roleDefItems) {
	case 0:
		return fmt.Errorf("find no role %q", targetRole)
	case 1:
		roleDefinition = &roleDefItems[0]
		if roleDefinition.ID != nil {
			credMinter.logger.Infof("Found role %q under %q", targetRole, *roleDefinition.ID)
		}
	default:
		return fmt.Errorf("more than one role %q found", targetRole)
	}

	credMinter.logger.Debugf("getting current role assignments for service principal %s", principalName)
	filter := fmt.Sprintf("principalId eq '%s'", principalID)
	currentRoleAssignments, err := credMinter.roleAssignmentsClient.List(ctx, filter)
	if err != nil {
		credMinter.logger.WithError(err).Error("failed to list role assignments")
		return err
	}

	for _, resourceGroup := range resourceGroups {
		scope := "/subscriptions/" + credMinter.subscriptionID + "/resourceGroups/" + resourceGroup

		// check whether assignment already exists
		alreadyExists := false
		for _, r := range currentRoleAssignments {
			if *r.Properties.Scope == scope {
				credMinter.logger.Debugf("role %s already assigned in resource group %s for service principal %s", targetRole, resourceGroup, principalName)
				alreadyExists = true
				break
			}
		}
		if alreadyExists {
			continue
		}

		raName := uuid.NewV4().String()

		err = wait.PollImmediate(5*time.Second, 60*time.Second, func() (bool, error) {
			credMinter.logger.Debugf("assigning role %s for resource group %s", *roleDefinition.Name, resourceGroup)
			_, err = credMinter.roleAssignmentsClient.Create(ctx, scope, raName, authorization.RoleAssignmentCreateParameters{
				Properties: &authorization.RoleAssignmentProperties{
					RoleDefinitionID: roleDefinition.ID,
					PrincipalID:      &principalID,
				},
			})

			if err, ok := err.(autorest.DetailedError); ok {
				if err, ok := err.Original.(*azure.RequestError); ok {
					if err.ServiceError != nil && err.ServiceError.Code == "PrincipalNotFound" {
						return false, nil
					}
					if err.ServiceError != nil && err.ServiceError.Code == "RoleAssignmentExists" {
						return true, nil
					}
				}
			}

			return err == nil, err
		})

		if err != nil {
			return fmt.Errorf("unable to assign role to principal %q (%v): %v", principalName, principalID, err)
		}

		credMinter.logger.Infof("Assigned %q role scoped to %q to principal %q (%v)", targetRole, resourceGroup, principalName, principalID)
	}
	return nil
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
