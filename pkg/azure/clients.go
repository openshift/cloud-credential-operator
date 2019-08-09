package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/services/authorization/mgmt/2015-07-01/authorization"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest"
)

//go:generate mockgen -source=./clients.go -destination=./mock/client_generated.go -package=mock

// AppClient is a wrapper object for actual Azure SDK to allow for easier testing.
type AppClient interface {
	List(ctx context.Context, filter string) ([]graphrbac.Application, error)
	Create(ctx context.Context, parameters graphrbac.ApplicationCreateParameters) (result graphrbac.Application, err error)
	UpdatePasswordCredentials(ctx context.Context, applicationObjectID string, parameters graphrbac.PasswordCredentialsUpdateParameters) error
	Delete(ctx context.Context, applicationObjectID string) error
}

type appClient struct {
	client graphrbac.ApplicationsClient
}

func (appClient *appClient) List(ctx context.Context, filter string) ([]graphrbac.Application, error) {
	appResp, err := appClient.client.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	return appResp.Values(), nil
}

func (appClient *appClient) Create(ctx context.Context, parameters graphrbac.ApplicationCreateParameters) (result graphrbac.Application, err error) {
	return appClient.client.Create(ctx, parameters)
}

func (appClient *appClient) UpdatePasswordCredentials(ctx context.Context, applicationObjectID string, parameters graphrbac.PasswordCredentialsUpdateParameters) error {
	_, err := appClient.client.UpdatePasswordCredentials(ctx, applicationObjectID, parameters)
	return err
}

func (appClient *appClient) Delete(ctx context.Context, applicationObjectID string) error {
	_, err := appClient.client.Delete(ctx, applicationObjectID)
	return err
}

var _ AppClient = &appClient{}

func NewAppClient(tenantID string, authorizer autorest.Authorizer) *appClient {
	client := graphrbac.NewApplicationsClient(tenantID)
	client.Authorizer = authorizer
	return &appClient{
		client: client,
	}
}

// SPClient is a wrapper object for actual Azure SDK to allow for easier testing.
type ServicePrincipalClient interface {
	List(ctx context.Context, filter string) ([]graphrbac.ServicePrincipal, error)
	Create(ctx context.Context, parameters graphrbac.ServicePrincipalCreateParameters) (graphrbac.ServicePrincipal, error)
}

type servicePrincipalClient struct {
	client graphrbac.ServicePrincipalsClient
}

func (spClient *servicePrincipalClient) List(ctx context.Context, filter string) ([]graphrbac.ServicePrincipal, error) {
	spResp, err := spClient.client.List(ctx, filter)
	if err != nil {
		return nil, err
	}

	return spResp.Values(), nil
}

func (spClient *servicePrincipalClient) Create(ctx context.Context, parameters graphrbac.ServicePrincipalCreateParameters) (graphrbac.ServicePrincipal, error) {
	return spClient.client.Create(ctx, parameters)
}

var _ ServicePrincipalClient = &servicePrincipalClient{}

func NewServicePrincipalClient(tenantID string, authorizer autorest.Authorizer) *servicePrincipalClient {
	client := graphrbac.NewServicePrincipalsClient(tenantID)
	client.Authorizer = authorizer
	return &servicePrincipalClient{
		client: client,
	}
}

// RoleAssignmentsClient is a wrapper object for actual Azure SDK to allow for easier testing.
type RoleAssignmentsClient interface {
	Create(ctx context.Context, scope string, roleAssignmentName string, parameters authorization.RoleAssignmentCreateParameters) (authorization.RoleAssignment, error)
}

type roleAssignmentsClient struct {
	client authorization.RoleAssignmentsClient
}

func (raClient *roleAssignmentsClient) Create(ctx context.Context, scope string, roleAssignmentName string, parameters authorization.RoleAssignmentCreateParameters) (authorization.RoleAssignment, error) {
	return raClient.client.Create(ctx, scope, roleAssignmentName, parameters)
}

var _ RoleAssignmentsClient = &roleAssignmentsClient{}

func NewRoleAssignmentsClient(subscriptionID string, authorizer autorest.Authorizer) *roleAssignmentsClient {
	client := authorization.NewRoleAssignmentsClient(subscriptionID)
	client.Authorizer = authorizer
	return &roleAssignmentsClient{
		client: client,
	}
}

// RoleDefinitionClient is a wrapper object for actual Azure SDK to allow for easier testing.
type RoleDefinitionClient interface {
	List(ctx context.Context, scope string, filter string) ([]authorization.RoleDefinition, error)
}

type roleDefinitionClient struct {
	client authorization.RoleDefinitionsClient
}

func (rdClient *roleDefinitionClient) List(ctx context.Context, scope string, filter string) ([]authorization.RoleDefinition, error) {
	roleDefResp, err := rdClient.client.List(ctx, scope, filter)
	if err != nil {
		return nil, err
	}

	return roleDefResp.Values(), nil
}

var _ RoleDefinitionClient = &roleDefinitionClient{}

func NewRoleDefinitionClient(subscriptionID string, authorizer autorest.Authorizer) *roleDefinitionClient {
	client := authorization.NewRoleDefinitionsClient(subscriptionID)
	client.Authorizer = authorizer
	return &roleDefinitionClient{
		client: client,
	}
}
