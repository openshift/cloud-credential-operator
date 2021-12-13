package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
)

//go:generate mockgen -source=./clients.go -destination=./mock/client_generated.go -package=mock

// AppClient is a wrapper object for actual Azure SDK to allow for easier testing.
type AppClient interface {
	List(ctx context.Context, filter string) ([]graphrbac.Application, error)
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

func (appClient *appClient) Delete(ctx context.Context, applicationObjectID string) error {
	_, err := appClient.client.Delete(ctx, applicationObjectID)
	return err
}

var _ AppClient = &appClient{}

func NewAppClient(env azure.Environment, tenantID string, authorizer autorest.Authorizer) *appClient {
	client := graphrbac.NewApplicationsClientWithBaseURI(env.GraphEndpoint, tenantID)
	client.Authorizer = authorizer
	return &appClient{
		client: client,
	}
}
