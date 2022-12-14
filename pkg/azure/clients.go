package azure

import (
	"context"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/applications"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
)

//go:generate mockgen -source=./clients.go -destination=./mock/client_generated.go -package=mock

// AppClient is a wrapper object for actual Azure SDK to allow for easier testing.
type AppClient interface {
	List(ctx context.Context, filter string) ([]models.Applicationable, error)
	Delete(ctx context.Context, applicationObjectID string) error
}

type appClient struct {
	client *msgraphsdk.GraphServiceClient
}

func (appClient *appClient) List(ctx context.Context, filter string) ([]models.Applicationable, error) {
	listQuery := applications.ApplicationsRequestBuilderGetRequestConfiguration{
		QueryParameters: &applications.ApplicationsRequestBuilderGetQueryParameters{
			Filter: &filter,
		},
	}
	appResp, err := appClient.client.Applications().Get(ctx, &listQuery)
	if err != nil {
		return nil, err
	}

	return appResp.GetValue(), nil
}

func (appClient *appClient) Delete(ctx context.Context, applicationObjectID string) error {
	return appClient.client.ApplicationsById(applicationObjectID).Delete(ctx, nil)
}

var _ AppClient = &appClient{}

func NewAppClient(authorizer *msgraphsdk.GraphRequestAdapter) *appClient {
	client := msgraphsdk.NewGraphServiceClient(authorizer)

	return &appClient{
		client: client,
	}
}
