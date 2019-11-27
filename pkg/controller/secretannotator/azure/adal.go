package azure

import (
	"fmt"

	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
)

//go:generate mockgen -source=./adal.go -destination=./mock/adal_generated.go -package=mock

// AdalService is interface for github.com/Azure/go-autorest/autorest/adal for easier testing
type AdalService interface {
	NewOAuthConfig(activeDirectoryEndpoint, tenantID string) (*adal.OAuthConfig, error)
	NewServicePrincipalToken(oauthConfig adal.OAuthConfig, clientID string, secret string, resource string, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error)
}

type adalService struct{}

func (a *adalService) NewOAuthConfig(activeDirectoryEndpoint, tenantID string) (*adal.OAuthConfig, error) {
	return adal.NewOAuthConfig(azure.PublicCloud.ActiveDirectoryEndpoint, tenantID)
}

func (a *adalService) NewServicePrincipalToken(oauthConfig adal.OAuthConfig, clientID string, secret string, resource string, callbacks ...adal.TokenRefreshCallback) (*adal.ServicePrincipalToken, error) {
	token, err := adal.NewServicePrincipalToken(oauthConfig, clientID, secret, resource, callbacks...)
	if err != nil {
		return nil, err
	}

	err = token.EnsureFresh()
	if err != nil {
		return nil, err
	}
	return token, nil
}

type AzureClaim struct {
	Roles []string `json:"roles,omitempty"`
}

func (*AzureClaim) Valid() error {
	return fmt.Errorf("unimplemented")
}
