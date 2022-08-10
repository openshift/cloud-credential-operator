/*
 Kubernetes environment reads settings by accessing Kubernetes APIs.
*/

package kubernetes

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/nutanix-cloud-native/prism-go-client/environment/types"
	coreinformers "k8s.io/client-go/informers/core/v1"
)

type provider struct {
	secretInformer coreinformers.SecretInformer
	prismEndpoint  NutanixPrismEndpoint
}

func (prov *provider) getCredentials(_ types.Topology) (*types.ApiCredentials, error) {
	ref := prov.prismEndpoint.CredentialRef
	secret, err := prov.secretInformer.Lister().Secrets(ref.Namespace).Get(ref.Name)
	if err != nil {
		return nil, err
	}

	// Parse credentials in secret
	credsData, ok := secret.Data["credentials"]
	if !ok {
		return nil, fmt.Errorf("no \"credentials\" data found in secret %s/%s",
			ref.Namespace, ref.Name)
	}
	creds := &NutanixCredentials{}
	err = json.Unmarshal(credsData, &creds.Credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal the credentials data. %w", err)
	}
	// TODO only single API endpoint supported
	for _, cred := range creds.Credentials {
		switch cred.Type {
		case BasicAuthCredentialType:
			basicAuthCreds := BasicAuthCredential{}
			if err := json.Unmarshal(cred.Data, &basicAuthCreds); err != nil {
				return nil, fmt.Errorf("failed to unmarshal the basic-auth data. %w", err)
			}
			pc := basicAuthCreds.PrismCentral
			if pc.Username == "" || pc.Password == "" {
				return nil, fmt.Errorf("the PrismCentral credentials data is not set for secret %s/%s",
					ref.Namespace, ref.Name)
			}
			return &types.ApiCredentials{
				Username: pc.Username,
				Password: pc.Password,
			}, nil
		default:
			return nil, fmt.Errorf("unsupported credentials type in secret %s/%s: %v",
				ref.Namespace, ref.Name, cred.Type)
		}
	}
	return nil, fmt.Errorf("no Prism credentials in secret %s/%s", ref.Namespace, ref.Name)
}

// GetManagementEndpoint retrieves managment endpoint
func (prov *provider) GetManagementEndpoint(
	topology types.Topology,
) (*types.ManagementEndpoint, error) {
	creds, err := prov.getCredentials(topology)
	if err != nil {
		return nil, err
	}
	addr, err := url.Parse(fmt.Sprintf("https://%s:%d",
		prov.prismEndpoint.Address, prov.prismEndpoint.Port))
	if err != nil {
		return nil, err
	}
	return &types.ManagementEndpoint{
		Address:        addr,
		Insecure:       prov.prismEndpoint.Insecure,
		ApiCredentials: *creds,
	}, nil
}

// Get retrieves settings applicable to the environment like project
// or category to which resources created on behalf of Kubernetes cluster are
// assigned to.
// These settings might have to be explicitly propagated to resources.
// Return whether lookup was successful to distinguish from nil as value.
func (prov *provider) Get(topology types.Topology, key string) (
	interface{}, error,
) {
	return nil, types.ErrNotFound
}

// NewProvider constructs Kubernetes Environment provider taking
// Prism endpoint and a secretes informer as input.
// It's assumed secrets informer is already running and its cache has been synced.
func NewProvider(
	prismEndpoint NutanixPrismEndpoint,
	secretInformer coreinformers.SecretInformer,
) types.Provider {
	return &provider{
		prismEndpoint:  prismEndpoint,
		secretInformer: secretInformer,
	}
}
