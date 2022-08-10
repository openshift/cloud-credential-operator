package kubernetes

import (
	"encoding/json"
)

// CredentialType describes authentication mechanism like basic auth.
type CredentialType string

const (
	// BasicAuthCredentialType is username/password based authentication.
	BasicAuthCredentialType CredentialType = "basic_auth"
)

type Credential struct {
	Type CredentialType  `json:"type"`
	Data json.RawMessage `json:"data"`
}

// NutanixCredentials is list of credentials to be embedded in other objects like
// Kubernetes secrets.
type NutanixCredentials struct {
	Credentials []Credential `json:"credentials"`
}

// BasicAuthCredential is payload in Credential.Data for type of BasicAuthCredentialType
type BasicAuthCredential struct {
	// The Basic Auth (username, password) for the Prism Central
	PrismCentral PrismCentralBasicAuth `json:"prismCentral"`
	// The Basic Auth (username, password) for the Prism Elements (clusters).
	PrismElements []PrismElementBasicAuth `json:"prismElements"`
}

type BasicAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type PrismCentralBasicAuth struct {
	BasicAuth `json:",inline"`
}

type PrismElementBasicAuth struct {
	BasicAuth `json:",inline"`
	// Name is the unique resource name of the Prism Element (cluster) in the Prism Central's domain
	Name string `json:"name"`
}

type NutanixCredentialKind string

const (
	// Secret kind is enum value
	SecretKind = NutanixCredentialKind("Secret")
)

type NutanixCredentialReference struct {
	// Kind of the Nutanix credential
	Kind NutanixCredentialKind `json:"kind"`
	// Name of the credential.
	Name string `json:"name"`
	// namespace of the credential.
	Namespace string `json:"namespace"`
}

// NutanixPrismEndpoint defines a Nutanix API endpoint with reference to credentials.
// Credentials are stored in Kubernetes secrets.
type NutanixPrismEndpoint struct {
	// address is the endpoint address (DNS name or IP address) of the Nutanix Prism Central or Element (cluster)
	Address string `json:"address"`
	// port is the port number to access the Nutanix Prism Central or Element (cluster)
	Port int32 `json:"port"`
	// use insecure connection to Prism endpoint
	// +optional
	Insecure bool `json:"insecure"`
	// Pass credential information for the target Prism instance
	// +optional
	CredentialRef *NutanixCredentialReference `json:"credentialRef,omitempty"`
}
