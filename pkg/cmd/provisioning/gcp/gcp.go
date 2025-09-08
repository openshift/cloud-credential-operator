package gcp

import (
	"github.com/spf13/cobra"

	configv1 "github.com/openshift/api/config/v1"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
)

type options struct {
	TargetDir                string
	PublicKeyPath            string
	Region                   string
	Name                     string
	Project                  string
	WorkloadIdentityPool     string
	WorkloadIdentityProvider string
	CredRequestDir           string
	DryRun                   bool
	EnableTechPreview        bool
	Endpoints                endpoints
}

type endpoints struct {
	CRM     string
	IAM     string
	Storage string
}

func (e *endpoints) ToGCPServiceEndpoint() []configv1.GCPServiceEndpoint {
	endpoints := []configv1.GCPServiceEndpoint{}

	if e.CRM != "" {
		endpoints = append(endpoints, configv1.GCPServiceEndpoint{
			Name: configv1.GCPServiceEndpointNameCloudResource,
			URL:  e.CRM,
		})
	}

	if e.IAM != "" {
		endpoints = append(endpoints, configv1.GCPServiceEndpoint{
			Name: configv1.GCPServiceEndpointNameIAM,
			URL:  e.IAM,
		})
	}

	if e.Storage != "" {
		endpoints = append(endpoints, configv1.GCPServiceEndpoint{
			Name: configv1.GCPServiceEndpointNameStorage,
			URL:  e.Storage,
		})
	}

	return endpoints
}

// NewGCPCmd implements the "gcp" subcommand for the credentials provisioning
func NewGCPCmd() *cobra.Command {
	gcpCmd := &cobra.Command{
		Use:   "gcp",
		Short: "Manage credentials objects for Google cloud",
		Long:  "Creating/updating/deleting cloud credentials objects for Google cloud",
	}

	gcpCmd.AddCommand(provisioning.NewCreateKeyPairCmd())
	gcpCmd.AddCommand(NewCreateWorkloadIdentityPool())
	gcpCmd.AddCommand(NewCreateWorkloadIdentityProviderCmd())
	gcpCmd.AddCommand(NewCreateServiceAccountsCmd())
	gcpCmd.AddCommand(NewCreateAllCmd())
	gcpCmd.AddCommand(NewDeleteCmd())

	return gcpCmd
}
