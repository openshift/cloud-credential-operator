package gcp

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
)

const (
	// iamPolicyMaxRetries is the maximum retry index (0-based) for transient IAM policy errors.
	// With a 10-second delay this allows up to 24 attempts (~4 minutes total).
	iamPolicyMaxRetries = 23
	// iamPolicyRetryDelay is the sleep duration between IAM policy retry attempts.
	iamPolicyRetryDelay = 10 * time.Second
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
	KeyStorageMethod         string
	DryRun                   bool
	EnableTechPreview        bool
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
