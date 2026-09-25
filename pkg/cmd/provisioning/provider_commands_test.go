package provisioning_test

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/aws"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/azure"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/gcp"
)

func TestProviderCommandsIncludeSimplifiedUpgradeWorkflow(t *testing.T) {
	providers := []struct {
		name    string
		command func() *cobra.Command
	}{
		{name: "aws", command: aws.NewAWSCmd},
		{name: "azure", command: azure.NewAzureCmd},
		{name: "gcp", command: gcp.NewGCPCmd},
	}

	for _, provider := range providers {
		t.Run(provider.name, func(t *testing.T) {
			cmd := provider.command()

			applySecrets, remaining, err := cmd.Find([]string{"apply", "secrets"})
			require.NoError(t, err)
			require.Empty(t, remaining)
			require.Equal(t, "secrets", applySecrets.Name())

			setUpgradeableTo, remaining, err := cmd.Find([]string{"set-upgradeable-to"})
			require.NoError(t, err)
			require.Empty(t, remaining)
			require.Equal(t, "set-upgradeable-to", setUpgradeableTo.Name())
		})
	}
}
