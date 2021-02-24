package main

import (
	"log"

	"github.com/spf13/cobra"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "ccoctl",
		Short: "OpenShift credentials provisioning tool",
	}

	rootCmd.PersistentFlags().StringVar(&provisioning.CreateOpts.TargetDir, "output-dir", "", "Directory to place generated files (defaults to current directory)")

	rootCmd.AddCommand(provisioning.NewCreateCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
