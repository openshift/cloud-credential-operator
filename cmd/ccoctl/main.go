package main

import (
	"log"

	"github.com/spf13/cobra"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/aws"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "ccoctl",
		Short: "OpenShift credentials provisioning tool",
	}

	rootCmd.AddCommand(aws.NewAWSCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
