package main

import (
	"log"

	"github.com/spf13/cobra"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/alibabacloud"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/aws"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/gcp"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/ibmcloud"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "ccoctl",
		Short: "OpenShift credentials provisioning tool",
	}

	rootCmd.AddCommand(aws.NewAWSCmd())
	rootCmd.AddCommand(gcp.NewGCPCmd())
	rootCmd.AddCommand(ibmcloud.NewIBMCloudCmd())
	rootCmd.AddCommand(alibabacloud.NewAliababaCloudCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
