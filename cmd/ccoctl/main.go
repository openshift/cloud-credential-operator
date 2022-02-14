package main

import (
	"log"

	"github.com/spf13/cobra"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/alibabacloud"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/aws"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/gcp"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/ibmcloud"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/nutanix"
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
	rootCmd.AddCommand(nutanix.NewNutanixCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
