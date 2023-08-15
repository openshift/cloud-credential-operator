package main

import (
	"log"
	"os"

	operatorcmd "github.com/openshift/cloud-credential-operator/pkg/cmd/operator"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/render"
	webhookoperatorcmd "github.com/openshift/cloud-credential-operator/pkg/cmd/webhookoperator"
	"github.com/openshift/cloud-credential-operator/pkg/version"
	"github.com/spf13/cobra"
)

/*
Copyright 2018 The OpenShift Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

func main() {
	cmd := &cobra.Command{
		Use:   "cloud-credential-operator",
		Short: "OpenShift cloud credential operator",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
			os.Exit(1)
		},
	}

	if v := version.Get().String(); len(v) == 0 {
		cmd.Version = "<unknown>"
	} else {
		cmd.Version = v
	}

	cmd.AddCommand(operatorcmd.NewOperator())
	cmd.AddCommand(render.NewRenderCommand())
	cmd.AddCommand(webhookoperatorcmd.NewOperator())

	err := cmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
