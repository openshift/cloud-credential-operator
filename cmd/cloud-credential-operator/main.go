package main

import (
	"log"
	"os"

	"github.com/go-logr/logr"
	operatorcmd "github.com/openshift/cloud-credential-operator/pkg/cmd/operator"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/render"
	"github.com/openshift/cloud-credential-operator/pkg/version"
	"github.com/spf13/cobra"
	ctrlruntimelog "sigs.k8s.io/controller-runtime/pkg/log"
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

func init() {
	// This is required because controller-runtime expects its consumers to
	// set a logger through log.SetLogger within 30 seconds of the program's
	// initalization. We have our own logger and can configure controller-runtime's
	// logger to do nothing.
	ctrlruntimelog.SetLogger(logr.New(ctrlruntimelog.NullLogSink{}))
}

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

	err := cmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
