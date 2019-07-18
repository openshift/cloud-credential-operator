/*
Copyright 2019 The OpenShift Authors.

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

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/openshift/cloud-credential-operator/pkg/assets"
)

const (
	podTemplate = `apiVersion: v1
kind: Pod
metadata:
  name: cloud-credential-operator
  namespace: openshift-cloud-credential-operator
spec:
  containers:
  - command:
    - /root/manager
    args:
    - --log-level=debug
    - --kubeconfig=/etc/kubernetes/secrets/kubeconfig
    image: %s
    imagePullPolicy: IfNotPresent
    name: manager
    volumeMounts:
    - mountPath: /etc/kubernetes/secrets
      name: secrets
      readOnly: true
  hostNetwork: true
  volumes:
  - hostPath:
      path: /etc/kubernetes/bootstrap-secrets
    name: secrets`
)

const (
	manifestsDir          = "manifests"
	bootstrapManifestsDir = "bootstrap-manifests"
)

var (
	renderAssets = []string{
		"config/crds/cloudcredential_v1_credentialsrequest.yaml",
		"config/manager/namespace.yaml",
	}

	renderCmd = &cobra.Command{
		Use:   "render",
		Short: "Cloud Credential Operator render manifests",
		Long:  "Have the Cloud Credential Operator render manifests for use as a bootstrap static pod",
		Run:   runRenderCmd,
	}

	renderOpts struct {
		destinationDir string
		ccoImage       string
		logLevel       string
	}
)

func newRenderCommand() *cobra.Command {
	renderCmd.Flags().StringVar(&renderOpts.destinationDir, "dest-dir", "", "The destination directory where CCO writes the manifests.")
	renderCmd.MarkFlagRequired("dest-dir")
	renderCmd.Flags().StringVar(&renderOpts.ccoImage, "cloud-credential-operator-image", "", "Image for Cloud Credential Operator.")
	renderCmd.MarkFlagRequired("cloud-credential-operator-image")
	renderCmd.Flags().StringVar(&renderOpts.logLevel, "log-level", defaultLogLevel, "Logging verbosity")

	return renderCmd
}

func runRenderCmd(cmd *cobra.Command, args []string) {
	// Set log level
	level, err := log.ParseLevel(renderOpts.logLevel)
	if err != nil {
		log.WithError(err).Fatal("Cannot parse log level")
	}
	log.SetLevel(level)
	log.Debug("debug logging enabled")

	log.Infof("Rendering files to %s", renderOpts.destinationDir)

	ccoRenderDir := renderOpts.destinationDir

	// render manifests
	if err := os.MkdirAll(filepath.Join(ccoRenderDir, manifestsDir), 0775); err != nil {
		log.WithError(err).Fatal("error creating manifests directory")
	}

	for _, assetName := range renderAssets {
		asset, err := assets.Asset(assetName)
		if err != nil {
			log.WithError(err).Fatal("failed to read static asset")
		}

		assetRenderPath := filepath.Join(ccoRenderDir, "manifests", "cco-"+filepath.Base(assetName))
		log.Debugf("writing file: %s", assetRenderPath)
		err = ioutil.WriteFile(assetRenderPath, asset, 0644)
		if err != nil {
			log.WithError(err).Fatal("failed to write file")
		}
	}

	// render static pod
	if err := os.Mkdir(filepath.Join(ccoRenderDir, bootstrapManifestsDir), 0775); err != nil {
		log.WithError(err).Fatal("error creating bootstrap-manifests directory")
	}
	podPath := filepath.Join(ccoRenderDir, bootstrapManifestsDir, "cloud-credential-operator-pod.yaml")
	podContent := fmt.Sprintf(podTemplate, renderOpts.ccoImage)
	log.Debugf("writing file: %s", podPath)
	err = ioutil.WriteFile(podPath, []byte(podContent), 0644)
	if err != nil {
		log.WithError(err).Fatal("failed to write file")
	}
}
