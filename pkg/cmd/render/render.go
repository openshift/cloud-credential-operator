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

package render

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"text/template"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	corev1 "k8s.io/api/core/v1"
	yaml "k8s.io/apimachinery/pkg/util/yaml"

	operatorv1 "github.com/openshift/api/operator/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	assets "github.com/openshift/cloud-credential-operator/pkg/assets/bootstrap"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

const (
	podYamlFilename = "cloud-credential-operator-pod.yaml"

	podTemplate = `apiVersion: v1
kind: Pod
metadata:
  name: cloud-credential-operator
  namespace: openshift-cloud-credential-operator
spec:
  containers:
  - command:
    - /usr/bin/cloud-credential-operator
    args:
    - operator
    - --log-level=debug
    - --kubeconfig=/etc/kubernetes/secrets/kubeconfig
    image: %s
    imagePullPolicy: IfNotPresent
    name: cloud-credential-operator
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
	defaultLogLevel       = "info"

	installConfigNamespace = "kube-system"
	installConfigName      = "cluster-config-v1"
	installConfigKeyName   = "install-config"

	operatorConfigFilename = "cco-operator-config.yaml"
)

var (
	operatorConfigTemplate = template.Must(template.New("operatorConfig").Parse(`apiVersion: operator.openshift.io/v1
kind: CloudCredential
metadata:
  name: cluster
spec:
  credentialsMode: "{{ .CredentialsMode }}"`))

	renderAssets = []string{
		"bootstrap/cloudcredential_v1_operator_config_crd.yaml",
		"bootstrap/cloudcredential_v1_credentialsrequest_crd.yaml",
		"bootstrap/namespace.yaml",
	}

	renderCmd = &cobra.Command{
		Use:   "render",
		Short: "Render operator manifests",
		Long:  "Have the Cloud Credential Operator render manifests for use as a bootstrap static pod",
		Run:   runRenderCmd,
	}

	renderOpts struct {
		manifestsDir   string
		destinationDir string
		ccoImage       string
		logLevel       string
	}
)

type operatorTemplateVars struct {
	CredentialsMode operatorv1.CloudCredentialsMode
}

func NewRenderCommand() *cobra.Command {
	renderCmd.Flags().StringVar(&renderOpts.manifestsDir, "manifests-dir", "", "The directory where the install-time manifests are located.")
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

	err = render()
	if err != nil {
		log.WithError(err).Fatal("failed while rendering bootstrap assets")
	}
}

func render() error {
	operatorDisabledViaConfigmap := isDisabledViaConfigmap()

	installConfigMode, err := getModeFromInstallConfig()
	if err != nil {
		return err
	}
	if !isValidMode(installConfigMode) {
		return fmt.Errorf("invalid mode defined: %s", installConfigMode)
	}

	effectiveMode, conflict := utils.GetEffectiveOperatorMode(operatorDisabledViaConfigmap, installConfigMode)

	if conflict {
		return fmt.Errorf("config map asking for CCO to be disabled, and install-config asking for %q mode", installConfigMode)
	}

	log.Infof("Rendering files to %s", renderOpts.destinationDir)

	ccoRenderDir := renderOpts.destinationDir

	// render manifests from bindata
	if err := os.MkdirAll(filepath.Join(ccoRenderDir, manifestsDir), 0775); err != nil {
		return errors.Wrap(err, "error creating manifests directory")
	}

	for _, assetName := range renderAssets {
		asset, err := assets.Asset(assetName)
		if err != nil {
			return errors.Wrap(err, "failed to read static asset")
		}

		assetRenderPath := filepath.Join(ccoRenderDir, manifestsDir, "cco-"+filepath.Base(assetName))
		if err := writeFile(assetRenderPath, asset); err != nil {
			return err
		}
	}

	// render operator config
	var operatorConfig bytes.Buffer
	templateVars := operatorTemplateVars{
		CredentialsMode: effectiveMode,
	}

	if err := operatorConfigTemplate.Execute(&operatorConfig, templateVars); err != nil {
		return errors.Wrap(err, "failed to execute operator config template")
	}
	assetRenderPath := filepath.Join(ccoRenderDir, manifestsDir, operatorConfigFilename)
	if err := writeFile(assetRenderPath, operatorConfig.Bytes()); err != nil {
		return err
	}

	// need at least the empty dir so the installer bootkube.sh script works as expected
	if err := os.Mkdir(filepath.Join(ccoRenderDir, bootstrapManifestsDir), 0775); err != nil {
		errors.Wrap(err, "error creating bootstrap-manifests directory")
	}
	if effectiveMode != operatorv1.CloudCredentialsModeManual {
		log.Info("Rendering static pod")
		podPath := filepath.Join(ccoRenderDir, bootstrapManifestsDir, podYamlFilename)
		podContent := fmt.Sprintf(podTemplate, renderOpts.ccoImage)
		log.Infof("writing file: %s", podPath)
		err := ioutil.WriteFile(podPath, []byte(podContent), 0644)
		if err != nil {
			return errors.Wrap(err, "failed to write file")
		}
	} else {
		log.Info("CCO disabled, skipping static pod manifest.")
	}

	return nil
}

func writeFile(filePath string, fileData []byte) error {
	log.Infof("Writing file: %s", filePath)
	err := ioutil.WriteFile(filePath, fileData, 0644)
	if err != nil {
		return errors.Wrap(err, "failed to write file")
	}
	return nil
}

func isValidMode(mode operatorv1.CloudCredentialsMode) bool {
	switch mode {
	case operatorv1.CloudCredentialsModeDefault,
		operatorv1.CloudCredentialsModeManual,
		operatorv1.CloudCredentialsModeMint,
		operatorv1.CloudCredentialsModePassthrough:
		return true
	default:
		return false
	}
}

// isDisabled will search through all the files in destinationDir (which also contains
// the source manifests) for the deprecated configmap indicating whether or not CCO is disabled. In
// the absence of any configmap, it will return the default disabled setting (which is
// that the operator is enabled by default) for the operator.
func isDisabledViaConfigmap() bool {

	// if were were not provided a place to search for the install-time manifests,
	// just return the default CCO operator enabled/disabled value
	if renderOpts.manifestsDir == "" {
		return utils.OperatorDisabledDefault
	}

	cm, err := getConfigMap(renderOpts.manifestsDir, minterv1.CloudCredOperatorNamespace, constants.CloudCredOperatorConfigMap)
	if err != nil {
		log.WithError(err).Warnf("errored while searching for ConfigMap %s/%s, using defaults", minterv1.CloudCredOperatorNamespace, constants.CloudCredOperatorConfigMap)
		return utils.OperatorDisabledDefault
	}
	if cm == nil {
		log.Debugf("configmap %s/%s not found, using default mode", minterv1.CloudCredOperatorNamespace, constants.CloudCredOperatorConfigMap)
		return utils.OperatorDisabledDefault
	}

	disabled, err := utils.CCODisabledCheck(cm, log.WithFields(nil))
	if err != nil {
		return utils.OperatorDisabledDefault
	}

	return disabled
}

type basicInstallConfig struct {
	CredentialsMode operatorv1.CloudCredentialsMode `json:"credentialsMode"`
}

func getModeFromInstallConfig() (operatorv1.CloudCredentialsMode, error) {

	// if we were not provided a place to search for the install-time manifests,
	// just return the default cloudCredentialsMode (empty string)
	if renderOpts.manifestsDir == "" {
		return "", nil
	}

	cm, err := getConfigMap(renderOpts.manifestsDir, installConfigNamespace, installConfigName)
	if err != nil {
		return "", errors.Wrapf(err, "failed to find configmap %s/%s in manifests", installConfigNamespace, installConfigName)
	}
	if cm == nil {
		return "", fmt.Errorf("failed to find configmap %s/%s in manifests", installConfigNamespace, installConfigName)
	}

	data, ok := cm.Data[installConfigKeyName]
	if !ok {
		return "", fmt.Errorf("did not find key %s in configmap %s/%s", installConfigKeyName, installConfigNamespace, installConfigName)
	}

	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader([]byte(data)), 4096)
	instConf := &basicInstallConfig{}
	if err := decoder.Decode(instConf); err != nil {
		return "", errors.Wrap(err, "failed to decode install config")
	}
	log.Debugf("install-config contains CredentialsMode: %s", instConf.CredentialsMode)
	return instConf.CredentialsMode, nil
}

func getConfigMap(manifestsDir, namespace, name string) (*corev1.ConfigMap, error) {

	files, err := ioutil.ReadDir(manifestsDir)
	if err != nil {
		log.WithError(err).Errorf("failed to list files in %s", manifestsDir)
		return nil, err
	}

	for _, fInfo := range files {
		// non-recursive checking of all files where the source manifests are located
		if fInfo.IsDir() {
			continue
		}

		fullPath := filepath.Join(manifestsDir, fInfo.Name())
		log.Debugf("checking file: %s", fullPath)
		file, err := os.Open(fullPath)
		if err != nil {
			log.WithError(err).Warn("failed to open file while searching for configmap")
			continue
		}

		decoder := yaml.NewYAMLOrJSONDecoder(file, 4096)
		configMap := &corev1.ConfigMap{}
		if err := decoder.Decode(configMap); err != nil {
			log.WithError(err).Debug("failed to decode into configmap")
			continue
		}

		if configMap.APIVersion == corev1.SchemeGroupVersion.Identifier() &&
			configMap.Kind == "ConfigMap" &&
			configMap.Namespace == namespace &&
			configMap.Name == name {
			return configMap, nil
		}
	}

	// if we made it this far, then the file was not found
	return nil, nil
}
