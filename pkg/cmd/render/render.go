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
	"os"
	"path/filepath"

	v1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	sigsyaml "sigs.k8s.io/yaml"

	operatorv1 "github.com/openshift/api/operator/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	assets "github.com/openshift/cloud-credential-operator/pkg/assets/bootstrap"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

const (
	manifestsDir          = "manifests"
	bootstrapManifestsDir = "bootstrap-manifests"
	defaultLogLevel       = "info"

	installConfigNamespace = "kube-system"
	installConfigName      = "cluster-config-v1"
	installConfigKeyName   = "install-config"

	operatorConfigFilename = "cco-operator-config.yaml"
	podYamlFilename        = "cloud-credential-operator-pod.yaml"
)

var (
	operatorConfig = &operatorv1.CloudCredential{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "operator.openshift.io/v1",
			Kind:       "CloudCredential",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
	}

	renderAssets = []string{
		"bootstrap/cloudcredential_v1_operator_config_custresdef.yaml",
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

	staticPod = &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cloud-credential-operator",
			Namespace: "openshift-cloud-credential-operator",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Args: []string{
					"operator",
					"--log-level=debug",
					"--kubeconfig=/etc/kubernetes/secrets/kubeconfig",
				},
				Command:         []string{"/usr/bin/cloud-credential-operator"},
				ImagePullPolicy: corev1.PullIfNotPresent,
				Name:            "cloud-credential-operator",
				VolumeMounts: []corev1.VolumeMount{{
					MountPath: "/etc/pki/ca-trust/extracted/pem",
					Name:      "cco-trusted-ca",
					ReadOnly:  true,
				}, {
					MountPath: "/etc/kubernetes/secrets",
					Name:      "secrets",
					ReadOnly:  true,
				}},
			}},
			HostNetwork: true,
			Volumes: []corev1.Volume{{
				Name: "cco-trusted-ca",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/etc/pki/ca-trust/extracted/pem",
					},
				},
			}, {
				Name: "secrets",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/etc/kubernetes/bootstrap-secrets",
					},
				},
			}},
		},
	}
)

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

	installConfig, err := getInstallConfig()
	if err != nil {
		return errors.Wrap(err, "failed to read install config")
	}

	installConfigMode := installConfig.CredentialsMode

	if !isValidMode(installConfigMode) {
		return fmt.Errorf("invalid mode defined: %s", installConfigMode)
	}

	if isDisabledViaCapability(installConfig.Capabilities) {
		return nil
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
	operatorConfig.Spec.CredentialsMode = effectiveMode

	log.Info("Rendering operator manifest")
	operatorPath := filepath.Join(ccoRenderDir, manifestsDir, operatorConfigFilename)

	operatorContent, err := sigsyaml.Marshal(&operatorConfig)
	if err != nil {
		return errors.Wrap(err, "failed to encode yaml")
	}

	err = writeFile(operatorPath, operatorContent)
	if err != nil {
		return err
	}

	// need at least the empty dir so the installer bootkube.sh script works as expected
	if err := os.Mkdir(filepath.Join(ccoRenderDir, bootstrapManifestsDir), 0775); err != nil {
		return errors.Wrap(err, "error creating bootstrap-manifests directory")
	}
	if effectiveMode != operatorv1.CloudCredentialsModeManual {
		log.Info("Rendering static pod manifest")
		podPath := filepath.Join(ccoRenderDir, bootstrapManifestsDir, podYamlFilename)

		staticPod.Spec.Containers[0].Image = renderOpts.ccoImage

		if installConfig.Proxy != nil {
			if installConfig.Proxy.HTTPProxy != "" {
				staticPod.Spec.Containers[0].Env = append(staticPod.Spec.Containers[0].Env, corev1.EnvVar{
					Name:  "HTTP_PROXY",
					Value: installConfig.Proxy.HTTPProxy,
				})
			}

			if installConfig.Proxy.HTTPSProxy != "" {
				staticPod.Spec.Containers[0].Env = append(staticPod.Spec.Containers[0].Env, corev1.EnvVar{
					Name:  "HTTPS_PROXY",
					Value: installConfig.Proxy.HTTPSProxy,
				})
			}

			if installConfig.Proxy.NoProxy != "" {
				staticPod.Spec.Containers[0].Env = append(staticPod.Spec.Containers[0].Env, corev1.EnvVar{
					Name:  "NO_PROXY",
					Value: installConfig.Proxy.NoProxy,
				})
			}
		}

		podContent, err := sigsyaml.Marshal(&staticPod)
		if err != nil {
			return errors.Wrap(err, "failed to encode yaml")
		}

		err = writeFile(podPath, podContent)
		if err != nil {
			return err
		}
	} else {
		log.Info("CCO disabled, skipping static pod manifest.")
	}

	return nil
}

func isDisabledViaCapability(capabilities *v1.ClusterVersionCapabilitiesSpec) bool {
	baselineSet := v1.ClusterVersionCapabilitySetCurrent
	if capabilities != nil && capabilities.BaselineCapabilitySet != "" {
		baselineSet = capabilities.BaselineCapabilitySet
	}

	enabledCaps := sets.New[v1.ClusterVersionCapability](v1.ClusterVersionCapabilitySets[baselineSet]...)
	if capabilities != nil {
		enabledCaps.Insert(capabilities.AdditionalEnabledCapabilities...)
	}

	return !enabledCaps.Has(v1.ClusterVersionCapabilityCloudCredential)
}

func writeFile(filePath string, fileData []byte) error {
	log.Infof("Writing file: %s", filePath)
	err := os.WriteFile(filePath, fileData, 0644)
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

type Proxy struct {
	// +optional
	HTTPProxy string `json:"httpProxy,omitempty"`

	// +optional
	HTTPSProxy string `json:"httpsProxy,omitempty"`

	// +optional
	NoProxy string `json:"noProxy,omitempty"`
}

type basicInstallConfig struct {
	CredentialsMode operatorv1.CloudCredentialsMode    `json:"credentialsMode"`
	Capabilities    *v1.ClusterVersionCapabilitiesSpec `json:"capabilities"`

	// +optional
	Proxy *Proxy `json:"proxy,omitempty"`
}

func getInstallConfig() (*basicInstallConfig, error) {
	instConf := &basicInstallConfig{}

	// if we were not provided a place to search for the install-time manifests,
	// just return the default cloudCredentialsMode (empty string)
	if renderOpts.manifestsDir == "" {
		return instConf, nil
	}

	cm, err := getConfigMap(renderOpts.manifestsDir, installConfigNamespace, installConfigName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to find configmap %s/%s in manifests", installConfigNamespace, installConfigName)
	}
	if cm == nil {
		return nil, fmt.Errorf("failed to find configmap %s/%s in manifests", installConfigNamespace, installConfigName)
	}

	data, ok := cm.Data[installConfigKeyName]
	if !ok {
		return nil, fmt.Errorf("did not find key %s in configmap %s/%s", installConfigKeyName, installConfigNamespace, installConfigName)
	}

	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader([]byte(data)), 4096)
	if err := decoder.Decode(instConf); err != nil {
		return nil, errors.Wrap(err, "failed to decode install config")
	}
	log.Debugf("install-config contains CredentialsMode: %s", instConf.CredentialsMode)

	return instConf, nil
}

func getConfigMap(manifestsDir, namespace, name string) (*corev1.ConfigMap, error) {

	files, err := os.ReadDir(manifestsDir)
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
