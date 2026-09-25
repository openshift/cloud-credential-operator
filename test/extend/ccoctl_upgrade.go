package extend

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
)

const ccoctlSecretManifest = `apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
stringData:
  credentials: %s
`

var _ = g.Describe("[Jira:\"CCO-765\"] ccoctl simplified upgrade workflow", func() {
	var oc = newCLI("ccoctl-simplified-upgrade")

	g.JustBeforeEach(func() {
		skipIfMicroShift(oc)
		skipIfHypershiftHostedCluster(oc)
		skipNoCapabilities(oc, ccoCap)
	})

	g.It("[Suite:cco/conformance/parallel] applies generated secrets and sets the upgradeable annotation through the production command handlers", func() {
		namespace := "ccoctl-upgrade-" + rand.String(8)
		err := oc.AsAdmin().WithoutNamespace().Run("create").Args("namespace", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer func() {
			cleanupErr := oc.AsAdmin().WithoutNamespace().Run("delete").Args(
				"namespace", namespace, "--ignore-not-found=true", "--wait=true", "--timeout=2m",
			).Execute()
			o.Expect(cleanupErr).NotTo(o.HaveOccurred())
		}()

		g.By("applying and updating a generated Secret through the apply secrets handler")
		targetDir, err := os.MkdirTemp("", "ccoctl-upgrade-")
		o.Expect(err).NotTo(o.HaveOccurred())
		defer os.RemoveAll(targetDir)

		manifestsDir := filepath.Join(targetDir, provisioning.ManifestsDirName)
		err = os.MkdirAll(manifestsDir, 0o700)
		o.Expect(err).NotTo(o.HaveOccurred())

		secretName := "ccoctl-upgrade"
		manifestPath := filepath.Join(manifestsDir, secretName+".yaml")
		writeSecretManifest(manifestPath, secretName, namespace, "initial")

		err = runApplySecretsCommand("--output-dir="+targetDir, "--kubeconfig="+oc.kubeconfig)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(readSecretCredential(oc, namespace, secretName)).To(o.Equal("initial"))

		writeSecretManifest(manifestPath, secretName, namespace, "updated")
		err = runApplySecretsCommand("--output-dir="+targetDir, "--kubeconfig="+oc.kubeconfig)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(readSecretCredential(oc, namespace, secretName)).To(o.Equal("updated"))

		g.By("saving the current upgradeable-to annotation")
		originalAnnotation, err := oc.AsAdmin().WithoutNamespace().Run("get").Args(
			"cloudcredential", constants.CloudCredOperatorConfig,
			"-o=jsonpath={.metadata.annotations.cloudcredential\\.openshift\\.io/upgradeable-to}",
		).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		originalAnnotation = strings.TrimSpace(originalAnnotation)
		defer func() {
			o.Expect(restoreUpgradeableAnnotation(oc, originalAnnotation)).To(o.Succeed())
		}()

		currentMajorMinor, _, err := getClusterVersion(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		targetVersion := nextMinorVersion(currentMajorMinor)

		g.By("setting the upgradeable-to annotation through the production handler")
		err = runSetUpgradeableToCommand("--kubeconfig="+oc.kubeconfig, targetVersion)
		o.Expect(err).NotTo(o.HaveOccurred())

		annotation, getErr := oc.AsAdmin().WithoutNamespace().Run("get").Args(
			"cloudcredential", constants.CloudCredOperatorConfig,
			"-o=jsonpath={.metadata.annotations.cloudcredential\\.openshift\\.io/upgradeable-to}",
		).Output()
		o.Expect(getErr).NotTo(o.HaveOccurred())
		o.Expect(strings.TrimSpace(annotation)).To(o.Equal(targetVersion))
	})
})

func runApplySecretsCommand(args ...string) error {
	provisioning.ApplySecretsOpts.TargetDir = ""
	provisioning.ApplySecretsOpts.KubeConfigFile = ""
	cmd := provisioning.NewApplySecretsCmd()
	cmd.SetArgs(args)
	cmd.SetOut(g.GinkgoWriter)
	cmd.SetErr(g.GinkgoWriter)
	return cmd.Execute()
}

func runSetUpgradeableToCommand(args ...string) error {
	provisioning.SetUpgradeableToOpts.KubeConfigFile = ""
	cmd := provisioning.NewSetUpgradeableToCmd()
	cmd.SetArgs(args)
	cmd.SetOut(g.GinkgoWriter)
	cmd.SetErr(g.GinkgoWriter)
	return cmd.Execute()
}

func writeSecretManifest(path, name, namespace, credential string) {
	manifest := fmt.Sprintf(ccoctlSecretManifest, name, namespace, credential)
	o.Expect(os.WriteFile(path, []byte(manifest), 0o600)).To(o.Succeed())
}

func readSecretCredential(oc *CLI, namespace, name string) string {
	encoded, err := oc.AsAdmin().WithoutNamespace().Run("get").Args(
		"secret", name, "-n", namespace, "-o=jsonpath={.data.credentials}",
	).Output()
	o.Expect(err).NotTo(o.HaveOccurred())

	credential, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	o.Expect(err).NotTo(o.HaveOccurred())
	return string(credential)
}

func nextMinorVersion(current string) string {
	parts := strings.Split(current, ".")
	o.Expect(parts).To(o.HaveLen(2))

	minor, err := strconv.Atoi(parts[1])
	o.Expect(err).NotTo(o.HaveOccurred())
	return fmt.Sprintf("%s.%d", parts[0], minor+1)
}

func restoreUpgradeableAnnotation(oc *CLI, value string) error {
	annotationValue := any(value)
	if value == "" {
		annotationValue = nil
	}

	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]any{
				constants.UpgradeableAnnotation: annotationValue,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to build annotation cleanup patch: %w", err)
	}

	return oc.AsAdmin().WithoutNamespace().Run("patch").Args(
		"cloudcredential", constants.CloudCredOperatorConfig, "--type=merge", "-p", string(patch),
	).Execute()
}
