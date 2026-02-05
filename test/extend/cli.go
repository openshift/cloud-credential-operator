package extend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	"github.com/tidwall/gjson"
	"k8s.io/apimachinery/pkg/util/wait"
)

// This file provides CLI wrapper and test helper functions for CCO tests.
// It implements a subset of helpers compatible with openshift/origin's exutil/cli patterns,
// keeping the test extension independent from the origin repo while preserving expected behavior.

// Constants for commonly used Kubernetes resources and namespaces
const (
	// DefaultNamespace is the default namespace used by CCO tests
	DefaultNamespace = "openshift-cloud-credential-operator"
	// KubeSystemNamespace is the kube-system namespace
	KubeSystemNamespace = "kube-system"
	// OpenShiftImageRegistryNamespace is the openshift-image-registry namespace
	OpenShiftImageRegistryNamespace = "openshift-image-registry"
	// OpenShiftMonitoringNamespace is the openshift-monitoring namespace
	OpenShiftMonitoringNamespace = "openshift-monitoring"
	// OpenShiftIngressOperatorNamespace is the openshift-ingress-operator namespace
	OpenShiftIngressOperatorNamespace = "openshift-ingress-operator"
	// AWSRootSecretName is the name of the AWS root credentials secret
	AWSRootSecretName = "aws-creds"
	// GCPRootSecretName is the name of the GCP root credentials secret
	GCPRootSecretName = "gcp-credentials"
	// AzureRootSecretName is the name of the Azure root credentials secret
	AzureRootSecretName = "azure-credentials"
	// VSphereRootSecretName is the name of the vSphere root credentials secret
	VSphereRootSecretName = "vsphere-creds"
	// OpenStackRootSecretName is the name of the OpenStack root credentials secret
	OpenStackRootSecretName = "openstack-credentials"
	// OvirtRootSecretName is the name of the oVirt root credentials secret
	OvirtRootSecretName = "ovirt-credentials"
	// InstallerCloudCredentialsSecretName is the name of the installer cloud credentials secret
	InstallerCloudCredentialsSecretName = "installer-cloud-credentials"
	// CloudCredentialsSecretName is the name of the cloud-credentials secret
	CloudCredentialsSecretName = "cloud-credentials"
	// PrometheusK8sServiceAccount is the prometheus-k8s service account name
	PrometheusK8sServiceAccount = "prometheus-k8s"
)

// CLI is a tiny wrapper around the `oc` binary.
type CLI struct {
	id         string
	kubeconfig string
	namespace  string
}

// newCLI creates a CLI wrapper. If kubeconfig isn't provided, it uses kubeConfigPath().
func newCLI(id string, kubeconfig ...string) *CLI {
	kc := kubeConfigPath()
	if len(kubeconfig) > 0 && kubeconfig[0] != "" {
		kc = kubeconfig[0]
	}
	return &CLI{
		id:         id,
		kubeconfig: kc,
		// Default namespace used by origin tests; callers can override or clear.
		namespace: DefaultNamespace,
	}
}

func (c *CLI) Namespace() string { return c.namespace }

func (c *CLI) AsAdmin() *CLI {
	// In modern OpenShift CI, the kubeconfig is typically already cluster-admin.
	// Keep this as a semantic marker and a potential extension point.
	cp := *c
	return &cp
}

func (c *CLI) WithoutNamespace() *CLI {
	cp := *c
	cp.namespace = ""
	return &cp
}

// SetNamespace sets a new namespace for the CLI instance
func (c *CLI) SetNamespace(ns string) *CLI {
	cp := *c
	cp.namespace = ns
	return &cp
}

// Run starts building an `oc` command invocation. This matches the common
// origin/exutil usage pattern: `oc.Run("get").Args(...).Output()`.
func (c *CLI) Run(commands ...string) *CLICommand {
	return &CLICommand{cli: c, commands: append([]string(nil), commands...)}
}

type CLICommand struct {
	cli      *CLI
	commands []string
	args     []string
}

func (cmd *CLICommand) Args(args ...string) *CLICommand {
	cmd.args = append(cmd.args, args...)
	return cmd
}

func (cmd *CLICommand) ocArgs() []string {
	var out []string
	if cmd.cli.kubeconfig != "" {
		out = append(out, fmt.Sprintf("--kubeconfig=%s", cmd.cli.kubeconfig))
	}
	if cmd.cli.namespace != "" {
		out = append(out, fmt.Sprintf("--namespace=%s", cmd.cli.namespace))
	}
	return append(append(out, cmd.commands...), cmd.args...)
}

func (cmd *CLICommand) Outputs() (string, string, error) {
	c := exec.Command("oc", cmd.ocArgs()...)
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	err := c.Run()
	return stdout.String(), stderr.String(), err
}

func (cmd *CLICommand) Output() (string, error) {
	// In origin's helper, "Output" is typically treated as combined output
	// (tests frequently assert error messages that may appear on stderr).
	stdout, stderr, err := cmd.Outputs()
	return stdout + stderr, err
}

func (cmd *CLICommand) Execute() error {
	_, _, err := cmd.Outputs()
	return err
}

func (cmd *CLICommand) OutputToFile(filename string) (string, error) {
	if filename == "" {
		return "", errors.New("filename cannot be empty")
	}
	// Validate filename doesn't contain path traversal attempts
	cleaned := filepath.Clean(filename)
	if cleaned != filename || filepath.IsAbs(filename) {
		return "", fmt.Errorf("filename contains invalid path: %s", filename)
	}
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filename, []byte(out), 0o644); err != nil {
		return "", fmt.Errorf("failed to write file %s: %w", filename, err)
	}
	return filename, nil
}

func kubeConfigPath() string {
	// Match origin's behavior: only return KUBECONFIG env var
	// Note: origin's implementation doesn't fallback to ~/.kube/config,
	// but our fallback is more robust for standalone test extensions
	if kc := os.Getenv("KUBECONFIG"); kc != "" {
		return kc
	}
	// Fallback to default kubeconfig location for better compatibility
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".kube", "config")
}

// logf is a convenience function for logging to GinkgoWriter
func logf(format string, args ...any) {
	fmt.Fprintf(g.GinkgoWriter, format+"\n", args...)
}

func assertWaitPollNoErr(err error, message string) {
	if err != nil {
		g.Fail(fmt.Sprintf("%s: %v", message, err), 1)
	}
}

// --- Capability gating (best-effort, origin compatible-ish) ---

// capabilitiesFromEnv returns a set from common env vars used in CI.
func capabilitiesFromEnv() map[string]struct{} {
	candidates := []string{
		"TEST_CAPABILITIES",
		"OPENSHIFT_TESTS_CAPABILITIES",
		"OPENSHIFT_REQUIRED_CAPABILITIES",
	}
	for _, k := range candidates {
		if raw := os.Getenv(k); strings.TrimSpace(raw) != "" {
			out := map[string]struct{}{}
			for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
				if part = strings.TrimSpace(part); part != "" {
					out[part] = struct{}{}
				}
			}
			return out
		}
	}
	return map[string]struct{}{}
}

func skipNoCapabilities(_ *CLI, requiredCap string) {
	// If capabilities aren't exposed by env, do not skip.
	caps := capabilitiesFromEnv()
	if len(caps) == 0 {
		return
	}
	if _, ok := caps[requiredCap]; !ok {
		g.Skip(fmt.Sprintf("missing required capability %q", requiredCap))
	}
}

// skipIfCapEnabled skips the test if a capability is enabled
func skipIfCapEnabled(oc *CLI, capability string) {
	clusterversionJSON, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("clusterversion", "version", "-o=json").Output()
	o.Expect(err).NotTo(o.HaveOccurred())

	// Check if capability is known (i.e., can be disabled)
	knownCapsJSON := gjson.Get(clusterversionJSON, "status.capabilities.knownCapabilities")
	capKnown := false
	if knownCapsJSON.Exists() {
		for _, knownCap := range knownCapsJSON.Array() {
			if knownCap.String() == capability {
				capKnown = true
				break
			}
		}
	}
	if !capKnown {
		g.Skip(fmt.Sprintf("Will skip as capability %s is unknown (i.e. cannot be disabled in the first place)", capability))
	}

	// Check if capability is enabled
	enabledCapsJSON := gjson.Get(clusterversionJSON, "status.capabilities.enabledCapabilities")
	if enabledCapsJSON.Exists() {
		for _, enabledCap := range enabledCapsJSON.Array() {
			if enabledCap.String() == capability {
				g.Skip(fmt.Sprintf("Will skip as capability %s is enabled", capability))
			}
		}
	}
}

// isHyperShiftCluster checks if the cluster has an externally hosted control plane
func IsHypershiftHostedCluster(oc *CLI) bool {
	topology, err := oc.WithoutNamespace().AsAdmin().Run("get").Args("infrastructures.config.openshift.io", "cluster", "-o=jsonpath={.status.controlPlaneTopology}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	logf("topology is %s", topology)
	if topology == "" {
		status, _ := oc.WithoutNamespace().AsAdmin().Run("get").Args("infrastructures.config.openshift.io", "cluster", "-o=jsonpath={.status}").Output()
		logf("cluster status %s", status)
		g.Fail("failure: controlPlaneTopology returned empty", 1)
	}
	return strings.Compare(topology, "External") == 0
}

// skipIfHypershiftHostedCluster skips the test if the cluster has an externally hosted control plane
func skipIfHypershiftHostedCluster(oc *CLI) {
	if IsHypershiftHostedCluster(oc) {
		g.Skip("Test is skipped on externally hosted control plane clusters (e.g., HyperShift)")
	}
}

// skipIfMicroShift skips the test if the cluster is MicroShift
func skipIfMicroShift(oc *CLI) {
	if isMicroshiftCluster(oc) {
		g.Skip("Test is skipped on MicroShift clusters")
	}
}

func isSNOCluster(oc *CLI) bool {
	stdout, _, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("nodes", "--no-headers").Outputs()
	if err != nil {
		return false
	}
	count := 0
	for _, l := range strings.Split(stdout, "\n") {
		if strings.TrimSpace(l) != "" {
			count++
			if count > 1 {
				return false
			}
		}
	}
	return count == 1
}

// --- Cluster info helpers ---

func getClusterVersion(oc *CLI) (string, string, error) {
	ver, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("clusterversion", "version", "-o=jsonpath={.status.desired.version}").Output()
	if err != nil {
		return "", "", err
	}
	ver = strings.TrimSpace(ver)
	parts := strings.Split(ver, ".")
	if len(parts) < 2 {
		return "", ver, fmt.Errorf("unexpected cluster version format %q", ver)
	}
	return fmt.Sprintf("%s.%s", parts[0], parts[1]), ver, nil
}

func getSAToken(oc *CLI) (string, error) {
	// Prefer `oc create token` (newer). Fall back to legacy `sa get-token`.
	token, err := oc.AsAdmin().WithoutNamespace().Run("create").Args("token", PrometheusK8sServiceAccount, "-n", OpenShiftMonitoringNamespace).Output()
	if err == nil {
		if trimmed := strings.TrimSpace(token); trimmed != "" {
			return trimmed, nil
		}
	}

	// Legacy fallback.
	token, err2 := oc.AsAdmin().WithoutNamespace().Run("sa").Args("get-token", PrometheusK8sServiceAccount, "-n", OpenShiftMonitoringNamespace).Output()
	if err2 == nil {
		if trimmed := strings.TrimSpace(token); trimmed != "" {
			return trimmed, nil
		}
	}

	// Return error from first method if available, otherwise second
	if err != nil {
		return "", fmt.Errorf("create token failed: %w", err)
	}
	if err2 != nil {
		return "", fmt.Errorf("sa get-token failed: %w", err2)
	}
	return "", errors.New("failed to obtain serviceaccount token: both methods returned empty tokens")
}

// applyNsResourceFromTemplate renders a template (via `oc process`) and applies it.
// Signature and semantics match common origin helpers used in tests.
func applyNsResourceFromTemplate(oc *CLI, ns string, args ...string) {
	if ns == "" {
		g.Fail("namespace cannot be empty", 1)
	}
	// Render template
	processArgs := append([]string{"process", "-n", ns}, args...)
	renderArgs := processArgs
	if oc.kubeconfig != "" {
		renderArgs = append([]string{fmt.Sprintf("--kubeconfig=%s", oc.kubeconfig)}, processArgs...)
	}
	render := exec.Command("oc", renderArgs...)
	var rendered, renderErr bytes.Buffer
	render.Stdout = &rendered
	render.Stderr = &renderErr
	if err := render.Run(); err != nil {
		stderr := strings.TrimSpace(renderErr.String())
		if stderr == "" {
			stderr = "(no stderr output)"
		}
		g.Fail(fmt.Sprintf("oc process failed in namespace %q: %v: %s", ns, err, stderr), 1)
	}

	// Apply
	applyArgs := []string{"apply", "-n", ns, "-f", "-"}
	if oc.kubeconfig != "" {
		applyArgs = append([]string{fmt.Sprintf("--kubeconfig=%s", oc.kubeconfig)}, applyArgs...)
	}
	apply := exec.Command("oc", applyArgs...)
	apply.Stdin = bytes.NewReader(rendered.Bytes())
	var applyErr bytes.Buffer
	apply.Stderr = &applyErr
	if err := apply.Run(); err != nil {
		stderr := strings.TrimSpace(applyErr.String())
		if stderr == "" {
			stderr = "(no stderr output)"
		}
		g.Fail(fmt.Sprintf("oc apply failed in namespace %q: %v: %s", ns, err, stderr), 1)
	}
}

// IsMicroshiftCluster determines whether the cluster is a MicroShift cluster
// Parameters:
//   - oc: CLI client for interacting with the OpenShift cluster
//
// Returns:
//   - bool: true if cluster is MicroShift, false otherwise
func isMicroshiftCluster(oc *CLI) bool {
	return !isCRDSpecificFieldExist(oc, "template.apiVersion")
}

// isCRDSpecificFieldExist checks whether the specified CRD field exists in the cluster
// Parameters:
//   - oc: CLI client for interacting with the OpenShift cluster
//   - crdFieldPath: path to the CRD field to check (e.g., "template.apiVersion")
//
// Returns:
//   - bool: true if the CRD field exists, false otherwise
func isCRDSpecificFieldExist(oc *CLI, crdFieldPath string) bool {
	var (
		crdFieldInfo string
		getInfoErr   error
	)
	err := wait.PollUntilContextTimeout(context.TODO(), 5*time.Second, 30*time.Second, false, func(ctx context.Context) (bool, error) {
		crdFieldInfo, getInfoErr = oc.AsAdmin().WithoutNamespace().Run("explain").Args(crdFieldPath).Output()
		if getInfoErr != nil && strings.Contains(crdFieldInfo, "the server doesn't have a resource type") {
			if strings.Contains(crdFieldInfo, "the server doesn't have a resource type") {
				logf("The test cluster specified crd field: %s is not exist.", crdFieldPath)
				return true, nil
			}
			// TODO: The "couldn't find resource" error info sometimes(very low frequency) happens in few cases but I couldn't reproduce it, this retry solution should be an enhancement
			if strings.Contains(getInfoErr.Error(), "couldn't find resource") {
				logf("Failed to check whether the specified crd field: %s exist, try again. Err:\n%v", crdFieldPath, getInfoErr)
				return false, nil
			}
			return false, getInfoErr
		}
		return true, nil
	})
	if err != nil {
		g.Skip(fmt.Sprintf("Check whether the specified: %s crd field exist with err %v for case, so skip it.", crdFieldPath, err))
	}
	return !strings.Contains(crdFieldInfo, "the server doesn't have a resource type")
}

// IsRosaCluster determines whether the cluster is a Red Hat OpenShift Service on AWS (ROSA) cluster
// Parameters:
//   - oc: CLI client for interacting with the OpenShift cluster
//
// Returns:
//   - bool: true if cluster is ROSA, false otherwise
func isRosaCluster(oc *CLI) bool {
	product, _ := oc.WithoutNamespace().AsAdmin().Run("get").Args("clusterclaims/product.open-cluster-management.io", "-o=jsonpath={.spec.value}").Output()
	return strings.Compare(product, "ROSA") == 0
}
