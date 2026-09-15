package provisioning

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ccoctlFieldManager is the server-side apply field manager that ccoctl claims ownership under.
const ccoctlFieldManager = "ccoctl"

type applySecretsOptions struct {
	TargetDir      string
	KubeConfigFile string
}

var (
	// ApplySecretsOpts captures the options that affect applying generated secret manifests.
	ApplySecretsOpts = applySecretsOptions{}
)

// NewApplyCmd provides the "apply" subcommand, grouping commands that push previously
// generated manifests to a cluster.
func NewApplyCmd() *cobra.Command {
	applyCmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply previously generated manifests to a cluster",
	}

	applyCmd.AddCommand(NewApplySecretsCmd())

	return applyCmd
}

// NewApplySecretsCmd provides the "apply secrets" subcommand
func NewApplySecretsCmd() *cobra.Command {
	applySecretsCmd := &cobra.Command{
		Use:   "secrets",
		Short: "Apply generated secret manifests to a cluster",
		Long: "Apply the Secret manifests previously generated into <output-dir>/manifests " +
			"to the cluster. Manifests of any other kind are ignored.",
		RunE: runApplySecrets,
		// main.go already reports whatever Execute returns, so letting cobra print it too
		// would show every error twice.
		SilenceErrors: true,
	}

	applySecretsCmd.PersistentFlags().StringVar(&ApplySecretsOpts.TargetDir, "output-dir", "", "Directory containing the generated manifests directory (defaults to current directory)")
	applySecretsCmd.PersistentFlags().StringVar(&ApplySecretsOpts.KubeConfigFile, "kubeconfig", "", "Path to the kubeconfig file (defaults to $KUBECONFIG, then ~/.kube/config)")

	return applySecretsCmd
}

func runApplySecrets(cmd *cobra.Command, args []string) error {
	// Flags parsed successfully, so anything that fails from here on is a runtime problem
	// rather than misuse. Printing the usage block after it would bury the message.
	cmd.SilenceUsage = true

	targetDir := ApplySecretsOpts.TargetDir
	if targetDir == "" {
		pwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
		targetDir = pwd
	}

	targetDir, err := filepath.Abs(targetDir)
	if err != nil {
		return fmt.Errorf("failed to resolve full path: %w", err)
	}

	// Read and validate the manifests before touching the cluster so that a bad
	// output directory fails without any API calls.
	secrets, err := loadSecretManifests(filepath.Join(targetDir, ManifestsDirName))
	if err != nil {
		return err
	}

	if len(secrets) == 0 {
		log.Printf("WARNING: No Secret manifests found in %s, nothing to apply", filepath.Join(targetDir, ManifestsDirName))
		return nil
	}

	kubeClient, err := newClusterClient(ApplySecretsOpts.KubeConfigFile)
	if err != nil {
		return err
	}

	return applySecrets(cmd.Context(), kubeClient, secrets)
}

// loadSecretManifests reads every YAML document in manifestsDir and returns the ones
// that are core v1 Secrets. Other kinds are ignored: the directory also holds
// install-time manifests such as cluster-authentication-02-config.yaml which must not
// be applied to a running cluster.
func loadSecretManifests(manifestsDir string) ([]*unstructured.Unstructured, error) {
	entries, err := os.ReadDir(manifestsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("manifests directory %s does not exist, run the create command for your cloud first or pass --output-dir", manifestsDir)
		}
		return nil, fmt.Errorf("failed to read manifests directory %s: %w", manifestsDir, err)
	}

	secrets := make([]*unstructured.Unstructured, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !(strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml")) {
			continue
		}

		manifestPath := filepath.Join(manifestsDir, entry.Name())
		fileSecrets, err := decodeSecretsFromFile(manifestPath)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, fileSecrets...)
	}

	return secrets, nil
}

func decodeSecretsFromFile(manifestPath string) ([]*unstructured.Unstructured, error) {
	manifestFile, err := os.Open(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open manifest %s: %w", manifestPath, err)
	}
	defer manifestFile.Close()

	secrets := []*unstructured.Unstructured{}
	decoder := yaml.NewYAMLOrJSONDecoder(manifestFile, 4096)
	for {
		manifest := &unstructured.Unstructured{}
		if err := decoder.Decode(manifest); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to parse manifest %s: %w", manifestPath, err)
		}

		// An empty YAML document decodes without error into an object with no content.
		if len(manifest.Object) == 0 {
			continue
		}

		if manifest.GetAPIVersion() != "v1" || manifest.GetKind() != "Secret" {
			log.Printf("Ignoring %s in %s, not a Secret", manifest.GetKind(), manifestPath)
			continue
		}

		if manifest.GetName() == "" {
			return nil, fmt.Errorf("manifest %s contains a Secret without a name", manifestPath)
		}

		if manifest.GetNamespace() == "" {
			return nil, fmt.Errorf("manifest %s contains Secret %s without a namespace", manifestPath, manifest.GetName())
		}

		secrets = append(secrets, manifest)
	}

	return secrets, nil
}

// applySecrets server-side applies the given secrets, halting on the first failure.
//
// ForceOwnership is set because the flow this replaces is "oc apply -f", which stamps the
// kubectl-client-side-apply field manager. Without it, the first ccoctl run against a cluster
// prepared that way conflicts on every secret.
//
// Note that the AWS and Azure secret templates use stringData, which the API server folds into
// data server-side, so ccoctl does not end up owning the data field in managedFields. Applies
// still work, but SSA pruning and conflict detection on data do not behave as they appear to.
// That is acceptable for create-or-overwrite; do not build finer-grained ownership logic on it.
// The GCP template uses data directly and is unaffected.
func applySecrets(ctx context.Context, kubeClient client.Client, secrets []*unstructured.Unstructured) error {
	if err := checkNamespacesExist(ctx, kubeClient, secrets); err != nil {
		return err
	}

	for _, secret := range secrets {
		if err := kubeClient.Apply(ctx, client.ApplyConfigurationFromUnstructured(secret),
			client.FieldOwner(ccoctlFieldManager), client.ForceOwnership); err != nil {
			return fmt.Errorf("failed to apply Secret %s/%s: %w", secret.GetNamespace(), secret.GetName(), err)
		}
		log.Printf("Applied Secret %s/%s", secret.GetNamespace(), secret.GetName())
	}

	log.Printf("Applied %d Secret(s)", len(secrets))
	return nil
}

// checkNamespacesExist reports every target namespace that is missing before anything is
// applied, so that pointing ccoctl at the wrong cluster fails with one clear message rather
// than a raw API error part way through the secrets. It is best-effort: callers that cannot
// read namespaces skip the check rather than being blocked by it.
func checkNamespacesExist(ctx context.Context, kubeClient client.Client, secrets []*unstructured.Unstructured) error {
	checked := sets.New[string]()
	missing := []string{}

	for _, secret := range secrets {
		namespace := secret.GetNamespace()
		if checked.Has(namespace) {
			continue
		}
		checked.Insert(namespace)

		err := kubeClient.Get(ctx, types.NamespacedName{Name: namespace}, &corev1.Namespace{})
		switch {
		case apierrors.IsNotFound(err):
			missing = append(missing, namespace)
		case apierrors.IsForbidden(err):
			// Reading namespaces is not something this command needs, only something that
			// buys a better error message. Credentials scoped to writing secrets should not
			// be turned away here; let the apply surface any real problem.
			continue
		case err != nil:
			return fmt.Errorf("failed to check whether namespace %s exists: %w", namespace, err)
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("target namespace(s) %s do not exist, check that --kubeconfig points at the intended cluster", strings.Join(missing, ", "))
	}

	return nil
}

// newClusterClient builds a client for the cluster identified by kubeConfigFile, falling back
// to $KUBECONFIG and then ~/.kube/config when it is empty.
func newClusterClient(kubeConfigFile string) (client.Client, error) {
	restConfig, err := loadRESTConfig(kubeConfigFile)
	if err != nil {
		return nil, err
	}

	kubeClient, err := client.New(restConfig, client.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	return kubeClient, nil
}

func loadRESTConfig(kubeConfigFile string) (*rest.Config, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeConfigFile != "" {
		loadingRules.ExplicitPath = kubeConfigFile
	}

	restConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig, pass --kubeconfig or set $KUBECONFIG: %w", err)
	}

	return restConfig, nil
}
