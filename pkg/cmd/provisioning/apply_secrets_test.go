package provisioning

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const secretManifestTemplate = `apiVersion: v1
kind: Secret
metadata:
  name: %s
  namespace: %s
stringData:
  credentials: %s
`

const clusterAuthenticationManifest = `apiVersion: config.openshift.io/v1
kind: Authentication
metadata:
  name: cluster
spec:
  serviceAccountIssuer: https://example.com
`

func secretManifest(name, namespace, credentials string) string {
	return fmt.Sprintf(secretManifestTemplate, name, namespace, credentials)
}

// writeManifests creates <dir>/manifests populated with the given filename -> content pairs.
func writeManifests(t *testing.T, dir string, manifests map[string]string) string {
	t.Helper()

	manifestsDir := filepath.Join(dir, ManifestsDirName)
	require.NoError(t, os.MkdirAll(manifestsDir, 0700))

	for name, content := range manifests {
		require.NoError(t, os.WriteFile(filepath.Join(manifestsDir, name), []byte(content), 0600))
	}

	return manifestsDir
}

func TestLoadSecretManifests(t *testing.T) {
	tests := []struct {
		name            string
		manifests       map[string]string
		omitManifestDir bool
		expectedSecrets []string
		expectedErr     string
	}{
		{
			name: "loads secrets from the manifests directory",
			manifests: map[string]string{
				"openshift-image-registry-installer-cloud-credentials-credentials.yaml": secretManifest("installer-cloud-credentials", "openshift-image-registry", "a"),
				"openshift-ingress-operator-cloud-credentials-credentials.yaml":         secretManifest("cloud-credentials", "openshift-ingress-operator", "b"),
			},
			expectedSecrets: []string{
				"openshift-image-registry/installer-cloud-credentials",
				"openshift-ingress-operator/cloud-credentials",
			},
		},
		{
			name: "ignores non-Secret manifests",
			manifests: map[string]string{
				"cluster-authentication-02-config.yaml": clusterAuthenticationManifest,
				"secret.yaml":                           secretManifest("cloud-credentials", "openshift-ingress-operator", "a"),
			},
			expectedSecrets: []string{"openshift-ingress-operator/cloud-credentials"},
		},
		{
			name: "ignores non-yaml files and reads .yml",
			manifests: map[string]string{
				"01-create-role.sh": "#!/bin/sh\necho hello\n",
				"secret.yml":        secretManifest("cloud-credentials", "openshift-ingress-operator", "a"),
			},
			expectedSecrets: []string{"openshift-ingress-operator/cloud-credentials"},
		},
		{
			name: "reads multi-document manifests",
			manifests: map[string]string{
				"secrets.yaml": secretManifest("first", "ns-one", "a") + "---\n" + secretManifest("second", "ns-two", "b"),
			},
			expectedSecrets: []string{"ns-one/first", "ns-two/second"},
		},
		{
			name:            "empty manifests directory yields no secrets",
			manifests:       map[string]string{},
			expectedSecrets: []string{},
		},
		{
			name: "manifests directory with only non-Secrets yields no secrets",
			manifests: map[string]string{
				"cluster-authentication-02-config.yaml": clusterAuthenticationManifest,
			},
			expectedSecrets: []string{},
		},
		{
			name:            "missing manifests directory is a clear error",
			omitManifestDir: true,
			expectedErr:     "does not exist",
		},
		{
			name: "malformed yaml names the offending file",
			manifests: map[string]string{
				"broken.yaml": "apiVersion: v1\nkind: Secret\n\tmetadata: oops\n",
			},
			expectedErr: "broken.yaml",
		},
		{
			name: "secret without a name is rejected",
			manifests: map[string]string{
				"nameless.yaml": "apiVersion: v1\nkind: Secret\nmetadata:\n  namespace: openshift-ingress-operator\n",
			},
			expectedErr: "without a name",
		},
		{
			// Without this check the secret reaches the cluster stage and fails there as
			// "target namespace(s)  do not exist", which blames the kubeconfig for what is
			// really a malformed file, and does not say which file.
			name: "secret without a namespace is rejected",
			manifests: map[string]string{
				"namespaceless.yaml": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: cloud-credentials\n",
			},
			expectedErr: "namespaceless.yaml contains Secret cloud-credentials without a namespace",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			targetDir := t.TempDir()
			manifestsDir := filepath.Join(targetDir, ManifestsDirName)
			if !test.omitManifestDir {
				manifestsDir = writeManifests(t, targetDir, test.manifests)
			}

			secrets, err := loadSecretManifests(manifestsDir)

			if test.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.expectedErr)
				return
			}

			require.NoError(t, err)

			loaded := []string{}
			for _, secret := range secrets {
				loaded = append(loaded, secret.GetNamespace()+"/"+secret.GetName())
			}
			assert.ElementsMatch(t, test.expectedSecrets, loaded)
		})
	}
}

// TestRunApplySecrets covers the cobra command path up to the point a cluster client is needed.
// Both the missing-directory and nothing-to-apply cases return before any client is built, so
// they exercise flag handling and output-dir resolution without a cluster.
func TestRunApplySecrets(t *testing.T) {
	tests := []struct {
		name            string
		manifests       map[string]string
		omitManifestDir bool
		useDefaultDir   bool
		expectedErr     string
	}{
		{
			name:            "missing manifests directory is reported through the command",
			omitManifestDir: true,
			expectedErr:     "does not exist",
		},
		{
			name:      "no secrets to apply succeeds without contacting a cluster",
			manifests: map[string]string{"cluster-authentication-02-config.yaml": clusterAuthenticationManifest},
		},
		{
			name:          "output-dir defaults to the current directory",
			manifests:     map[string]string{},
			useDefaultDir: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			targetDir := t.TempDir()
			if !test.omitManifestDir {
				writeManifests(t, targetDir, test.manifests)
			}

			// ApplySecretsOpts is package-level state shared by the aws/azure/gcp command
			// instances, so it has to be restored between subtests.
			t.Cleanup(func() { ApplySecretsOpts = applySecretsOptions{} })

			cmd := NewApplySecretsCmd()
			args := []string{}
			if test.useDefaultDir {
				t.Chdir(targetDir)
			} else {
				args = append(args, "--output-dir="+targetDir)
			}
			cmd.SetArgs(args)

			err := cmd.Execute()

			if test.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.expectedErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestApplySecrets(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))

	newSecret := func(name, namespace, credentials string) *unstructured.Unstructured {
		secret := &unstructured.Unstructured{}
		secret.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: "Secret"})
		secret.SetName(name)
		secret.SetNamespace(namespace)
		require.NoError(t, unstructured.SetNestedStringMap(secret.Object, map[string]string{"credentials": credentials}, "stringData"))
		return secret
	}

	tests := []struct {
		name             string
		existing         []client.Object
		secrets          []*unstructured.Unstructured
		createErrSecrets sets.Set[string]
		expectedErr      string
		expectedApplied  map[string]string
	}{
		{
			name: "creates secrets on a cluster that has none",
			secrets: []*unstructured.Unstructured{
				newSecret("cloud-credentials", "openshift-ingress-operator", "new"),
			},
			expectedApplied: map[string]string{"openshift-ingress-operator/cloud-credentials": "new"},
		},
		{
			name: "updates a secret that already exists",
			existing: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "cloud-credentials", Namespace: "openshift-ingress-operator"},
					StringData: map[string]string{"credentials": "stale"},
				},
			},
			secrets: []*unstructured.Unstructured{
				newSecret("cloud-credentials", "openshift-ingress-operator", "fresh"),
			},
			expectedApplied: map[string]string{"openshift-ingress-operator/cloud-credentials": "fresh"},
		},
		{
			name:            "applying nothing is not an error",
			secrets:         []*unstructured.Unstructured{},
			expectedApplied: map[string]string{},
		},
		{
			name: "a secret failing to apply does not stop the others, and the failure is reported",
			secrets: []*unstructured.Unstructured{
				newSecret("cloud-credentials", "openshift-ingress-operator", "new"),
				newSecret("installer-cloud-credentials", "openshift-image-registry", "new"),
			},
			createErrSecrets: sets.New("openshift-image-registry/installer-cloud-credentials"),
			expectedErr:      "failed to create Secret openshift-image-registry/installer-cloud-credentials",
			expectedApplied:  map[string]string{"openshift-ingress-operator/cloud-credentials": "new"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seeded := append([]client.Object{}, test.existing...)

			funcs := interceptor.Funcs{}
			if test.createErrSecrets.Len() > 0 {
				funcs.Create = func(ctx context.Context, wrapped client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
					if test.createErrSecrets.Has(obj.GetNamespace() + "/" + obj.GetName()) {
						return apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, obj.GetName(), fmt.Errorf("no RBAC"))
					}
					return wrapped.Create(ctx, obj, opts...)
				}
			}

			kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(seeded...).WithInterceptorFuncs(funcs).Build()

			err := applySecrets(context.TODO(), kubeClient, test.secrets)

			if test.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.expectedErr)
			} else {
				require.NoError(t, err)
			}

			for key, expectedCredentials := range test.expectedApplied {
				namespace, name := filepath.Split(key)
				namespace = filepath.Clean(namespace)

				applied := &corev1.Secret{}
				require.NoError(t, kubeClient.Get(context.TODO(), types.NamespacedName{Namespace: namespace, Name: name}, applied))
				assert.Equal(t, expectedCredentials, applied.StringData["credentials"])
			}
		})
	}
}
