package provisioning

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
)

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectedErr string
	}{
		{
			name:     "major.minor is returned unchanged",
			input:    "4.19",
			expected: "4.19",
		},
		{
			name:     "a v prefix is accepted and dropped",
			input:    "v4.19",
			expected: "4.19",
		},
		{
			name:     "a patch version is reduced to major.minor",
			input:    "4.19.3",
			expected: "4.19",
		},
		{
			name:     "a prerelease version is reduced to major.minor",
			input:    "4.19.3-rc.1",
			expected: "4.19",
		},
		{
			// semver.IsValid("v4") is true and semver.MajorMinor("v4") returns "v4.0",
			// so without an explicit check this would silently write a version that
			// never exists.
			name:        "a bare major version is rejected",
			input:       "4",
			expectedErr: `"4" is not a valid version, expected a major.minor version such as 4.19`,
		},
		{
			name:        "a non-version is rejected",
			input:       "next",
			expectedErr: `"next" is not a valid version, expected a major.minor version such as 4.19`,
		},
		{
			name:        "an empty version is rejected",
			input:       "",
			expectedErr: `"" is not a valid version, expected a major.minor version such as 4.19`,
		},
		{
			name:        "a zero-padded version is rejected",
			input:       "04.19",
			expectedErr: `"04.19" is not a valid version, expected a major.minor version such as 4.19`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			normalized, err := normalizeVersion(test.input)

			if test.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.expectedErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.expected, normalized)
		})
	}
}

func TestCheckVersionIsUpgrade(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, configv1.AddToScheme(scheme))

	clusterVersion := func(history ...configv1.UpdateHistory) *configv1.ClusterVersion {
		return &configv1.ClusterVersion{
			ObjectMeta: metav1.ObjectMeta{Name: "version"},
			Status:     configv1.ClusterVersionStatus{History: history},
		}
	}

	completed := func(version string) configv1.UpdateHistory {
		return configv1.UpdateHistory{State: configv1.CompletedUpdate, Version: version}
	}

	partial := func(version string) configv1.UpdateHistory {
		return configv1.UpdateHistory{State: configv1.PartialUpdate, Version: version}
	}

	tests := []struct {
		name        string
		existing    []client.Object
		getErr      error
		version     string
		expectedErr string
	}{
		{
			name:     "a higher minor version is an upgrade",
			existing: []client.Object{clusterVersion(completed("4.18.7"))},
			version:  "4.19",
		},
		{
			name:     "an in-progress update is ignored in favour of the last completed one",
			existing: []client.Object{clusterVersion(partial("4.19.0"), completed("4.18.7"))},
			version:  "4.19",
		},
		{
			name:        "the current version is not an upgrade",
			existing:    []client.Object{clusterVersion(completed("4.19.2"))},
			version:     "4.19",
			expectedErr: "4.19 is not an upgrade from the cluster's current version 4.19",
		},
		{
			name:        "a lower version is not an upgrade",
			existing:    []client.Object{clusterVersion(completed("4.19.2"))},
			version:     "4.18",
			expectedErr: "4.18 is not an upgrade from the cluster's current version 4.19",
		},
		{
			// An unparseable current version must not be treated as "lower than
			// everything", which is what semver.Compare would otherwise do.
			name:        "an unparseable cluster version is fatal",
			existing:    []client.Object{clusterVersion(completed("not-a-version"))},
			version:     "4.19",
			expectedErr: `could not parse the cluster's current version "not-a-version"`,
		},
		{
			// The check only buys a better error message, so credentials that cannot read
			// ClusterVersion must not be blocked by it.
			name:    "the check is skipped when reading ClusterVersion is forbidden",
			getErr:  apierrors.NewForbidden(schema.GroupResource{Resource: "clusterversions"}, "version", fmt.Errorf("no RBAC")),
			version: "4.19",
		},
		{
			name:        "a missing ClusterVersion is fatal",
			version:     "4.19",
			expectedErr: "could not read the cluster version",
		},
		{
			name:        "a cluster with no completed update is fatal",
			existing:    []client.Object{clusterVersion(partial("4.19.0"))},
			version:     "4.19",
			expectedErr: "the cluster has no completed version",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			funcs := interceptor.Funcs{}
			if test.getErr != nil {
				funcs.Get = func(ctx context.Context, wrapped client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, isClusterVersion := obj.(*configv1.ClusterVersion); isClusterVersion {
						return test.getErr
					}
					return wrapped.Get(ctx, key, obj, opts...)
				}
			}

			kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(test.existing...).WithInterceptorFuncs(funcs).Build()

			err := checkVersionIsUpgrade(context.TODO(), kubeClient, test.version)

			if test.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.expectedErr)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestApplyUpgradeableAnnotation(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, operatorv1.AddToScheme(scheme))

	tests := []struct {
		name                string
		existing            []client.Object
		patchErr            error
		version             string
		expectedAnnotations map[string]string
		expectedErr         string
	}{
		{
			name: "sets the annotation on a config that has none",
			existing: []client.Object{
				&operatorv1.CloudCredential{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}},
			},
			version: "4.19",
			expectedAnnotations: map[string]string{
				constants.UpgradeableAnnotation: "4.19",
			},
		},
		{
			name: "overwrites a stale annotation",
			existing: []client.Object{
				&operatorv1.CloudCredential{ObjectMeta: metav1.ObjectMeta{
					Name:        "cluster",
					Annotations: map[string]string{constants.UpgradeableAnnotation: "4.18"},
				}},
			},
			version: "4.19",
			expectedAnnotations: map[string]string{
				constants.UpgradeableAnnotation: "4.19",
			},
		},
		{
			name: "leaves unrelated annotations alone",
			existing: []client.Object{
				&operatorv1.CloudCredential{ObjectMeta: metav1.ObjectMeta{
					Name:        "cluster",
					Annotations: map[string]string{"example.com/keep": "me"},
				}},
			},
			version: "4.19",
			expectedAnnotations: map[string]string{
				constants.UpgradeableAnnotation: "4.19",
				"example.com/keep":              "me",
			},
		},
		{
			name: "surfaces a patch failure",
			existing: []client.Object{
				&operatorv1.CloudCredential{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}},
			},
			patchErr:    fmt.Errorf("connection refused"),
			version:     "4.19",
			expectedErr: "failed to set the upgradeable-to annotation",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			funcs := interceptor.Funcs{}
			if test.patchErr != nil {
				funcs.Patch = func(_ context.Context, _ client.WithWatch, _ client.Object, _ client.Patch, _ ...client.PatchOption) error {
					return test.patchErr
				}
			}

			kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(test.existing...).WithInterceptorFuncs(funcs).Build()

			err := applyUpgradeableAnnotation(context.TODO(), kubeClient, test.version)

			if test.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.expectedErr)
				return
			}
			require.NoError(t, err)

			applied := &operatorv1.CloudCredential{}
			require.NoError(t, kubeClient.Get(context.TODO(), types.NamespacedName{Name: "cluster"}, applied))
			for key, value := range test.expectedAnnotations {
				assert.Equal(t, value, applied.Annotations[key], "annotation %s", key)
			}
		})
	}
}

func TestRunSetUpgradeableTo(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectedErr string
	}{
		{
			name:        "rejects a malformed version before touching the cluster",
			args:        []string{"next"},
			expectedErr: "is not a valid version",
		},
		{
			name:        "rejects a bare major version before touching the cluster",
			args:        []string{"4"},
			expectedErr: "is not a valid version",
		},
		{
			name:        "requires exactly one argument",
			args:        []string{},
			expectedErr: "accepts 1 arg(s), received 0",
		},
		{
			name:        "rejects more than one argument",
			args:        []string{"4.19", "4.20"},
			expectedErr: "accepts 1 arg(s), received 2",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := NewSetUpgradeableToCmd()
			cmd.SetArgs(test.args)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)

			err := cmd.Execute()

			require.Error(t, err)
			assert.Contains(t, err.Error(), test.expectedErr)
		})
	}
}
