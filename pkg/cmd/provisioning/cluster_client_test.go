package provisioning

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// TestNewClusterScheme locks in the type groups the cluster client depends on.
func TestNewClusterScheme(t *testing.T) {
	clusterScheme, err := newClusterScheme()
	require.NoError(t, err)

	tests := []struct {
		name string
		gvk  schema.GroupVersionKind
	}{
		{
			name: "core types are registered",
			gvk:  schema.GroupVersionKind{Version: "v1", Kind: "Secret"},
		},
		{
			name: "ClusterVersion is registered",
			gvk:  schema.GroupVersionKind{Group: "config.openshift.io", Version: "v1", Kind: "ClusterVersion"},
		},
		{
			name: "CloudCredential is registered",
			gvk:  schema.GroupVersionKind{Group: "operator.openshift.io", Version: "v1", Kind: "CloudCredential"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.True(t, clusterScheme.Recognizes(test.gvk), "scheme does not recognize %s", test.gvk)
		})
	}
}
