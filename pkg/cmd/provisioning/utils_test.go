package provisioning

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/runtime"

	configv1 "github.com/openshift/api/config/v1"

	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
)

const (
	testDirPath = "/tmp/test-Dir"
)

func TestEnsureDir(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*testing.T)
		expectError bool
		verify      func(*testing.T)
		cleanup     func(*testing.T)
	}{
		{
			name: "directory does not exist",
			setup: func(t *testing.T) {
				err := os.RemoveAll(testDirPath)
				require.NoError(t, err, "error clearing out directory that should not exist")
			},
			verify: func(t *testing.T) {
				sResult, err := os.Stat(testDirPath)
				require.NoError(t, err, "failed to stat")
				assert.Truef(t, sResult.IsDir(), "unexpected error")
			},
			cleanup: func(t *testing.T) {
				err := os.RemoveAll(testDirPath)
				require.NoError(t, err, "failed to clean test environment")
			},
		},
		{
			name: "directory already exist",
			setup: func(t *testing.T) {
				err := os.Mkdir(testDirPath, 0700)
				require.NoError(t, err, "error setting up test environment")
			},
			verify: func(t *testing.T) {
				sResult, err := os.Stat(testDirPath)
				require.NoError(t, err, "failed to stat")
				assert.True(t, sResult.IsDir(), "unexpected error")
			},
			cleanup: func(t *testing.T) {
				err := os.RemoveAll(testDirPath)
				require.NoError(t, err, "failed to clean test environment")
			},
		},
		{
			name:        "File exits but not a directory",
			expectError: true,
			setup: func(t *testing.T) {
				_, err := os.Create(testDirPath)
				require.NoError(t, err, "error setting up test environment")
			},
			verify: func(t *testing.T) {},
			cleanup: func(t *testing.T) {
				err := os.RemoveAll(testDirPath)
				require.NoError(t, err, "failed to clean test environment")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			test.setup(t)

			err := EnsureDir(testDirPath)
			if test.expectError {
				assert.Error(t, err, "expected error")
			} else {
				assert.NoError(t, err, "unexpected error")
			}

			test.verify(t)

			if test.cleanup != nil {
				test.cleanup(t)
			}
		})
	}
}

func TestFilteringCredReqs(t *testing.T) {
	tests := []struct {
		name              string
		setup             func(*testing.T)
		expectError       bool
		verify            func(*testing.T, []*credreqv1.CredentialsRequest)
		enableTechPreview bool
	}{
		{
			name: "ignore CredReq marked as tech-preview",
			setup: func(t *testing.T) {
				testNewCredReq(t, "credReqA")
				testNewTechPreviewCredReq(t, "credReqB")
			},
			verify: func(t *testing.T, credReqs []*credreqv1.CredentialsRequest) {
				sResult, err := os.Stat(testDirPath)
				require.NoError(t, err, "failed to stat")
				assert.True(t, sResult.IsDir(), "unexpected error")

				assert.Equal(t, 1, len(credReqs))
			},
			enableTechPreview: false,
		},
		{
			name: "include CredReq marked as tech-preview",
			setup: func(t *testing.T) {
				testNewCredReq(t, "credReqA")
				testNewTechPreviewCredReq(t, "credReqB")
			},
			verify: func(t *testing.T, credReqs []*credreqv1.CredentialsRequest) {
				sResult, err := os.Stat(testDirPath)
				require.NoError(t, err, "failed to stat")
				assert.True(t, sResult.IsDir(), "unexpected error")

				assert.Equal(t, 2, len(credReqs))
			},
			enableTechPreview: true,
		},
		{
			name: "ignore CredReq marked for deletion",
			setup: func(t *testing.T) {
				testNewMarkedForDeletionCredReq(t, "credReqA")
			},
			verify: func(t *testing.T, credReqs []*credreqv1.CredentialsRequest) {
				sResult, err := os.Stat(testDirPath)
				require.NoError(t, err, "failed to stat")
				assert.True(t, sResult.IsDir(), "unexpected error")

				assert.Equal(t, 0, len(credReqs))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// start from an empty directory
			err := os.RemoveAll(testDirPath)
			require.NoError(t, err, "error clearing out directory that should not exist")
			err = os.Mkdir(testDirPath, 0700)
			require.NoError(t, err, "error creating temp directory")

			test.setup(t)

			credReqs, err := GetListOfCredentialsRequests(testDirPath, test.enableTechPreview)
			require.NoError(t, err, "unexpected error")

			test.verify(t, credReqs)

			err = os.RemoveAll(testDirPath)
			require.NoError(t, err, "failed to clean test environment")
		})
	}
}

func testNewCredReq(t *testing.T, crName string) {
	cr := NewCredentialsRequestBuilder().
		Options(WithName(crName)).
		Build()

	saveCredReq(t, cr)
}

func testNewTechPreviewCredReq(t *testing.T, crName string) {
	cr := NewCredentialsRequestBuilder().
		Options(WithName(crName)).
		Options(WithTechPreviewAnnotation()).
		Build()

	saveCredReq(t, cr)
}

func testNewMarkedForDeletionCredReq(t *testing.T, crName string) {
	cr := NewCredentialsRequestBuilder().
		Options(WithName(crName)).
		Options(WithDeletionAnnotation()).
		Build()

	saveCredReq(t, cr)
}

func saveCredReq(t *testing.T, credReq *credreqv1.CredentialsRequest) {
	re := &runtime.RawExtension{
		Object: credReq,
	}

	out, err := re.MarshalJSON()
	require.NoError(t, err, "error marshaling CredReq")

	f, err := ioutil.TempFile(testDirPath, "credreq-testing-")
	require.NoError(t, err, "error creating temp file")
	defer f.Close()

	_, err = f.Write(out)
	require.Nil(t, err, "err")
}

type option func(*credreqv1.CredentialsRequest)

func Build(opts ...option) *credreqv1.CredentialsRequest {
	retval := &credreqv1.CredentialsRequest{}

	for _, o := range opts {
		o(retval)
	}

	return retval
}

type Builder interface {
	Build(opts ...option) *credreqv1.CredentialsRequest

	Options(opts ...option) Builder
}

type builder struct {
	options []option
}

func (b *builder) Build(opts ...option) *credreqv1.CredentialsRequest {
	return Build(append(b.options, opts...)...)
}

func (b *builder) Options(opts ...option) Builder {
	return &builder{
		options: append(b.options, opts...),
	}
}
func NewCredentialsRequestBuilder() Builder {
	return &builder{}
}

func WithName(name string) option {
	return func(credreq *credreqv1.CredentialsRequest) {
		credreq.SetName(name)
	}
}

func WithTechPreviewAnnotation() option {
	return func(credreq *credreqv1.CredentialsRequest) {
		if credreq.Annotations == nil {
			credreq.Annotations = map[string]string{}
		}
		credreq.Annotations[featureGateAnnotation] = string(configv1.TechPreviewNoUpgrade)
	}
}

func WithDeletionAnnotation() option {
	return func(credreq *credreqv1.CredentialsRequest) {
		if credreq.Annotations == nil {
			credreq.Annotations = map[string]string{}
		}
		credreq.Annotations[deletionAnnotation] = "true"
	}
}
