package gcp

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	iamCloud "cloud.google.com/go/iam"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/iam/v1"
	pb "google.golang.org/genproto/googleapis/iam/v1"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
	mockgcp "github.com/openshift/cloud-credential-operator/pkg/gcp/mock"
)

const (
	testInfraName     = "test-infra-name"
	testRegionName    = "test-region"
	testPublicKeyFile = "publicKeyFile"
	testPublicKeyData = "-----BEGIN PUBLIC KEY-----" +
		"\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwlzW80E8Tj19NCuPTdwd" +
		"\ng56fcpRKW6cnJ981cXNrHbQt/0ZR7HDYf/r+B1GRUblSoncQOA2IPU95wnPq6HHf" +
		"\nkxP6G8qRgA3MfhW1m/OAD9U16YTcBIN3BMnNtmJzQkCbEQz6JSlFRRU5vhPmL59h" +
		"\nZ61CBYhbxd3whtoG6WXifhrudowJdZnTMEeZnkiJ8uhHpJOGZJmcRkQ6RPVlaiqC" +
		"\ntmpTZf3DU0yvajoqMH4t3EwxzB1QYLDsNJvpnh5FlvLZUTAvpp0u6TxbnFeBFMO/" +
		"\nP6V5sjNf+aPPEr+BDaL/Jv7KbB1FYdX/ngDvsjq36+GrDvDjbnd+5GfqpuR02a/X" +
		"\nfM0zVtvWXxIgD8gKFfYSfJH3K6x4SbxGdaXSX2ixmQjB1jwdkbAgQ1cbe2MgnqTO" +
		"\n8KcgAFxwdvTUo0CA2R1NGgmeLoPUYv9kTSRWhRvgRoLAlzFGnfdqO6Gq5CwHR820" +
		"\nAdohiu7Lgp940AR7mMRcjxkpfArpyKOxfVIFrpZDw0G39zd9bn3KYYWQ4Kah1BR0" +
		"\nWpJJV+OtxxsUI51vQ0+wp9KI5Eu0ibyzL1Fq7IoBOhFRea384iF4LEXmkM/y1eRi" +
		"\nhEnmk6kDfjWWsPkxXrD5qY4KgSp1/fqJP29p0Ypeh0cfrVkdQvn3v7ppcS/7TmWk" +
		"\nhiFcsE1ngFW/nR6+7K/JdVUCAwEAAQ==" +
		"\n-----END PUBLIC KEY-----\n"
)

func TestCreateWorkloadIdentityProvider(t *testing.T) {

	tests := []struct {
		name          string
		mockGCPClient func(mockCtrl *gomock.Controller) *mockgcp.MockClient
		setup         func(*testing.T) string
		verify        func(t *testing.T, tempDirName string)
		cleanup       func(*testing.T)
		generateOnly  bool
		expectError   bool
	}{
		{
			name: "Public key not found",
			mockGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockCreateBucketSuccess(mockGCPClient, 1)
				mockPutObjectSuccess(mockGCPClient, 1)
				mockGetBucketPolicySuccess(mockGCPClient, 1)
				mockSetBucketPolicySuccess(mockGCPClient, 1)
				return mockGCPClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")
				return tempDirName
			},
			expectError: true,
		},
		{
			name: "Identity provider created, saved discovery document and json web key set",
			mockGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				mockCreateBucketSuccess(mockGCPClient, 1)
				mockPutObjectSuccess(mockGCPClient, 2)
				mockGetBucketPolicySuccess(mockGCPClient, 1)
				mockSetBucketPolicySuccess(mockGCPClient, 1)
				mockCreateWorkloadIdentityProviderSuccess(mockGCPClient)
				return mockGCPClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				err = ioutil.WriteFile(filepath.Join(tempDirName, testPublicKeyFile), []byte(testPublicKeyData), 0600)
				require.NoError(t, err, "errored while setting up environment for test")

				return tempDirName
			},
			verify:      func(t *testing.T, tempDirName string) {},
			expectError: false,
		},
		{
			name: "generate files only",
			mockGCPClient: func(mockCtrl *gomock.Controller) *mockgcp.MockClient {
				mockGCPClient := mockgcp.NewMockClient(mockCtrl)
				return mockGCPClient
			},
			setup: func(t *testing.T) string {
				tempDirName, err := ioutil.TempDir(os.TempDir(), testDirPrefix)
				require.NoError(t, err, "Failed to create temp directory")

				err = ioutil.WriteFile(filepath.Join(tempDirName, testPublicKeyFile), []byte(testPublicKeyData), 0600)
				require.NoError(t, err, "errored while setting up environment for test")

				return tempDirName
			},
			verify: func(t *testing.T, tempDirName string) {
				// Validating the issuer URL in the discovery document
				discoveryDocument, err := ioutil.ReadFile(filepath.Join(tempDirName, gcpOidcConfigurationFilename))
				require.NoError(t, err, "error reading in discovery document")

				var discoveryDocumentJSON map[string]interface{}
				err = json.Unmarshal(discoveryDocument, &discoveryDocumentJSON)
				require.NoError(t, err, "discovery document is not a JSON")

				issuerURL, ok := discoveryDocumentJSON["issuer"]
				require.True(t, ok, "issuer field absent in discovery document")
				bucketName := fmt.Sprintf("%s-oidc", testInfraName)
				assert.Equal(t, fmt.Sprintf("https://storage.googleapis.com/%s", bucketName), issuerURL, "unexpected issuer url")

				jwksURI, ok := discoveryDocumentJSON["jwks_uri"]
				require.True(t, ok, "jwks_uri field absent in discovery document")
				assert.Equal(t, fmt.Sprintf("%s/%s", issuerURL, provisioning.KeysURI), jwksURI, "unexpected jwks uri")

				// Comparing key ID from the JSON web key with the one generated from the public key
				jwks, err := ioutil.ReadFile(filepath.Join(tempDirName, gcpOidcKeysFilename))
				require.NoError(t, err, "error reading in JSON web key set (JWKS)")

				var jwksJSON map[string]interface{}
				err = json.Unmarshal(jwks, &jwksJSON)
				require.NoError(t, err, "JSON web key set is not a JSON")

				keys, ok := jwksJSON["keys"].([]interface{})
				require.True(t, ok, "No keys in the JSON web key set")
				key := keys[0].(map[string]interface{})
				kid, ok := key["kid"]
				require.True(t, ok, "key id absent in JSON web key", key)

				block, _ := pem.Decode([]byte(testPublicKeyData))
				publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
				expectedKeyID, err := provisioning.KeyIDFromPublicKey(publicKey)
				require.NoError(t, err, "error calculating expected key id")
				assert.Equalf(t, expectedKeyID, kid, "unexpected key id")
			},
			generateOnly: true,
			expectError:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockGCPClient := test.mockGCPClient(mockCtrl)

			tempDirName := test.setup(t)
			defer os.RemoveAll(tempDirName)

			testPublicKeyPath := filepath.Join(tempDirName, testPublicKeyFile)
			err := createWorkloadIdentityProvider(context.TODO(), mockGCPClient, testInfraName, testRegionName, testProject, testName, testPublicKeyPath, tempDirName, test.generateOnly)

			if test.expectError {
				require.Error(t, err, "expected error returned")
			} else {
				test.verify(t, tempDirName)
			}
		})
	}
}

func mockCreateBucketSuccess(mockGCPClient *mockgcp.MockClient, times int) {
	mockGCPClient.EXPECT().CreateBucket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(times)
}

func mockGetBucketPolicySuccess(mockGCPClient *mockgcp.MockClient, times int) {
	mockGCPClient.EXPECT().GetBucketPolicy(gomock.Any(), gomock.Any()).Return(
		&iamCloud.Policy3{
			Bindings: []*pb.Binding{},
		},
		nil).Times(times)
}

func mockSetBucketPolicySuccess(mockGCPClient *mockgcp.MockClient, times int) {
	mockGCPClient.EXPECT().SetBucketPolicy(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(times)
}

func mockPutObjectSuccess(mockGCPClient *mockgcp.MockClient, times int) {
	mockGCPClient.EXPECT().PutObject(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(times)
}

func mockCreateWorkloadIdentityProviderSuccess(mockGCPClient *mockgcp.MockClient) {
	mockGCPClient.EXPECT().CreateWorkloadIdentityProvider(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(&iam.Operation{
		Done: true,
	}, nil).Times(1)
}
