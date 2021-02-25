package provisioning

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mockaws "github.com/openshift/cloud-credential-operator/pkg/aws/mock"
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
	testDirPrefix = "identityprovidertestdir"
)

func TestCreateIdentityProvider(t *testing.T) {

	tests := []struct {
		name          string
		mockAWSClient func(mockCtrl *gomock.Controller) *mockaws.MockClient
		setup         func(*testing.T) string
		verify        func(t *testing.T, tempDirName string)
		cleanup       func(*testing.T)
		generateOnly  bool
		expectError   bool
	}{
		{
			name: "Public key not found",
			mockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockCreateBucketSuccess(mockAWSClient)
				mockPutBucketTaggingSuccess(mockAWSClient)
				mockPutObjectSuccess(mockAWSClient)
				return mockAWSClient
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
			mockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				mockCreateBucketSuccess(mockAWSClient)
				mockPutBucketTaggingSuccess(mockAWSClient)
				mockPutObjectSuccess(mockAWSClient)
				mockListOpenIDConnectProviders(mockAWSClient)
				mockCreateOpenIDConnectProvider(mockAWSClient)
				mockTagOpenIDConnectProvider(mockAWSClient)
				return mockAWSClient
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
			mockAWSClient: func(mockCtrl *gomock.Controller) *mockaws.MockClient {
				mockAWSClient := mockaws.NewMockClient(mockCtrl)
				return mockAWSClient
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
				discoveryDocument, err := ioutil.ReadFile(filepath.Join(tempDirName, oidcConfigurationFilename))
				require.NoError(t, err, "error reading in discovery document")

				var discoveryDocumentJSON map[string]interface{}
				err = json.Unmarshal(discoveryDocument, &discoveryDocumentJSON)
				require.NoError(t, err, "discovery document is not a JSON")

				issuerURL, ok := discoveryDocumentJSON["issuer"]
				require.True(t, ok, "issuer field absent in discovery document")
				bucketName := fmt.Sprintf("%s-oidc", testInfraName)
				assert.Equal(t, fmt.Sprintf("https://%s.s3.%s.amazonaws.com", bucketName, testRegionName), issuerURL, "unexpected issuer url")

				jwksURI, ok := discoveryDocumentJSON["jwks_uri"]
				require.True(t, ok, "jwks_uri field absent in discovery document")
				assert.Equal(t, fmt.Sprintf("%s/%s", issuerURL, keysURI), jwksURI, "unexpected jwks uri")

				// Comparing key ID from the JSON web key with the one generated from the public key
				jwks, err := ioutil.ReadFile(filepath.Join(tempDirName, oidcKeysFilename))
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
				expectedKeyID, err := keyIDFromPublicKey(publicKey)
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

			mockAWSClient := test.mockAWSClient(mockCtrl)

			tempDirName := test.setup(t)
			defer os.RemoveAll(tempDirName)

			testPublicKeyPath := filepath.Join(tempDirName, testPublicKeyFile)

			err := createIdentityProvider(mockAWSClient, testInfraName, testRegionName, testPublicKeyPath, tempDirName, test.generateOnly)

			if test.expectError {
				require.Error(t, err, "expected error returned")
			} else {
				test.verify(t, tempDirName)
			}
		})
	}
}

func mockCreateBucketSuccess(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().CreateBucket(gomock.Any()).Return(
		&s3.CreateBucketOutput{}, nil).AnyTimes()
}

func mockPutBucketTaggingSuccess(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().PutBucketTagging(gomock.Any()).Return(
		&s3.PutBucketTaggingOutput{}, nil).AnyTimes()
}

func mockPutObjectSuccess(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().PutObject(gomock.Any()).Return(
		&s3.PutObjectOutput{}, nil).AnyTimes()
}

func mockListOpenIDConnectProviders(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().ListOpenIDConnectProviders(gomock.Any()).Return(
		&iam.ListOpenIDConnectProvidersOutput{
			OpenIDConnectProviderList: []*iam.OpenIDConnectProviderListEntry{},
		}, nil).AnyTimes()
}

func mockCreateOpenIDConnectProvider(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().CreateOpenIDConnectProvider(gomock.Any()).Return(
		&iam.CreateOpenIDConnectProviderOutput{
			OpenIDConnectProviderArn: awssdk.String("provider-arn"),
		}, nil).AnyTimes()
}

func mockTagOpenIDConnectProvider(mockAWSClient *mockaws.MockClient) {
	mockAWSClient.EXPECT().TagOpenIDConnectProvider(gomock.Any()).Return(
		&iam.TagOpenIDConnectProviderOutput{}, nil).AnyTimes()
}
