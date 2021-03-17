package provisioning

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const keypairTestDirPrefix = "keypairtestdir"

func TestKeyPair(t *testing.T) {

	tests := []struct {
		name        string
		setup       func(*testing.T) string
		verify      func(t *testing.T, tempDirName string)
		cleanup     func(*testing.T)
		expectError bool
	}{
		{
			name: "private key file exists",
			setup: func(t *testing.T) string {
				tempDirName := prepTempDir(t)

				err := ioutil.WriteFile(filepath.Join(tempDirName, privateKeyFile), []byte("some data"), 0600)
				require.NoError(t, err, "errored while setting up environment for test")

				return tempDirName
			},
			verify: func(t *testing.T, tempDirName string) {
				_, err := os.Stat(filepath.Join(tempDirName, publicKeyFile))
				require.Error(t, err, "expected public key file to not exist")

				fileData, err := ioutil.ReadFile(filepath.Join(tempDirName, privateKeyFile))
				require.NoError(t, err, "unexpected error reading in test private key data")

				assert.Equal(t, []byte("some data"), fileData, "unexpected change in test private key data")
			},
		},
		{
			name: "generate keys",
			setup: func(t *testing.T) string {
				tempDirName := prepTempDir(t)

				return tempDirName
			},
			verify: func(t *testing.T, tempDirName string) {
				pubFileBytes, err := ioutil.ReadFile(filepath.Join(tempDirName, publicKeyFile))
				require.NoError(t, err, "error reading in generated public key file")

				privFile, err := ioutil.ReadFile(filepath.Join(tempDirName, privateKeyFile))
				require.NoError(t, err, "error reading in test private key file")

				block, _ := pem.Decode(privFile)
				require.NotNil(t, block, "nil result after decoding private key")

				privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				require.NoError(t, err, "unexpected error decoding private key file")

				err = privKey.Validate()
				require.Nil(t, err, "private key failed validation")

				calculatedPubKey, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
				require.NoError(t, err, "unexpected error marshaling public key from test private key")

				calculatedPubKeyBytes := pem.EncodeToMemory(&pem.Block{
					Type:    "PUBLIC KEY",
					Headers: nil,
					Bytes:   calculatedPubKey,
				})

				assert.Equal(t, pubFileBytes, calculatedPubKeyBytes, "Missmatch between written public key file and caluclated public key (from private key)")

			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			tempDirName := test.setup(t)
			defer os.RemoveAll(tempDirName)

			err := createKeys(tempDirName)

			if test.expectError {
				require.Error(t, err, "expected error returned")
			} else {
				test.verify(t, tempDirName)
			}
		})
	}
}

func prepTempDir(t *testing.T) string {
	tempDirName, err := ioutil.TempDir(os.TempDir(), keypairTestDirPrefix)

	require.NoError(t, err, "unexpected error setting up temp directory")

	tlsDir := filepath.Join(tempDirName, tlsDirName)
	err = os.Mkdir(tlsDir, 0770)
	require.NoError(t, err, "errored trying to create temp tls dir")

	return tempDirName
}
