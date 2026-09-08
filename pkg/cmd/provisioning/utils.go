package provisioning

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/pkg/errors"

	"k8s.io/apimachinery/pkg/util/yaml"

	configv1 "github.com/openshift/api/config/v1"

	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	jwkutil "github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/jwks"
)

type JSONWebKeySet struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

// EnsureDir ensures that directory exists at a given path
func EnsureDir(path string) error {
	sResult, err := os.Stat(path)
	if os.IsNotExist(err) {
		if err := os.Mkdir(path, 0700); err != nil {
			return fmt.Errorf("failed to create directory: %s", err)
		}
		sResult, err = os.Stat(path)
	} else if err != nil {
		return fmt.Errorf("failed to stat: %+v", err)
	}

	if !sResult.IsDir() {
		return fmt.Errorf("file %s exists and is not a directory", path)
	}

	return nil
}

// CreateShellScript creates a shell script given commands to execute
func CreateShellScript(commands []string) string {
	return fmt.Sprintf("#!/bin/sh\n%s", strings.Join(commands, "\n"))
}

// CountNonDirectoryFiles counts files which are not a directory
func CountNonDirectoryFiles(files []os.DirEntry) int {
	NonDirectoryFiles := 0
	for _, f := range files {
		if !f.IsDir() {
			NonDirectoryFiles++
		}
	}
	return NonDirectoryFiles
}

// CreateClusterAuthentication creates the authentication manifest file for the installer
func CreateClusterAuthentication(issuerURL, targetDir string) error {
	clusterAuthenticationTemplate := `apiVersion: config.openshift.io/v1
kind: Authentication
metadata:
  name: cluster
spec:
  serviceAccountIssuer: %s`

	clusterAuthFile := filepath.Join(targetDir, ManifestsDirName, "cluster-authentication-02-config.yaml")

	fileData := fmt.Sprintf(clusterAuthenticationTemplate, issuerURL)
	if err := os.WriteFile(clusterAuthFile, []byte(fileData), 0600); err != nil {
		return errors.Wrap(err, "failed to save cluster authentication file")
	}
	log.Printf("Wrote cluster authentication manifest at path %s", clusterAuthFile)
	log.Printf("Issuer URL (serviceAccountIssuer) is %s", issuerURL)

	return nil
}

// BuildJsonWebKeySet builds JSON web key set from the public key
func BuildJsonWebKeySet(publicKeyPath string) ([]byte, error) {
	log.Print("Reading public key")
	publicKeyContent, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read public key")
	}

	keySet, err := jwkutil.NewSigner(publicKeyContent)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build JSON web key set from public key")
	}
	encoded, err := json.MarshalIndent(JSONWebKeySet{Keys: keySet.Keys}, "", "    ")
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode JSON web key set")
	}
	return encoded, nil
}

// KeyIDFromPublicKey derives a key ID non-reversibly from a public key
// reference: https://github.com/kubernetes/kubernetes/blob/0f140bf1eeaf63c155f5eba1db8db9b5d52d5467/pkg/serviceaccount/jwt.go#L89-L111
func KeyIDFromPublicKey(publicKey interface{}) (string, error) {
	return jwkutil.KeyIDFromPublicKey(publicKey)
}

// GetListOfCredentialsRequests decodes manifests in a given directory and returns a list of CredentialsRequests
func GetListOfCredentialsRequests(dir string, enableTechPreview bool) ([]*credreqv1.CredentialsRequest, error) {
	credRequests := make([]*credreqv1.CredentialsRequest, 0)
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() || !(strings.HasSuffix(file.Name(), ".yaml") || strings.HasSuffix(file.Name(), ".yml")) {
			continue
		}
		f, err := os.Open(filepath.Join(dir, file.Name()))
		if err != nil {
			return nil, errors.Wrap(err, "Failed to open file")
		}
		defer f.Close()
		decoder := yaml.NewYAMLOrJSONDecoder(f, 4096)
		for {
			cr := &credreqv1.CredentialsRequest{}
			if err := decoder.Decode(cr); err != nil {
				if err == io.EOF {
					break
				}
				return nil, errors.Wrap(err, "Failed to decode to CredentialsRequest")
			}
			// Ignore CredentialsRequest manifest if it has "release.openshift.io/delete" annotation with value "true"
			// These manifests are marked for in-cluster deletion and should not be consumed by ccoctl to create credentials
			// infrastructure.
			if value, ok := cr.Annotations["release.openshift.io/delete"]; ok && value == "true" {
				log.Printf("Ignoring CredentialsRequest %s/%s as it is marked for in-cluster deletion", cr.Namespace, cr.Name)
				continue
			}

			// Handle CredentialsRequest with the feature-gate annotation
			if value, ok := cr.Annotations[featureGateAnnotation]; ok {
				if !enableTechPreview {
					log.Printf("Ignoring CredentialsRequest %s/%s with tech-preview annotation", cr.Namespace, cr.Name)
					continue
				}
				if value != string(configv1.TechPreviewNoUpgrade) {
					log.Printf("Ignoring CredentialsRequest %s/%s with tech-preview value %s", cr.Namespace, cr.Name, value)
					continue
				} // else allow it to be added it to the list of CredReqs to process
			}

			credRequests = append(credRequests, cr)
		}
	}

	return credRequests, nil
}

func ShortenName(name string, maxLength int) string {
	if len(name) > maxLength {
		return name[0:maxLength]
	}
	return name
}
