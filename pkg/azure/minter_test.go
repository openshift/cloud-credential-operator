package azure_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openshift/cloud-credential-operator/pkg/azure"
)

func writeEnvFile(t *testing.T, dir string, content interface{}) string {
	t.Helper()
	data, err := json.Marshal(content)
	require.NoError(t, err)
	path := filepath.Join(dir, "cloud.json")
	require.NoError(t, os.WriteFile(path, data, 0600))
	return path
}

func TestNewAzureCredentialsMinterAzureStackCloud(t *testing.T) {
	logger := log.NewEntry(log.New())

	t.Run("missing AZURE_ENVIRONMENT_FILEPATH env var", func(t *testing.T) {
		t.Setenv("AZURE_ENVIRONMENT_FILEPATH", "")
		_, err := azure.NewAzureCredentialsMinter(logger, "clientID", "clientSecret", "AzureStackCloud", "tenantID", "subID")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "AZURE_ENVIRONMENT_FILEPATH")
	})

	t.Run("env file does not exist", func(t *testing.T) {
		t.Setenv("AZURE_ENVIRONMENT_FILEPATH", "/nonexistent/path/cloud.json")
		_, err := azure.NewAzureCredentialsMinter(logger, "clientID", "clientSecret", "AzureStackCloud", "tenantID", "subID")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to read Azure Stack environment file")
	})

	t.Run("env file contains invalid JSON", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "cloud.json")
		require.NoError(t, os.WriteFile(path, []byte("not-json"), 0600))
		t.Setenv("AZURE_ENVIRONMENT_FILEPATH", path)
		_, err := azure.NewAzureCredentialsMinter(logger, "clientID", "clientSecret", "AzureStackCloud", "tenantID", "subID")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to parse Azure Stack environment file")
	})

	t.Run("env file missing activeDirectoryEndpoint", func(t *testing.T) {
		dir := t.TempDir()
		path := writeEnvFile(t, dir, map[string]string{
			"resourceManagerEndpoint": "https://management.example.com/",
			"tokenAudience":           "https://management.example.com/",
		})
		t.Setenv("AZURE_ENVIRONMENT_FILEPATH", path)
		_, err := azure.NewAzureCredentialsMinter(logger, "clientID", "clientSecret", "AzureStackCloud", "tenantID", "subID")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "activeDirectoryEndpoint")
	})

	t.Run("env file missing resourceManagerEndpoint", func(t *testing.T) {
		dir := t.TempDir()
		path := writeEnvFile(t, dir, map[string]string{
			"activeDirectoryEndpoint": "https://login.example.com/",
			"tokenAudience":           "https://management.example.com/",
		})
		t.Setenv("AZURE_ENVIRONMENT_FILEPATH", path)
		_, err := azure.NewAzureCredentialsMinter(logger, "clientID", "clientSecret", "AzureStackCloud", "tenantID", "subID")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "resourceManagerEndpoint")
	})
}
