package testdata

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var (
	// fixtureDir is where extracted fixtures are stored
	fixtureDir string
)

// init sets up the temporary directory for fixtures
func init() {
	var err error
	fixtureDir, err = ioutil.TempDir("", "testdata-fixtures-")
	if err != nil {
		panic(fmt.Sprintf("failed to create fixture directory: %v", err))
	}
}

// FixturePath returns the filesystem path to a test fixture file.
// This replaces functions like compat_otp.FixturePath() and exutil.FixturePath().
//
// The file is extracted from embedded bindata to the filesystem on first access.
// Files are extracted to a temporary directory that persists for the test run.
//
// Accepts multiple path elements that will be joined together.
//
// IMPORTANT: Do NOT include "testdata" as the first argument.
// The function automatically prepends "testdata/" to construct the bindata path.
//
// Migration examples:
//   Origin-tests:        compat_otp.FixturePath("testdata", "cluster_operator", "cloudcredential", "file.yaml")
//   Tests-extension:     testdata.FixturePath("cluster_operator", "cloudcredential", "file.yaml")
//
// Example:
//   configPath := testdata.FixturePath("cluster_operator", "cloudcredential", "config.yaml")
//   data, err := os.ReadFile(configPath)
func FixturePath(elem ...string) string {
	// Join all path elements
	relativePath := filepath.Join(elem...)
	targetPath := filepath.Join(fixtureDir, relativePath)

	// Check if already extracted
	if _, err := os.Stat(targetPath); err == nil {
		return targetPath
	}

	// Create parent directory
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		panic(fmt.Sprintf("failed to create directory for %s: %v", relativePath, err))
	}

	// Bindata stores assets with "testdata/" prefix
	// e.g., bindata has "testdata/cluster_operator/cloudcredential/file.yaml" 
	// but tests call FixturePath("cluster_operator", "cloudcredential", "file.yaml")
	bindataPath := filepath.Join("testdata", relativePath)

	// Extract to temp directory first to handle path mismatch
	tempDir, err := os.MkdirTemp("", "bindata-extract-")
	if err != nil {
		panic(fmt.Sprintf("failed to create temp directory: %v", err))
	}
	defer os.RemoveAll(tempDir)

	// Try to restore single asset or directory to temp location
	if err := RestoreAsset(tempDir, bindataPath); err != nil {
		// If single file fails, try restoring as directory
		if err := RestoreAssets(tempDir, bindataPath); err != nil {
			panic(fmt.Sprintf("failed to restore fixture %s: %v", relativePath, err))
		}
	}

	// Move extracted files from temp location to target location
	extractedPath := filepath.Join(tempDir, bindataPath)
	if err := os.Rename(extractedPath, targetPath); err != nil {
		panic(fmt.Sprintf("failed to move extracted files from %s to %s: %v", extractedPath, targetPath, err))
	}

	// Set appropriate permissions for directories
	if info, err := os.Stat(targetPath); err == nil && info.IsDir() {
		filepath.Walk(targetPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				os.Chmod(path, 0755)
			} else {
				os.Chmod(path, 0644)
			}
			return nil
		})
	}

	return targetPath
}

// CleanupFixtures removes all extracted fixture files.
// Call this in test cleanup (e.g., AfterAll hook).
func CleanupFixtures() error {
	if fixtureDir != "" {
		return os.RemoveAll(fixtureDir)
	}
	return nil
}

// GetFixtureData reads and returns the contents of a fixture file directly from bindata.
// Use this for small files that don't need to be written to disk.
//
// Accepts multiple path elements that will be joined together.
//
// Example:
//   data, err := testdata.GetFixtureData("cluster_operator", "cloudcredential", "config.yaml")
func GetFixtureData(elem ...string) ([]byte, error) {
	// Join all path elements
	relativePath := filepath.Join(elem...)

	// Normalize path - bindata uses "testdata/" prefix
	cleanPath := relativePath
	if len(cleanPath) > 0 && cleanPath[0] == '/' {
		cleanPath = cleanPath[1:]
	}

	return Asset(filepath.Join("testdata", cleanPath))
}

// MustGetFixtureData is like GetFixtureData but panics on error.
// Useful in test initialization code.
//
// Accepts multiple path elements that will be joined together.
func MustGetFixtureData(elem ...string) []byte {
	data, err := GetFixtureData(elem...)
	if err != nil {
		panic(fmt.Sprintf("failed to get fixture data for %s: %v", filepath.Join(elem...), err))
	}
	return data
}

// FixtureExists checks if a fixture exists in the embedded bindata.
// Use this to validate fixtures before accessing them.
//
// Accepts multiple path elements that will be joined together.
//
// Example:
//   if testdata.FixtureExists("cluster_operator", "cloudcredential", "deployment.yaml") {
//       path := testdata.FixturePath("cluster_operator", "cloudcredential", "deployment.yaml")
//   }
func FixtureExists(elem ...string) bool {
	// Join all path elements
	relativePath := filepath.Join(elem...)

	cleanPath := relativePath
	if len(cleanPath) > 0 && cleanPath[0] == '/' {
		cleanPath = cleanPath[1:]
	}
	_, err := Asset(filepath.Join("testdata", cleanPath))
	return err == nil
}

// ListFixtures returns all available fixture paths in the embedded bindata.
// Useful for debugging and test discovery.
//
// Example:
//   fixtures := testdata.ListFixtures()
//   fmt.Printf("Available fixtures: %v\n", fixtures)
func ListFixtures() []string {
	names := AssetNames()
	fixtures := make([]string, 0, len(names))
	for _, name := range names {
		// Remove "testdata/" prefix for cleaner paths
		if strings.HasPrefix(name, "testdata/") {
			fixtures = append(fixtures, strings.TrimPrefix(name, "testdata/"))
		}
	}
	sort.Strings(fixtures)
	return fixtures
}

// ListFixturesInDir returns all fixtures within a specific directory.
//
// Example:
//   manifests := testdata.ListFixturesInDir("cluster_operator/cloudcredential")
func ListFixturesInDir(dir string) []string {
	allFixtures := ListFixtures()
	var matching []string
	prefix := dir
	if !strings.HasSuffix(prefix, "/") {
		prefix = prefix + "/"
	}
	for _, fixture := range allFixtures {
		if strings.HasPrefix(fixture, prefix) {
			matching = append(matching, fixture)
		}
	}
	return matching
}

// GetFixtureDir returns the temporary directory where fixtures are extracted.
// Use this if you need to pass a directory path to external tools.
//
// Example:
//   fixtureRoot := testdata.GetFixtureDir()
func GetFixtureDir() string {
	return fixtureDir
}
