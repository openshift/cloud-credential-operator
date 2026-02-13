package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/openshift-eng/openshift-tests-extension/pkg/cmd"
	e "github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	"github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	"github.com/spf13/cobra"
	"k8s.io/component-base/logs"

	g "github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
	// If using ginkgo, import your tests here.
	_ "github.com/openshift/cloud-credential-operator/test/extend"
)

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	extensionRegistry, ext := setupExtension()
	registerSuites(ext)
	specs := buildTestSpecs()
	specs = applyPlatformFilters(specs)
	ext.AddSpecs(specs)

	root := createRootCommand(extensionRegistry)
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// setupExtension creates and registers the extension with the registry.
func setupExtension() (*e.Registry, *e.Extension) {
	extensionRegistry := e.NewRegistry()
	ext := e.NewExtension("openshift", "payload", "cloud-credential-operator")
	extensionRegistry.Register(ext)
	return extensionRegistry, ext
}

// registerSuites registers all test suites for the extension.
func registerSuites(ext *e.Extension) {
	suites := []e.Suite{
		{
			Name: "cco/conformance/parallel",
			Parents: []string{
				"openshift/conformance/parallel",
			},
			Qualifiers: []string{
				`name.contains("[Level0]") && !(name.contains("[Serial]") || name.contains("[Disruptive]"))`,
			},
		},
		{
			Name: "cco/conformance/serial",
			Parents: []string{
				"openshift/conformance/serial",
			},
			Qualifiers: []string{
				`name.contains("[Serial]") && !name.contains("[Disruptive]")`,
			},
		},
		{
			Name:    "cco/disruptive",
			Parents: []string{"openshift/disruptive"},
			Qualifiers: []string{
				`name.contains("[Disruptive]")`,
			},
		},
		{
			Name:        "cco/all",
			Description: "All Cloud Credential Operator tests",
			// No qualifiers means all tests from this extension will be included
			// The source filter is automatically added by AddSuite
		},
	}

	for _, suite := range suites {
		ext.AddSuite(suite)
	}
}

// buildTestSpecs builds test specs from Ginkgo suite, filtering out vendor tests.
func buildTestSpecs() extensiontests.ExtensionTestSpecs {
	specs, err := g.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite(shouldIncludeTest)
	if err != nil {
		panic(fmt.Sprintf("couldn't build extension test specs from ginkgo: %v", err))
	}
	return specs
}

// shouldIncludeTest determines if a test spec should be included based on its code locations.
// It excludes vendor tests and external module tests, only including cloud-credential-operator tests.
func shouldIncludeTest(spec *extensiontests.ExtensionTestSpec) bool {
	for _, location := range spec.CodeLocations {
		// Exclude vendor directory tests
		if strings.Contains(location, "/vendor/") {
			return false
		}
		// Exclude external Kubernetes module tests
		if strings.HasPrefix(location, "k8s.io/") || strings.HasPrefix(location, "sigs.k8s.io/") {
			return false
		}
		// Include cloud-credential-operator tests
		if strings.Contains(location, "cloud-credential-operator/test/extend") {
			return true
		}
	}
	return false
}

// applyPlatformFilters applies platform-specific filters to test specs based on platform tags.
func applyPlatformFilters(specs extensiontests.ExtensionTestSpecs) extensiontests.ExtensionTestSpecs {
	return specs.Walk(func(spec *extensiontests.ExtensionTestSpec) {
		platformNames := extractPlatformNames(spec.Name)
		if len(platformNames) == 0 {
			return
		}

		if len(platformNames) == 1 {
			spec.Include(extensiontests.PlatformEquals(platformNames[0]))
		} else {
			orExprs := make([]string, 0, len(platformNames))
			for _, platformName := range platformNames {
				orExprs = append(orExprs, extensiontests.PlatformEquals(platformName))
			}
			spec.Include(extensiontests.Or(orExprs...))
		}
	})
}

// extractPlatformNames extracts platform names from test spec name using platform tags.
func extractPlatformNames(specName string) []string {
	platformRegex := regexp.MustCompile(`\[platform:([a-z0-9-]+)]`)
	matches := platformRegex.FindAllStringSubmatch(specName, -1)
	if len(matches) == 0 {
		return nil
	}

	platformNames := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) >= 2 {
			platformNames = append(platformNames, match[1])
		}
	}
	return platformNames
}

// createRootCommand creates and configures the root Cobra command.
func createRootCommand(extensionRegistry *e.Registry) *cobra.Command {
	root := &cobra.Command{
		Long: "Cloud Credential Operator tests extension for OpenShift",
	}
	// Ensure Go flags (like --kubeconfig) are available on the root command.
	root.PersistentFlags().AddGoFlagSet(flag.CommandLine)
	root.AddCommand(cmd.DefaultExtensionCommands(extensionRegistry)...)
	return root
}
