package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/openshift-eng/openshift-tests-extension/pkg/cmd"
	e "github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	et "github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	g "github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"

	// Import testdata package from local test module
	testdata "github.com/openshift/cloud-credential-operator/test/testdata"

	// Import test packages from local test module
	_ "github.com/openshift/cloud-credential-operator/test/e2e"
)

func main() {
	registry := e.NewRegistry()
	ext := e.NewExtension("openshift", "payload", "cloud-credential-operator")

	// Add main test suite
	ext.AddSuite(e.Suite{
		Name:    "openshift/cloud-credential-operator/tests",
		Parents: []string{"openshift/conformance/parallel"},
	})

	// Build test specs from Ginkgo
	specs, err := g.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite()
	if err != nil {
		panic(fmt.Sprintf("couldn't build extension test specs from ginkgo: %+v", err.Error()))
	}

	// Apply platform filters based on Platform: labels
	specs.Walk(func(spec *et.ExtensionTestSpec) {
		for label := range spec.Labels {
			if strings.HasPrefix(label, "Platform:") {
				platformName := strings.TrimPrefix(label, "Platform:")
				spec.Include(et.PlatformEquals(platformName))
			}
		}
	})

	// Apply platform filters based on [platform:xxx] in test names
	specs.Walk(func(spec *et.ExtensionTestSpec) {
		re := regexp.MustCompile(`\[platform:([a-z]+)\]`)
		if match := re.FindStringSubmatch(spec.Name); match != nil {
			platform := match[1]
			spec.Include(et.PlatformEquals(platform))
		}
	})

	// Add testdata validation and cleanup hooks
	specs.AddBeforeAll(func() {
		// List available fixtures
		fixtures := testdata.ListFixtures()
		fmt.Printf("Loaded %d test fixtures\n", len(fixtures))

		// Optional: Validate required fixtures
		// requiredFixtures := []string{
		//     "credentials_request.yaml",
		// }
		// if err := testdata.ValidateFixtures(requiredFixtures); err != nil {
		//     panic(fmt.Sprintf("Missing required fixtures: %v", err))
		// }
	})

	specs.AddAfterAll(func() {
		if err := testdata.CleanupFixtures(); err != nil {
			fmt.Printf("Warning: failed to cleanup fixtures: %v\n", err)
		}
	})

	ext.AddSpecs(specs)
	registry.Register(ext)

	root := &cobra.Command{
		Long: "Cloud Credential Operator Tests",
	}

	root.AddCommand(cmd.DefaultExtensionCommands(registry)...)

	if err := func() error {
		return root.Execute()
	}(); err != nil {
		os.Exit(1)
	}
}
