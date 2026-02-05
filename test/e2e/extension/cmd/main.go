package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/openshift-eng/openshift-tests-extension/pkg/cmd"
	e "github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	et "github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	g "github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"

	// Import test framework packages for initialization
	"github.com/openshift/origin/test/extended/util"
	"k8s.io/kubernetes/test/e2e/framework"

	// Import testdata package from test module
	testdata "github.com/openshift/cloud-credential-operator/test/e2e/extension/testdata"

	// Import test packages from test module
	_ "github.com/openshift/cloud-credential-operator/test/e2e/extension"
)

func main() {
	// Initialize test framework
	// This sets TestContext.KubeConfig from KUBECONFIG env var and initializes the cloud provider
	util.InitStandardFlags()
	if err := util.InitTest(false); err != nil {
		panic(fmt.Sprintf("couldn't initialize test framework: %+v", err.Error()))
	}
	framework.AfterReadingAllFlags(&framework.TestContext)

	registry := e.NewRegistry()
	ext := e.NewExtension("openshift", "payload", "cloud-credential-operator")

	// Add main test suite
	ext.AddSuite(e.Suite{
		Name:    "openshift/cloud-credential-operator/tests",
		Parents: []string{"openshift/conformance/parallel"},
	})

	// Build test specs from Ginkgo
	allSpecs, err := g.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite()
	if err != nil {
		panic(fmt.Sprintf("couldn't build extension test specs from ginkgo: %+v", err.Error()))
	}

	// Filter to only include component-specific tests (tests with specified sig tags)
	// Parse sig filter tags from comma-separated list
	sigTags := strings.Split("cco", ",")
	var filteredSpecs []*et.ExtensionTestSpec
	allSpecs.Walk(func(spec *et.ExtensionTestSpec) {
		for _, tag := range sigTags {
			tag = strings.TrimSpace(tag)
			if strings.Contains(spec.Name, "[sig-"+tag+"]") {
				filteredSpecs = append(filteredSpecs, spec)
				return // Found a match, no need to check other tags
			}
		}
	})
	specs := et.ExtensionTestSpecs(filteredSpecs)

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

	// Set lifecycle for all migrated tests to Informing
	// Tests will run but won't block CI on failure
	specs.Walk(func(spec *et.ExtensionTestSpec) {
		spec.Lifecycle = et.LifecycleInforming
	})

	// Wrap test execution with cleanup handler
	// This marks tests as started and ensures proper cleanup
	specs.Walk(func(spec *et.ExtensionTestSpec) {
		originalRun := spec.Run
		spec.Run = func(ctx context.Context) *et.ExtensionTestResult {
			var result *et.ExtensionTestResult
			util.WithCleanup(func() {
				result = originalRun(ctx)
			})
			return result
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

	// Use testdata package to prevent unused import error
	_ = testdata.FixturePath
}
