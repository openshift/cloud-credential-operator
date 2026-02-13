package main

import (
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

	// Create our registry of openshift-tests extensions
	extensionRegistry := e.NewRegistry()
	ext := e.NewExtension("openshift", "payload", "cloud-credential-operator")
	extensionRegistry.Register(ext)

	// Carve up the kube tests into our openshift suites...
	ext.AddSuite(e.Suite{
		Name: "cco/conformance/parallel",
		Parents: []string{
			"openshift/conformance/parallel",
		},
		Qualifiers: []string{
			`!(name.contains("[Serial]") || name.contains("[Slow]"))`,
		},
	})

	ext.AddSuite(e.Suite{
		Name: "cco/conformance/serial",
		Parents: []string{
			"openshift/conformance/serial",
		},
		Qualifiers: []string{
			`name.contains("[Serial]")`,
		},
	})

	// Suite: optional/slow (long-running tests)
	ext.AddSuite(e.Suite{
		Name:    "cco/optional/slow",
		Parents: []string{"openshift/optional/slow"},
		Qualifiers: []string{
			`name.contains("[Slow]")`,
		},
	})

	// If using Ginkgo, build test specs automatically
	// Use custom filter to handle both file system paths and module paths for vendor exclusion
	specs, err := g.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite(func(spec *extensiontests.ExtensionTestSpec) bool {
		// Only include tests from cloud-credential-operator module (exclude vendor tests)
		for _, cl := range spec.CodeLocations {
			// Handle file system paths (e.g., /path/to/vendor/k8s.io/...)
			if strings.Contains(cl, "/vendor/") {
				return false
			}
			// Handle module paths (e.g., k8s.io/kubernetes@v1.33.2/...)
			if strings.HasPrefix(cl, "k8s.io/") || strings.HasPrefix(cl, "sigs.k8s.io/") {
				return false
			}
			// Include cloud-credential-operator tests
			if strings.Contains(cl, "cloud-credential-operator/test/extend") {
				return true
			}
		}
		return false
	})
	if err != nil {
		panic(fmt.Sprintf("couldn't build extension test specs from ginkgo: %+v", err.Error()))
	}

	// Handle platform-specific tests by setting proper environmentSelector
	foundPlatforms := make(map[string]string)
	for _, test := range specs.Select(extensiontests.NameContains("[platform:")).Names() {
		re := regexp.MustCompile(`\[platform:[a-z]*]`)
		matches := re.FindAllString(test, -1)
		for _, platformDef := range matches {
			if _, ok := foundPlatforms[platformDef]; !ok {
				platform := platformDef[strings.Index(platformDef, ":")+1 : len(platformDef)-1]
				foundPlatforms[platformDef] = platform
			}
			specs.Select(extensiontests.NameContains(platformDef)).
				Include(extensiontests.PlatformEquals(platformDef[strings.Index(platformDef, ":")+1 : len(platformDef)-1]))
		}
	}

	ext.AddSpecs(specs)

	// Cobra stuff
	root := &cobra.Command{
		Long: "Cloud Credential Operator tests extension for OpenShift",
	}

	root.AddCommand(cmd.DefaultExtensionCommands(extensionRegistry)...)

	if err := func() error {
		return root.Execute()
	}(); err != nil {
		os.Exit(1)
	}
}
