//go:build tools
// +build tools

package tools

// Official workaround to track tool dependencies with go modules:
// https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module

import (
	_ "github.com/openshift/api/operator/v1/zz_generated.crd-manifests"
)
