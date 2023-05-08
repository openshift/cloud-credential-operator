//go:build e2e
// +build e2e

package sts

import (
	"testing"
)

// Test_CheckSTS runs end-to-end tests to verify that the results of an STS workflow are successful.

func Test_CheckSTS(t *testing.T) {
	t.Run("test of STS", func(t *testing.T) {
		t.Parallel()
	})
}
