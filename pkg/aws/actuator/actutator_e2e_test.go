//go:build e2e
// +build e2e

package actuator

import (
	"testing"
)

// Test_CheckSTS runs end-to-end tests to verify the basics of an STS workflow work.

func Test_CheckSTS(t *testing.T) {
	t.Run("test of STS", func(t *testing.T) {
		t.Parallel()
	})
}
