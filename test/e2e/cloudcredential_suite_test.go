package cloudcredential

import (
	"testing"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
)

func TestCloudCredential(t *testing.T) {
	o.RegisterFailHandler(g.Fail)
	g.RunSpecs(t, "Cloud Credential Operator Suite")
}
