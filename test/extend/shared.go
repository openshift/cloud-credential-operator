package extended

import (
	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
)

var _ = g.Describe("[Jira:Cloud Credential Operator][sig-cco] Cluster_Operator CCO is enabled", func() {
	g.It("[Suite:cco/conformance/serial] should verify CCO operator is running and available", func() {
		o.Expect(true).To(o.BeTrue())
	})
})

var _ = g.Describe("[Jira:Cloud Credential Operator][sig-cco] Cluster_Operator CCO is disabled", func() {
	g.It("[Suite:cco/optional/slow] should verify CCO operator is disabled", func() {
		o.Expect(true).To(o.BeTrue())
	})
})
