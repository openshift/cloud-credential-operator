package extended

import (
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	exutil "github.com/openshift/origin/test/extended/util"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"

	e2e "k8s.io/kubernetes/test/e2e/framework"
)

var _ = g.Describe("[sig-cco][Jira:Cloud Credential Operator] Cluster_Operator CCO is enabled", func() {
	defer g.GinkgoRecover()

	var (
		oc = exutil.NewCLI("default-cco")
	)

	g.JustBeforeEach(func() {
		compat_otp.SkipNoCapabilities(oc, ccoCap)
	})

	g.It("[Suite:openshift/cloud-credential-operator/conformance/parallel][PolarionID:33204][OTP] IPI on azure with cco passthrough mode[platform:azure]", func() {
		//NonHyperShiftHOST-Author:mihuang-[Level0]-Critical-33204-[cco-passthrough]
		compat_otp.SkipIfPlatformTypeNot(oc, "azure")

		mode, _ := getCloudCredentialMode(oc)
		if mode != "passthrough" {
			g.Skip("The cco mode is not passthrough - skipping test ...")
		}

		compat_otp.By("Check root credential has passthrough annotations")
		o.Expect(doOcpReq(oc, "get", true, "secret", "-n", "kube-system", "azure-credentials", "-o=jsonpath={.metadata.annotations.cloudcredential\\.openshift\\.io/mode}")).Should(o.Equal("passthrough"))
	})

	g.It("[Suite:openshift/cloud-credential-operator/conformance/parallel][PolarionID:36498][OTP] CCO credentials secret change to STS-style[platform:aws]", func() {
		//NonHyperShiftHOST-ROSA-OSD_CCS-Author:jshu-[Level0]-Critical-36498-CCO credentials secret change to STS-style[platform:aws]
		//Check IAAS platform type
		iaasPlatform := compat_otp.CheckPlatform(oc)
		if iaasPlatform != "aws" {
			g.Skip("IAAS platform is " + iaasPlatform + " while 36498 is for AWS - skipping test ...")
		}
		//Check CCO mode
		mode, err := getCloudCredentialMode(oc)
		e2e.Logf("cco mode in cluster is %v", mode)
		o.Expect(err).NotTo(o.HaveOccurred())
		if mode == "manual" {
			g.Skip(" Test case 36498 is not for cco mode=manual - skipping test ...")
		}
		if !checkSTSStyle(oc, mode) {
			g.Fail("The secret format didn't pass STS style check.")
		}
	})

	g.It("[Suite:openshift/cloud-credential-operator/conformance/parallel][PolarionID:66538][OTP][OCPFeatureGate:AzureWorkloadIdentity] Azure workload identity cluster healthy check.[platform:azure]", func() {
		//NonHyperShiftHOST-OSD_CCS-ARO-Author:mihuang-[Level0]-Critical-66538-Azure workload identity cluster healthy check.[platform:azure]
		mode, _ := getCloudCredentialMode(oc)
		if !(compat_otp.CheckPlatform(oc) == "azure" && mode == "manualpodidentity") {
			g.Skip("The cluster is not Azure Workload Identity Cluster - skipping test ...")
		}

		compat_otp.By("Check CCO status conditions")
		checkCCOHealth(oc, mode)

		compat_otp.By("The Azure workload identity cluster does not have `root` credentials")
		cmdOut, err := oc.AsAdmin().Run("get").Args("secret", "azure-credentials", "-n", "kube-system").Output()
		o.Expect(err).Should(o.HaveOccurred())
		o.Expect(cmdOut).To(o.ContainSubstring("Error from server (NotFound)"))

		compat_otp.By("The secret should contain azure_federated_token_file instead of azure credential keys.")
		o.Expect(strings.Contains(doOcpReq(oc, "get", true, "secrets", "-n", "openshift-image-registry", "installer-cloud-credentials", "-o=jsonpath={.data}"), "azure_federated_token_file")).Should(o.BeTrue())
	})
})
