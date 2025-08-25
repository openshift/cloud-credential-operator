// shared/shared.go
package shared

import (
	"fmt"
	"os/exec"
	"strings"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	util "github.com/openshift/cloud-credential-operator/test/e2e/common"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

var _ = g.Describe("[sig-cco][Suite:cco/conformance/serial][Serial] Cluster_Operator CCO is enabled", func() {
	defer g.GinkgoRecover()
	var oc *util.CLI

	g.BeforeEach(func() {
		oc = util.NewCLI("cco-shared", util.KubeConfigPath())
		util.SkipOnOpenShiftNess(true)
		oc.SetupProject()
		util.SkipNoCapabilities(oc, "CloudCredential")
	})

	g.AfterEach(func() {
		oc.TeardownProject()
	})

	g.It("PolarionID:82633-[platform:aws][platform:azure][platform:gcp] CCO network policies", func() {
		modeInCR, err := util.GetCloudCredentialMode(oc)
		o.Expect(err).NotTo(o.HaveOccurred())

		ccoNs := "openshift-cloud-credential-operator"

		iaasPlatform, err := util.GetIaasPlatform(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("Platform type is: %s", iaasPlatform)

		if modeInCR == "" {
			e2e.Failf("Failed to get cco mode from Cluster Resource")
		} else {
			e2e.Logf("Verify that the NetworkPolicy has been applied")
			output, err := oc.AsAdmin().Run("get").Args("networkpolicy", "-n", ccoNs).Output()
			e2e.Logf("output is %s", output)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).Should(o.ContainSubstring("allow-egress"))

			ccoPodName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-l", "app=cloud-credential-operator", "-n", "openshift-cloud-credential-operator", "-o=jsonpath={.items[*].metadata.name}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf("ccoPodName is %s", ccoPodName)

			podStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", ccoPodName, "-n", ccoNs, "-o=jsonpath={.status.phase}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(podStatus).To(o.Equal("Running"))

			e2e.Logf("Verify CCO can access Kubernetes API")
			kubernetesVersionOutput, err := exec.Command("oc", "exec",
				"-n", ccoNs,
				ccoPodName,
				"-c", "cloud-credential-operator",
				"--",
				"sh", "-c",
				"curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt --header \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" https://kubernetes.default.svc/version",
			).CombinedOutput()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf("the ")
			o.Expect(string(kubernetesVersionOutput)).To(o.ContainSubstring("gitVersion"))
			e2e.Logf("Successfully verified Kubernetes API access")

			e2e.Logf("Verify CCO can resolve DNS")
			dnsOutput, err := exec.Command("oc", "exec",
				"-n", ccoNs,
				ccoPodName,
				"-c", "cloud-credential-operator",
				"--",
				"sh", "-c",
				"nslookup google.com",
			).CombinedOutput()
			o.Expect(err).NotTo(o.HaveOccurred())
			dnsOutputStr := string(dnsOutput)
			e2e.Logf("DNS resolution output: %s", dnsOutputStr)

			o.Expect(dnsOutputStr).To(o.ContainSubstring("Server:"))
			o.Expect(dnsOutputStr).To(o.ContainSubstring("Address:"))
			o.Expect(dnsOutputStr).To(o.ContainSubstring("Name:"))
			o.Expect(dnsOutputStr).To(o.ContainSubstring("google.com"))
			o.Expect(dnsOutputStr).To(o.And(
				o.ContainSubstring("Address: "),
				o.Or(
					o.ContainSubstring("172."),
					o.ContainSubstring("2607:"),
				),
			))

			e2e.Logf("Verify CCO can access external cloud platform")
			cloudEndpoint := "https://sts.amazonaws.com"

			cloudOutput, err := exec.Command("oc", "exec",
				"-n", ccoNs,
				ccoPodName,
				"-c", "cloud-credential-operator",
				"--",
				"sh", "-c",
				fmt.Sprintf("curl -s -I %s", cloudEndpoint),
			).CombinedOutput()
			o.Expect(err).NotTo(o.HaveOccurred())
			cloudOutputStr := string(cloudOutput)
			e2e.Logf("Cloud platform access output: %s", cloudOutputStr)

			o.Expect(cloudOutputStr).To(o.Or(
				o.ContainSubstring("HTTP/1.1 200"),
				o.ContainSubstring("HTTP/2 200"),
				o.ContainSubstring("HTTP/1.1 302"),
				o.ContainSubstring("HTTP/2 302"),
			))

			defer func() {
				oc.AsAdmin().WithoutNamespace().Run("delete").Args("pod", "test-busybox-cco", "-n", ccoNs).Output()
			}()
			_, err = oc.AsAdmin().WithoutNamespace().Run("run").Args("test-busybox-cco",
				"-n", ccoNs,
				"--image=busybox",
				"--restart=Never",
				"--labels=app=cloud-credential-operator",
				"--overrides={\"spec\":{\"securityContext\":{\"runAsNonRoot\":true,\"allowPrivilegeEscalation\":false,\"seccompProfile\":{\"type\":\"RuntimeDefault\"}},\"containers\":[{\"name\":\"busybox\",\"image\":\"busybox\",\"command\":[\"sleep\",\"3600\"],\"securityContext\":{\"allowPrivilegeEscalation\":false,\"runAsNonRoot\":true,\"capabilities\":{\"drop\":[\"ALL\"]},\"seccompProfile\":{\"type\":\"RuntimeDefault\"}}}]}}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			oc.AsAdmin().WithoutNamespace().Run("wait").Args("pod", "test-busybox-cco", "-n", ccoNs, "--for=condition=Ready", "--timeout=60s").Output()
			o.Expect(err).NotTo(o.HaveOccurred())

			targetIp, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-l", "app=cloud-credential-operator", "-n", ccoNs, "-o=jsonpath={.items[0].status.podIP}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf("targetIp is %s", targetIp)

			ncOutput, err := exec.Command("oc", "exec", "-n", ccoNs, "test-busybox-cco", "-c", "busybox", "--", "sh", "-c", fmt.Sprintf("nc -zv %s 8443", targetIp)).CombinedOutput()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf("ncOutput is %s", string(ncOutput))
			o.Expect(string(ncOutput)).To(o.ContainSubstring("open"))

			e2e.Logf("Verify that the Go runtime profiling endpoint (pprof) is accessible externally.")
			pprofOutput, err := exec.Command("oc", "exec", "-n", ccoNs, "test-busybox-cco", "-c", "busybox", "--", "sh", "-c", fmt.Sprintf("wget -qO- http://%s:6060/debug/pprof/", targetIp)).CombinedOutput()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf("pprofOutput is %s", string(pprofOutput))
			o.Expect(string(pprofOutput)).To(o.ContainSubstring("html"))

			if !(strings.ToLower(iaasPlatform) == "azure" && modeInCR == "passthrough") {
				podIdentityWebhookPodsOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-l", "app=pod-identity-webhook", "-n", ccoNs, "-o=jsonpath={.items[*].metadata.name}").Output()
				podIdentityWebhookPods := strings.Fields(podIdentityWebhookPodsOutput)
				o.Expect(err).NotTo(o.HaveOccurred())
				e2e.Logf("webhookPodName is %s", podIdentityWebhookPods)

				e2e.Logf("Verify pod-identity-webhook can resolve DNS")
				webhookDNSOutput, err := exec.Command("oc", "exec", "-n", ccoNs, podIdentityWebhookPods[0], "-c", "pod-identity-webhook", "--", "sh", "-c", "nslookup google.com").CombinedOutput()
				o.Expect(err).NotTo(o.HaveOccurred())
				webhookDNSOutputStr := string(webhookDNSOutput)
				e2e.Logf("Webhook DNS resolution output: %s", webhookDNSOutputStr)

				o.Expect(webhookDNSOutputStr).To(o.ContainSubstring("Server:"))
				o.Expect(webhookDNSOutputStr).To(o.ContainSubstring("Address:"))
				o.Expect(webhookDNSOutputStr).To(o.ContainSubstring("Name:"))
				o.Expect(webhookDNSOutputStr).To(o.ContainSubstring("google.com"))
				o.Expect(webhookDNSOutputStr).To(o.And(o.ContainSubstring("Address: "), o.Or(o.ContainSubstring("172."), o.ContainSubstring("2607:"))))

				webhookCloudOutput, err := exec.Command("oc", "exec", "-n", ccoNs, podIdentityWebhookPods[0], "-c", "pod-identity-webhook", "--", "sh", "-c", fmt.Sprintf("curl -s -I %s", cloudEndpoint)).CombinedOutput()
				o.Expect(err).NotTo(o.HaveOccurred())
				webhookCloudOutputStr := string(webhookCloudOutput)
				e2e.Logf("Webhook cloud platform access output: %s", webhookCloudOutputStr)

				o.Expect(webhookCloudOutputStr).To(o.Or(
					o.ContainSubstring("HTTP/1.1 200"),
					o.ContainSubstring("HTTP/2 200"),
					o.ContainSubstring("HTTP/1.1 302"),
					o.ContainSubstring("HTTP/2 302"),
				))

				targetIp, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-l", "app=pod-identity-webhook", "-n", ccoNs, "-o=jsonpath={.items[0].status.podIP}").Output()
				o.Expect(err).NotTo(o.HaveOccurred())
				e2e.Logf("targetIp is %s", targetIp)

				webhookOutput, err := exec.Command("oc", "exec", "-n", ccoNs, "test-busybox-cco", "--", "sh", "-c", fmt.Sprintf("wget --no-check-certificate -qO- https://%s:9443/healthz", targetIp)).CombinedOutput()
				o.Expect(err).NotTo(o.HaveOccurred())
				e2e.Logf("webhookOutput is %s", string(webhookOutput))
				o.Expect(string(webhookOutput)).To(o.ContainSubstring("ok"))
			}
		}
	})
})
