package extend

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	ote "github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"

	"github.com/google/go-github/v57/github"
	"github.com/tidwall/gjson"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/wait"
)

var _ = g.Describe("[Jira:\"Cloud Credential Operator\"] Cluster_Operator CCO is enabled", func() {
	defer g.GinkgoRecover()

	var (
		oc           = newCLI("default-cco")
		modeInMetric string
	)

	g.JustBeforeEach(func() {
		skipNoCapabilities(oc, ccoCap)
		skipIfHypershiftHostedCluster(oc)
		skipIfMicroShift(oc)
	})

	// Upgrade test: skipped until QE CI migration.
	// g.It("[Suite:cco/conformance/parallel][OTP][PolarionID:23352] NonHyperShiftHOST-PstChkUpgrade-NonPreRelease-High-Cloud credential operator resets progressing transition timestamp when it upgrades", ote.Informing(), func() {
	// 	g.By("Check if ns-23352 namespace exists")
	// 	ns := "ns-23352"
	// 	err := oc.AsAdmin().WithoutNamespace().Run("get").Args("ns", ns).Execute()
	// 	if err != nil {
	// 		g.Skip("Skip the PstChkUpgrade test as ns-23352 namespace does not exist, PreChkUpgrade test did not run")
	// 	}
	// 	defer doOcpReq(oc, "delete", true, "ns", ns, "--ignore-not-found=true")

	// 	g.By("Get the progressingTransitionTimestamp before upgrade")
	// 	progressingTransitionTimestampCM := doOcpReq(oc, "get", true, "cm", "cm-23352", "-n", "ns-23352", `-o=jsonpath={.data.progressingTransitionTimestamp}`)
	// 	g.GinkgoT().Logf("progressingTransitionTimestampCM: %s", progressingTransitionTimestampCM)

	// 	g.By("Check the progressing transition timestamp should be reset after upgrade")
	// 	progressingTransitionTimestampAfterUpgrade, err := time.Parse(time.RFC3339, doOcpReq(oc, "get", true, "clusteroperator", "cloud-credential", `-o=jsonpath={.status.conditions[?(@.type=="Progressing")].lastTransitionTime}`))
	// 	o.Expect(err).NotTo(o.HaveOccurred())
	// 	g.GinkgoT().Logf("progressingTransitionTimestampAfterUpgrade: %s", progressingTransitionTimestampAfterUpgrade)
	// 	o.Expect(fmt.Sprintf("%s", progressingTransitionTimestampAfterUpgrade)).NotTo(o.Equal(progressingTransitionTimestampCM))
	// })

	// It is destructive case, will remove root credentials, so adding [Disruptive]. The case duration is greater than 5 minutes
	// so adding [Slow]
	g.It("[Suite:cco/disruptive][OTP][PolarionID:31768][Disruptive][Serial][Slow]NonHyperShiftHOST-High-Report the mode of cloud-credential operation as a metric", ote.Informing(), func() {
		iaasPlatform, err := getIaasPlatform(oc)
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Get cco mode from Cluster Resource")
		modeInCR, err := getCloudCredentialMode(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		// Skip tests for AWS STS and GCP WIF, since we have known issues with these cluster types.
		// https://issues.redhat.com/browse/OCPBUGS-29900 - Not a blocker bug
		if (iaasPlatform == "aws" || iaasPlatform == "gcp") && (modeInCR == "manual" || modeInCR == "manualpodidentity") {
			g.Skip("The cluster is AWS/GCP with CCO Manual mode - skipping test due to known issues...")
		}

		if modeInCR == "" {
			g.Fail(fmt.Sprintf("Failed to get cco mode from Cluster Resource"), 1)
		} else {
			g.By("Check if cco mode in metric is the same as cco mode in cluster resources")
			g.GinkgoT().Logf("cco mode in cluster CR is %v", modeInCR)
			g.By("Check if cco mode in Metric is correct")
			token, err := getSAToken(oc)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(token).NotTo(o.BeEmpty())
			err = checkModeInMetric(oc, token, modeInCR, &modeInMetric)
			if err != nil {
				g.Fail(fmt.Sprintf("Failed to check cco mode metric after waiting up to 3 minutes, cco mode should be %v, but is %v in metric", modeInCR, modeInMetric), 1)
			}
			if modeInCR == "mint" {
				g.By("if cco is in mint mode currently, then run the below test")
				g.By("Check cco mode when cco is in Passthrough mode")
				//Force cco mode to Passthrough is NOT supported officially but is good for coverage on AWS/GCP Passthrough mode
				g.GinkgoT().Logf("Force cco mode to Passthrough")
				originCCOMode, err := oc.AsAdmin().Run("get").Args("cloudcredential/cluster", "-o=jsonpath={.spec.credentialsMode}").Output()
				if originCCOMode == "" {
					originCCOMode = "\"\""
				}
				patchYaml := `
spec:
  credentialsMode: ` + originCCOMode
				err = oc.AsAdmin().Run("patch").Args("cloudcredential/cluster", "-p", `{"spec":{"credentialsMode":"Passthrough"}}`, "--type=merge").Execute()
				defer func() {
					err := oc.AsAdmin().Run("patch").Args("cloudcredential/cluster", "-p", patchYaml, "--type=merge").Execute()
					o.Expect(err).NotTo(o.HaveOccurred())
					err = checkModeInMetric(oc, token, modeInCR, &modeInMetric)
					if err != nil {
						g.Fail(fmt.Sprintf("Failed to check cco mode metric after waiting up to 3 minutes, cco mode should be %v, but is %v in metric", modeInCR, modeInMetric), 1)
					}
				}()
				o.Expect(err).NotTo(o.HaveOccurred())
				g.By("Get cco mode from cluster CR")
				modeInCR, err = getCloudCredentialMode(oc)
				g.GinkgoT().Logf("cco mode in cluster CR is %v", modeInCR)
				o.Expect(err).NotTo(o.HaveOccurred())
				g.By("Check if cco mode in Metric is correct")
				err = checkModeInMetric(oc, token, modeInCR, &modeInMetric)
				if err != nil {
					g.Fail(fmt.Sprintf("Failed to check cco mode metric after waiting up to 3 minutes, cco mode should be %v, but is %v in metric", modeInCR, modeInMetric), 1)
				}
				g.By("Check cco mode when root credential is removed when cco is not in manual mode")
				g.GinkgoT().Logf("remove root creds")
				rootSecretName, err := getRootSecretName(oc)
				o.Expect(err).NotTo(o.HaveOccurred())
				rootSecretYaml, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", rootSecretName, "-n", KubeSystemNamespace, "-o=yaml").OutputToFile("root-secret.yaml")
				o.Expect(err).NotTo(o.HaveOccurred())
				defer func() {
					os.Remove("root-secret.yaml")
				}()
				err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("secret", rootSecretName, "-n", KubeSystemNamespace).Execute()
				defer func() {
					err = oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", rootSecretYaml).Execute()
					o.Expect(err).NotTo(o.HaveOccurred())
				}()
				o.Expect(err).NotTo(o.HaveOccurred())
				g.By("Get cco mode from cluster CR")
				modeInCR, err = getCloudCredentialMode(oc)
				g.GinkgoT().Logf("cco mode in cluster CR is %v", modeInCR)
				o.Expect(err).NotTo(o.HaveOccurred())
				g.By("Get cco mode from Metric")
				err = checkModeInMetric(oc, token, modeInCR, &modeInMetric)
				if err != nil {
					g.Fail(fmt.Sprintf("Failed to check cco mode metric after waiting up to 3 minutes, cco mode should be %v, but is %v in metric", modeInCR, modeInMetric), 1)
				}
			}
		}
	})

	g.It("[Suite:cco/conformance/parallel][OTP][PolarionID:33204][Level0][platform:azure] NonHyperShiftHOST-Critical-[cco-passthrough]IPI on azure with cco passthrough mode", ote.Informing(), func() {
		g.By("Check if it's an azure cluster")
		skipIfPlatformTypeNot(oc, "azure")

		mode, _ := getCloudCredentialMode(oc)
		if mode != "passthrough" {
			g.Skip("The cco mode is not passthrough - skipping test ...")
		}

		g.By("Check root credential has passthrough annotations")
		o.Expect(doOcpReq(oc, "get", true, "secret", "-n", KubeSystemNamespace, AzureRootSecretName, "-o=jsonpath={.metadata.annotations.cloudcredential\\.openshift\\.io/mode}")).Should(o.Equal("passthrough"))
	})

	//For bug https://bugzilla.redhat.com/show_bug.cgi?id=1940142
	//For bug https://bugzilla.redhat.com/show_bug.cgi?id=1952891
	g.It("[Suite:cco/disruptive][OTP][PolarionID:45415][Level0][Disruptive][Serial][platform:openstack] NonHyperShiftHOST-High-[Bug 1940142] Reset CACert to correct path", ote.Informing(), func() {
		g.By("Check if it's an osp cluster")
		skipIfPlatformTypeNot(oc, "openstack")
		g.By("Get openstack root credential clouds.yaml field")
		goodCreds, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", OpenStackRootSecretName, "-n", KubeSystemNamespace, "-o=jsonpath={.data.clouds\\.yaml}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		goodCredsYaml := `
data:
  clouds.yaml: ` + goodCreds

		g.By("Check cacert path is correct")
		CredsTXT, err := base64.StdEncoding.DecodeString(goodCreds)
		o.Expect(err).NotTo(o.HaveOccurred())
		g.By("Check if it's a kuryr cluster")
		if !strings.Contains(string(CredsTXT), "cacert") {
			g.Skip("Skip for non-kuryr cluster!")
		}
		o.Expect(CredsTXT).To(o.ContainSubstring("cacert: /etc/kubernetes/static-pod-resources/configmaps/cloud-config/ca-bundle.pem"))

		g.By("Patch cacert path to an wrong path")
		var filename = "creds_45415.txt"
		err = os.WriteFile(filename, []byte(CredsTXT), 0o644)
		defer os.Remove(filename)
		o.Expect(err).NotTo(o.HaveOccurred())
		wrongPath, err := exec.Command("bash", "-c", fmt.Sprintf("sed -i -e \"s/cacert: .*/cacert: path-no-exist/g\" %s && cat %s", filename, filename)).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(wrongPath).To(o.ContainSubstring("cacert: path-no-exist"))
		o.Expect(wrongPath).NotTo(o.ContainSubstring("cacert: /etc/kubernetes/static-pod-resources/configmaps/cloud-config/ca-bundle.pem"))
		badCreds := base64.StdEncoding.EncodeToString(wrongPath)
		wrongCredsYaml := `
data:
  clouds.yaml: ` + badCreds
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("secret", OpenStackRootSecretName, "-n", KubeSystemNamespace, "--type=merge", "-p", wrongCredsYaml).Execute()
		defer func() {
			oc.AsAdmin().WithoutNamespace().Run("patch").Args("secret", OpenStackRootSecretName, "-n", KubeSystemNamespace, "--type=merge", "-p", goodCredsYaml).Execute()
			g.By("Wait for the storage operator to recover")
			err = wait.Poll(10*time.Second, 60*time.Second, func() (bool, error) {
				output, err := oc.AsAdmin().Run("get").Args("co", "storage").Output()
				if err != nil {
					g.GinkgoT().Logf("Fail to get clusteroperator storage, error: %s. Trying again", err)
					return false, nil
				}
				if matched, _ := regexp.MatchString("True.*False.*False", output); matched {
					g.GinkgoT().Logf("clusteroperator storage is recover to normal:\n%s", output)
					return true, nil
				}
				return false, nil
			})
			assertWaitPollNoErr(err, "clusteroperator storage is not recovered to normal")
		}()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Check cco change wrong path to correct one")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", OpenStackRootSecretName, "-n", KubeSystemNamespace, "-o=jsonpath={.data.clouds\\.yaml}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		credsTXT, err := base64.StdEncoding.DecodeString(output)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(credsTXT).To(o.ContainSubstring("cacert: /etc/kubernetes/static-pod-resources/configmaps/cloud-config/ca-bundle.pem"))
		o.Expect(credsTXT).NotTo(o.ContainSubstring("cacert: path-no-exist"))

		g.By("Patch cacert path to an empty path")
		wrongPath, err = exec.Command("bash", "-c", fmt.Sprintf("sed -i -e \"s/cacert: .*/cacert:/g\" %s && cat %s", filename, filename)).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(wrongPath).To(o.ContainSubstring("cacert:"))
		o.Expect(wrongPath).NotTo(o.ContainSubstring("cacert: path-no-exist"))
		badCreds = base64.StdEncoding.EncodeToString(wrongPath)
		wrongCredsYaml = `
data:
  clouds.yaml: ` + badCreds
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("secret", OpenStackRootSecretName, "-n", KubeSystemNamespace, "--type=merge", "-p", wrongCredsYaml).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Check cco remove cacert field when it's value is empty")
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", "openstack-credentials", "-n=kube-system", "-o=jsonpath={.data.clouds\\.yaml}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		credsTXT, err = base64.StdEncoding.DecodeString(output)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(credsTXT).NotTo(o.ContainSubstring("cacert:"))

		g.By("recover root credential")
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("secret", OpenStackRootSecretName, "-n", KubeSystemNamespace, "--type=merge", "-p", goodCredsYaml).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		output, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", "openstack-credentials", "-n=kube-system", "-o=jsonpath={.data.clouds\\.yaml}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		credsTXT, err = base64.StdEncoding.DecodeString(output)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(credsTXT).To(o.ContainSubstring("cacert: /etc/kubernetes/static-pod-resources/configmaps/cloud-config/ca-bundle.pem"))
	})

	g.It("[Suite:cco/conformance/parallel][OTP][PolarionID:36498][Level0][platform:aws] NonHyperShiftHOST-ROSA-OSD_CCS-Critical-CCO credentials secret change to STS-style", ote.Informing(), func() {
		//Check IAAS platform type
		iaasPlatform := checkPlatform(oc)
		if iaasPlatform != "aws" {
			g.Skip("IAAS platform is " + iaasPlatform + " while 36498 is for AWS - skipping test ...")
		}
		//Check CCO mode
		mode, err := getCloudCredentialMode(oc)
		g.GinkgoT().Logf("cco mode in cluster is %v", mode)
		o.Expect(err).NotTo(o.HaveOccurred())
		if mode == "manual" {
			g.Skip(" Test case 36498 is not for cco mode=manual - skipping test ...")
		}
		if !checkSTSStyle(oc, mode) {
			g.Fail("The secret format didn't pass STS style check.")
		}
	})

	g.It("[Suite:cco/conformance/parallel][OTP][PolarionID:50869] NonHyperShiftHOST-ROSA-OSD_CCS-ARO-Medium-High-53283-High-77285-CCO Pod Security Admission change", ote.Informing(), func() {
		g.By("1.Check cloud-credential-operator pod")
		ccoPodName, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-l", "app=cloud-credential-operator", "-n", DefaultNamespace, "-o=jsonpath={.items[*].metadata.name}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		allowPrivilegeEscalation, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", ccoPodName, "-n", DefaultNamespace, "-o=jsonpath={.spec.containers[*].securityContext.allowPrivilegeEscalation}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(allowPrivilegeEscalation).NotTo(o.ContainSubstring("true"))
		drop, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", ccoPodName, "-n", DefaultNamespace, "-o=jsonpath={.spec.containers[*].securityContext.capabilities.drop}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		dropAllCount := strings.Count(drop, "ALL")
		o.Expect(dropAllCount).To(o.Equal(2))
		runAsNonRoot, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", ccoPodName, "-n", DefaultNamespace, "-o=jsonpath={.spec.securityContext.runAsNonRoot}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(runAsNonRoot).To(o.Equal("true"))
		seccompProfileType, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", ccoPodName, "-n", DefaultNamespace, "-o=jsonpath={.spec.securityContext.seccompProfile.type}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(seccompProfileType).To(o.Equal("RuntimeDefault"))
		//Check IAAS platform type
		iaasPlatform := checkPlatform(oc)
		if iaasPlatform == "aws" || (iaasPlatform == "azure" && isWorkloadIdentityCluster(oc)) || iaasPlatform == "gcp" {
			g.By(fmt.Sprintf("2.Check pod-identity-webhook pod for %s", iaasPlatform))
			if isSNOCluster(oc) {
				checkWebhookSecurityContext(oc, 1)
			} else {
				checkWebhookSecurityContext(oc, 2)
			}
		}
	})

	// The feature is supported starting from version 4.19.
	g.It("[Suite:cco/conformance/parallel][OTP][PolarionID:80542] NonHyperShiftHOST-ROSA-OSD_CCS-ARO-High-Enable readOnlyRootFilesystem on all containers", ote.Informing(), func() {
		g.By("Check if SCC Security readOnlyRootFilesystem is correctly configured for the cloud-credential-operator")
		ccoOperatorPods, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-l", "app=cloud-credential-operator", "-n", DefaultNamespace, "-o=jsonpath={.items[*].metadata.name}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		ccoOperatorPodList := strings.Fields(ccoOperatorPods)

		podsToCheck := ccoOperatorPodList
		iaasPlatform := checkPlatform(oc)
		if iaasPlatform == "aws" || iaasPlatform == "gcp" || (iaasPlatform == "azure" && isWorkloadIdentityCluster(oc)) {
			g.GinkgoT().Logf("Checking pod-identity-webhook pod for readOnlyRootFilesystem enable")
			podIdentityWebhookPods, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-l", "app=pod-identity-webhook", "-n", DefaultNamespace, "-o=jsonpath={.items[*].metadata.name}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			podIdentityWebhookPodList := strings.Fields(podIdentityWebhookPods)
			podsToCheck = append(podsToCheck, podIdentityWebhookPodList...)
		}

		for _, podName := range podsToCheck {
			containers, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", podName, "-n", DefaultNamespace, "-o=jsonpath={.spec.containers[*].name}").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			containerList := strings.Fields(containers)

			for _, container := range containerList {
				g.GinkgoT().Logf("Testing Pod: %s | Container: %s", podName, container)
				_, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", DefaultNamespace, "-c", container, podName, "--", "sh", "-c", "touch /testfile").Output()
				o.Expect(err).To(o.HaveOccurred())

				readOnlyRootFilesystem, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", podName, "-n", DefaultNamespace, "-o=jsonpath={.spec.containers[*].securityContext.readOnlyRootFilesystem}").Output()
				o.Expect(err).NotTo(o.HaveOccurred())
				o.Expect(readOnlyRootFilesystem).To(o.ContainSubstring("true"))

				g.GinkgoT().Logf("Check tls-ca-bundle.pem mount in Pod %s", podName)
				_, err = oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", DefaultNamespace, "-c", container, podName, "--", "ls", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem").Output()
				o.Expect(err).NotTo(o.HaveOccurred())
			}
		}
	})

	g.It("[Suite:cco/disruptive][OTP][PolarionID:48360][Disruptive][Serial][platform:aws] NonHyperShiftHOST-Medium-Reconciliation of aws pod identity mutating webhook did not happen", ote.Informing(), func() {
		//Check IAAS platform type
		iaasPlatform := checkPlatform(oc)
		if iaasPlatform != "aws" {
			g.Skip("IAAS platform is " + iaasPlatform + " while 48360 is for AWS - skipping test ...")
		}
		g.By("1.Check the Mutating Webhook Configuration service port is 443")
		port, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("mutatingwebhookconfiguration", "pod-identity-webhook", "-o=jsonpath={.webhooks[].clientConfig.service.port}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(port).To(o.Equal("443"))
		g.By("2.Scale down cco pod")
		output, err := oc.AsAdmin().WithoutNamespace().Run("scale").Args("deployment", "cloud-credential-operator", "-n", DefaultNamespace, "--replicas=0").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("scaled"))
		g.By("3.Change the Mutating Webhook Configuration port to 444")
		patchContent := "[{\"op\": \"replace\", \"path\": \"/webhooks/0/clientConfig/service/port\", \"value\":444}]"
		patchResourceAsAdmin(oc, oc.Namespace(), "mutatingwebhookconfiguration", "pod-identity-webhook", patchContent)
		o.Expect(err).NotTo(o.HaveOccurred())
		g.By("4.Now the Mutating Webhook Configuration service port is 444")
		port, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("mutatingwebhookconfiguration", "pod-identity-webhook", "-o=jsonpath={.webhooks[].clientConfig.service.port}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(port).To(o.Equal("444"))
		g.By("5.1.Scale up cco pod")
		output, err = oc.AsAdmin().WithoutNamespace().Run("scale").Args("deployment", "cloud-credential-operator", "-n", DefaultNamespace, "--replicas=1").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("scaled"))
		//Need wait for some time to verify if the port reset to 443
		g.By("5.2.Check the Mutating Webhook Configuration service port is reset to 443")
		errWait := wait.Poll(3*time.Second, 60*time.Second, func() (bool, error) {
			result, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("mutatingwebhookconfiguration", "pod-identity-webhook", "-o=jsonpath={.webhooks[].clientConfig.service.port}").Output()
			if err != nil || result != "443" {
				g.GinkgoT().Logf("Encountered error or the port is NOT reset yet, and try next round")
				return false, nil
			}
			return true, nil
		})
		assertWaitPollNoErr(errWait, "The port is not reset to 443")
	})

	g.It("[Suite:cco/disruptive][OTP][PolarionID:45975][Disruptive][Serial] NonHyperShiftHOST-Medium-Test cco condition changes", ote.Informing(), func() {
		//Check CCO mode
		mode, err := getCloudCredentialMode(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		g.GinkgoT().Logf("cco mode in cluster is %v", mode)
		if mode == "manual" || mode == "manualpodidentity" {
			g.Skip(" Test case 45975 is not for cco mode manual - skipping test ...")
		}

		//Check IAAS platform type
		iaasPlatform, err := getIaasPlatform(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		var providerSpec string
		switch iaasPlatform {
		case "aws":
			providerSpec = "AWSProviderSpec"
		case "azure":
			providerSpec = "AzureProviderSpec"
		case "gcp":
			providerSpec = "GCPProviderSpec"
		case "openstack":
			providerSpec = "OpenStackProviderSpec"
		case "vsphere":
			providerSpec = "VSphereProviderSpec"
		default:
			g.Skip("IAAS platform is " + iaasPlatform + " which is NOT supported by 45975 - skipping test ...")
		}
		g.By("Degraded condition status is False at first")
		degradedStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "cloud-credential", `-o=jsonpath={.status.conditions[?(@.type=="Degraded")].status}`).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(degradedStatus).To(o.Equal("False"))

		g.By("Create 1st CredentialsRequest whose namespace does not exist")
		// NOTE: tests run with repo root as CWD, so use an explicit path.
		crTemp := filepath.Join("test", "extend", "testdata", "credentials_request.yaml")
		crName1 := "cloud-credential-operator-iam-ro-1"
		crNamespace := "namespace-does-not-exist"
		credentialsRequest1 := credentialsRequest{
			name:      crName1,
			namespace: crNamespace,
			provider:  providerSpec,
			template:  crTemp,
		}
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("CredentialsRequest", crName1, "-n", DefaultNamespace, "--ignore-not-found").Execute()
		credentialsRequest1.create(oc)

		g.By("Check the Degraded status is True now and save the timestamp")
		err = wait.Poll(3*time.Second, 60*time.Second, func() (bool, error) {
			degradedStatus, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "cloud-credential", `-o=jsonpath={.status.conditions[?(@.type=="Degraded")].status}`).Output()
			if err != nil || degradedStatus != "True" {
				g.GinkgoT().Logf("Degraded status is NOT True yet, and try next round")
				return false, nil
			}
			return true, nil
		})
		assertWaitPollNoErr(err, "Degraded status is NOT set to True due to wrong CR.")

		//save lastTransitionTime of Degraded condition
		oldDegradedTimestamp, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "cloud-credential", `-o=jsonpath={.status.conditions[?(@.type=="Degraded")].lastTransitionTime}`).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		//save lastTransitionTime of Progressing condition
		oldProgressingTimestamp, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "cloud-credential", `-o=jsonpath={.status.conditions[?(@.type=="Progressing")].lastTransitionTime}`).Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Create 2nd CredentialsRequest whose namespace does not exist")
		crName2 := "cloud-credential-operator-iam-ro-2"
		credentialsRequest2 := credentialsRequest{
			name:      crName2,
			namespace: crNamespace,
			provider:  providerSpec,
			template:  crTemp,
		}
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("CredentialsRequest", crName2, "-n", DefaultNamespace, "--ignore-not-found").Execute()
		credentialsRequest2.create(oc)

		g.By("Check 2 CR reporting errors and lastTransitionTime of Degraded and Progressing not changed")
		err = wait.Poll(3*time.Second, 60*time.Second, func() (bool, error) {
			progressingMessage, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "cloud-credential", `-o=jsonpath={.status.conditions[?(@.type=="Progressing")].message}`).Output()
			if err != nil || !strings.Contains(progressingMessage, "2 reporting errors") {
				g.GinkgoT().Logf("CCO didn't detect 2nd wrong CR yet, and try next round")
				return false, nil
			}
			return true, nil
		})
		assertWaitPollNoErr(err, "CCO didn't detect 2nd wrong CR finally.")

		//compare the lastTransitionTime
		newDegradedTimestamp, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "cloud-credential", `-o=jsonpath={.status.conditions[?(@.type=="Degraded")].lastTransitionTime}`).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(newDegradedTimestamp).To(o.Equal(oldDegradedTimestamp))
		newProgressingTimestamp, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "cloud-credential", `-o=jsonpath={.status.conditions[?(@.type=="Progressing")].lastTransitionTime}`).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(newProgressingTimestamp).To(o.Equal(oldProgressingTimestamp))
	})

	//For bug https://bugzilla.redhat.com/show_bug.cgi?id=1977319
	g.It("[Suite:cco/conformance/parallel][OTP][PolarionID:45219] NonHyperShiftHOST-ROSA-OSD_CCS-ARO-High-A fresh cluster should not have stale CR", ote.Informing(), func() {
		output, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "controller-manager-service", "-n", DefaultNamespace).Output()
		o.Expect(output).To(o.ContainSubstring("Error from server (NotFound)"))
	})

	g.It("[Suite:cco/conformance/parallel][OTP][PolarionID:34470] NonHyperShiftHOST-ROSA-OSD_CCS-ARO-Critical-Cloud credential operator health check", ote.Informing(), func() {
		iaasPlatform, err := getIaasPlatform(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		// Skip tests for IBMCloud/Nutanix due to known issues with these platforms.
		// https://issues.redhat.com/browse/OCPBUGS-29840 - Not a blocker bug
		if iaasPlatform == "ibmcloud" || iaasPlatform == "nutanix" {
			g.Skip("The cluster is IBMCloud/Nutanix - skipping test due to known issues...")
		}

		g.By("Check CCO status conditions")
		//Check CCO mode
		mode, err := getCloudCredentialMode(oc)
		g.GinkgoT().Logf("cco mode in cluster is %v", mode)
		o.Expect(err).NotTo(o.HaveOccurred())
		checkCCOHealth(oc, mode)
		g.By("Check CCO imagePullPolicy configuration")
		imagePullPolicy, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("deployment", "cloud-credential-operator", "-n", DefaultNamespace, "-o=jsonpath={.spec.template.spec.containers[1].imagePullPolicy}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(imagePullPolicy).To(o.Equal("IfNotPresent"))
	})

	g.It("[Suite:cco/conformance/parallel][OTP][PolarionID:66538][Level0][platform:azure] NonHyperShiftHOST-OSD_CCS-ARO-Critical-Azure workload identity cluster healthy check", ote.Informing(), func() {
		mode, _ := getCloudCredentialMode(oc)
		if !(checkPlatform(oc) == "azure" && mode == "manualpodidentity") {
			g.Skip("The cluster is not Azure Workload Identity Cluster - skipping test ...")
		}

		g.By("Check CCO status conditions")
		checkCCOHealth(oc, mode)

		g.By("The Azure workload identity cluster does not have `root` credentials")
		cmdOut, err := oc.AsAdmin().Run("get").Args("secret", AzureRootSecretName, "-n", KubeSystemNamespace).Output()
		o.Expect(err).Should(o.HaveOccurred())
		o.Expect(cmdOut).To(o.ContainSubstring("Error from server (NotFound)"))

		g.By("The secret should contain azure_federated_token_file instead of azure credential keys.")
		o.Expect(strings.Contains(doOcpReq(oc, "get", true, "secrets", "-n", OpenShiftImageRegistryNamespace, InstallerCloudCredentialsSecretName, "-o=jsonpath={.data}"), "azure_federated_token_file")).Should(o.BeTrue())
	})

	g.It("[Suite:cco/conformance/parallel][OTP][PolarionID:64885][platform:aws] NonHyperShiftHOST-OSD_CCS-ARO-Critical-CCO-based flow for olm managed operators and AWS STS", ote.Informing(), func() {
		skipIfPlatformTypeNot(oc, "aws")
		if !isSTSCluster(oc) {
			g.Skip("This test case is AWS STS only, skipping")
		}

		var (
			testCaseID       = "64885"
			crName           = "cr-" + testCaseID
			targetSecretName = crName
			targetNs         = oc.Namespace()
			stsIAMRoleARN    = "whatever"
			cloudTokenPath   = "anything"
		)

		var (
			targetSecretCreated = func() bool {
				stdout, _, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("Secret", "-n", targetNs).Outputs()
				o.Expect(err).NotTo(o.HaveOccurred())
				return strings.Contains(stdout, targetSecretName)
			}
		)

		g.By("Creating dummy CR")
		cr := credentialsRequest{
			name:      crName,
			namespace: targetNs,
			provider:  "AWSProviderSpec",
			template:  filepath.Join("test", "extend", "testdata", "credentials_request.yaml"),
		}
		defer func() {
			_ = oc.AsAdmin().WithoutNamespace().Run("delete").Args("CredentialsRequest", crName, "-n", DefaultNamespace).Execute()
		}()
		cr.create(oc)

		g.By("Making sure the target Secret is not created")
		o.Consistently(targetSecretCreated).WithTimeout(DefaultTimeout * time.Second).WithPolling(30 * time.Second).Should(o.BeFalse())

		g.By("Inserting an stsIAMRoleARN to the CR")
		stsIAMRoleARNPatch := `
spec:
  providerSpec:
    stsIAMRoleARN: ` + stsIAMRoleARN
		err := oc.
			AsAdmin().
			WithoutNamespace().
			Run("patch").
			Args("CredentialsRequest", crName, "-n", DefaultNamespace, "--type", "merge", "-p", stsIAMRoleARNPatch).
			Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Making sure the target Secret is created correctly")
		o.Eventually(targetSecretCreated).WithTimeout(DefaultTimeout * time.Second).WithPolling(30 * time.Second).Should(o.BeTrue())
		stdout, _, err := oc.
			AsAdmin().
			WithoutNamespace().
			Run("extract").
			Args("Secret/"+targetSecretName, "-n", targetNs, "--keys", "credentials", "--to", "-").
			Outputs()
		o.Expect(err).NotTo(o.HaveOccurred())
		// The Secret does not contain any sensitive info
		g.GinkgoT().Logf("Secret extracted = %v", stdout)
		o.Expect(stdout).To(o.ContainSubstring("[default]"))
		o.Expect(stdout).To(o.ContainSubstring("sts_regional_endpoints = regional"))
		o.Expect(stdout).To(o.ContainSubstring("role_arn = " + stsIAMRoleARN))
		o.Expect(stdout).To(o.ContainSubstring("web_identity_token_file = " + defaultSTSCloudTokenPath))

		g.By("Inserting a cloudTokenPath to the CR")
		cloudTokenPathPatch := `
spec:
  cloudTokenPath: ` + cloudTokenPath
		err = oc.
			AsAdmin().
			WithoutNamespace().
			Run("patch").
			Args("CredentialsRequest", crName, "-n", DefaultNamespace, "--type", "merge", "-p", cloudTokenPathPatch).
			Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Making sure the target Secret is updated in the correct way")
		o.Eventually(func() bool {
			stdout, _, err := oc.
				AsAdmin().
				WithoutNamespace().
				Run("extract").
				Args("Secret/"+targetSecretName, "-n", targetNs, "--keys", "credentials", "--to", "-").
				Outputs()
			o.Expect(err).NotTo(o.HaveOccurred())
			// The Secret does not contain any sensitive info
			g.GinkgoT().Logf("Secret extracted = %v", stdout)
			return strings.Contains(stdout, "web_identity_token_file = "+cloudTokenPath)
		}).WithTimeout(DefaultTimeout * time.Second).WithPolling(30 * time.Second).Should(o.BeTrue())
	})

	g.It("[Suite:cco/conformance/parallel][OTP][PolarionID:69971][platform:azure] NonHyperShiftHOST-OSD_CCS-ARO-Critical-Azure workload identity management for olm managed operators", ote.Informing(), func() {
		skipIfPlatformTypeNot(oc, "azure")
		if !isWorkloadIdentityCluster(oc) {
			g.Skip("This test case is for Azure Workload Identity only, skipping")
		}
		//Provide the following Azure Credentials with fake values
		azureCredList := []azureCredential{
			{
				key:   "azure_subscription_id",
				value: "12345678-1234-1234-1234-123456789ab",
			},
			{
				key:   "azure_tenant_id",
				value: "23456789-2345-2345-2345-23456789abcd",
			},
			{
				key:   "azure_region",
				value: "eastus",
			},
			{
				key:   "azure_client_id",
				value: "3456789a-3456-3456-3456-23456789abcde",
			},
			{
				key:   "azure_federated_token_file",
				value: "/var/run/secrets/token",
			},
		}

		var (
			testCaseID       = "69971"
			crName           = "cr-" + testCaseID
			targetSecretName = crName
			targetNs         = oc.Namespace()
		)

		var (
			targetSecretCreated = func() bool {
				stdout, _, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("Secret", "-n", targetNs).Outputs()
				o.Expect(err).NotTo(o.HaveOccurred())
				return strings.Contains(stdout, targetSecretName)
			}
		)

		g.By("Creating the dummy CR")
		cr := credentialsRequest{
			name:      crName,
			namespace: targetNs,
			provider:  "AzureProviderSpec",
			template:  filepath.Join("test", "extend", "testdata", "credentials_request.yaml"),
		}
		defer func() {
			_ = oc.AsAdmin().WithoutNamespace().Run("delete").Args("CredentialsRequest", crName, "-n", DefaultNamespace).Execute()
		}()
		cr.create(oc)

		g.By("Making sure the target Secret is not created")
		o.Consistently(targetSecretCreated).WithTimeout(60 * time.Second).WithPolling(30 * time.Second).Should(o.BeFalse())

		g.By("Patching the Azure Credentials and cloudTokenPath to the CR")
		crPatch := `
spec:
  cloudTokenPath: ` + azureCredList[4].value + `
  providerSpec:
    azureSubscriptionID: ` + azureCredList[0].value + `
    azureTenantID: ` + azureCredList[1].value + `
    azureRegion: ` + azureCredList[2].value + `
    azureClientID: ` + azureCredList[3].value
		err := oc.
			AsAdmin().
			WithoutNamespace().
			Run("patch").
			Args("CredentialsRequest", crName, "-n", DefaultNamespace, "--type", "merge", "-p", crPatch).
			Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Making sure the target Secret is created correctly")
		o.Eventually(targetSecretCreated).WithTimeout(60 * time.Second).WithPolling(30 * time.Second).Should(o.BeTrue())
		for _, azureCred := range azureCredList {
			credential, err := oc.AsAdmin().WithoutNamespace().Run("extract").Args("secret/"+targetSecretName, "-n", targetNs, "--keys", azureCred.key, "--to", "-").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(credential).To(o.ContainSubstring(azureCred.value))
		}
	})

	g.It("[Suite:cco/conformance/parallel][OTP][PolarionID:75429][platform:gcp] NonHyperShiftHOST-OSD_CCS-Critical-GCP workload identity management for olm managed operators", ote.Informing(), func() {
		skipIfPlatformTypeNot(oc, "gcp")
		if !isWorkloadIdentityCluster(oc) {
			g.Skip("This test case is for GCP Workload Identity only, skipping")
		}
		//Provide the following GCP Credentials with fake values
		gcpCredList := []gcpCredential{
			{
				key:   "audience",
				value: "//iam.googleapis.com/projects/1042363005003/locations/global/workloadIdentityPools/cco-test/providers/cco-test",
			},
			{
				key:   "serviceAccountEmail",
				value: "cco-test-cloud-crede-gtqkl@openshift-qe.iam.gserviceaccount.com",
			},
			{
				key:   "cloudTokenPath",
				value: "/var/run/secrets/token",
			},
		}

		var (
			testCaseID       = "75429"
			crName           = "cr-" + testCaseID
			targetSecretName = crName
			targetNs         = oc.Namespace()
		)

		var (
			targetSecretCreated = func() bool {
				stdout, _, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("Secret", "-n", targetNs).Outputs()
				o.Expect(err).NotTo(o.HaveOccurred())
				return strings.Contains(stdout, targetSecretName)
			}
		)

		g.By("Creating the dummy CR")
		cr := credentialsRequest{
			name:      crName,
			namespace: targetNs,
			provider:  "GCPProviderSpec",
			template:  filepath.Join("test", "extend", "testdata", "credentials_request.yaml"),
		}
		defer func() {
			_ = oc.AsAdmin().WithoutNamespace().Run("delete").Args("CredentialsRequest", crName, "-n", DefaultNamespace).Execute()
		}()
		cr.create(oc)

		g.By("Making sure the target Secret is not created")
		o.Consistently(targetSecretCreated).WithTimeout(60 * time.Second).WithPolling(30 * time.Second).Should(o.BeFalse())

		g.By("Patching the GCP Credentials and cloudTokenPath to the CR")
		crPatch := `
spec:
  cloudTokenPath: ` + gcpCredList[2].value + `
  providerSpec:
    audience: ` + gcpCredList[0].value + `
    serviceAccountEmail: ` + gcpCredList[1].value
		err := oc.
			AsAdmin().
			WithoutNamespace().
			Run("patch").
			Args("CredentialsRequest", crName, "-n", DefaultNamespace, "--type", "merge", "-p", crPatch).
			Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("Making sure the target Secret is created correctly")
		o.Eventually(targetSecretCreated).WithTimeout(60 * time.Second).WithPolling(30 * time.Second).Should(o.BeTrue())
		credentialBase64, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", targetSecretName, "-n", targetNs, "-o=jsonpath={.data.service_account\\.json}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		credential, err := base64.StdEncoding.DecodeString(credentialBase64)
		o.Expect(err).NotTo(o.HaveOccurred())
		//compare audience
		gen_audience := gjson.Get(string(credential), `audience`).String()
		o.Expect(gen_audience).To(o.Equal(gcpCredList[0].value))
		//check serviceAccountEmail
		gen_service_account := gjson.Get(string(credential), `service_account_impersonation_url`).String()
		o.Expect(gen_service_account).To(o.ContainSubstring(gcpCredList[1].value))
		//compare token path
		gen_token_path := gjson.Get(string(credential), `credential_source.file`).String()
		o.Expect(gen_token_path).To(o.Equal(gcpCredList[2].value))
	})
})

var _ = g.Describe("[Jira:\"Cloud Credential Operator\"] Cluster_Operator CCO is disabled", func() {
	defer g.GinkgoRecover()

	var (
		oc = newCLI("cco", kubeConfigPath())
	)

	g.BeforeEach(func() {
		skipIfCapEnabled(oc, ccoCap)
		skipIfHypershiftHostedCluster(oc)
		skipIfMicroShift(oc)
	})

	/*
		Only deals with the first half of OCP-68220 (makes sure CCO-related resources are not found in-cluster).
		The second half of OCP-68220 (day-2 enablement) will be covered by CI Profiles in Prow.

		Hard-coding resources-to-check is avoided since:
		- It leaves us a maintenance burden
		- The test case will not be able to detect such scenario when a resource is added (but not annotated) in the future
	*/
	g.It("[Suite:cco/conformance/parallel][OTP][PolarionID:68220] NonHyperShiftHOST-Critical-Leverage Composable OpenShift feature to make cloud-credential optional", ote.Informing(), func() {
		var (
			getManifestContent = func(manifest *github.RepositoryContent) []byte {
				// Prefer manifest.Content
				if content, _ := manifest.GetContent(); content != "" {
					return []byte(content)
				}

				// Fall back to downloadURL
				downloadURL := manifest.GetDownloadURL()
				o.Expect(downloadURL).NotTo(o.BeEmpty())
				req, err := http.NewRequest("GET", downloadURL, nil)
				o.Expect(err).NotTo(o.HaveOccurred())
				res, err := http.DefaultClient.Do(req)
				o.Expect(err).NotTo(o.HaveOccurred())
				defer func() {
					_ = res.Body.Close()
				}()
				content, err := io.ReadAll(res.Body)
				o.Expect(err).NotTo(o.HaveOccurred())
				return content
			}

			/*
				Here we avoid deserializing manifests through a runtime.Scheme since
				installing all required types (to the scheme) would bring in quite a few
				dependencies, making our test repo unnecessarily heavy.
			*/
			resourceInfoFromManifest = func(manifest []byte) (string, string, string) {
				var deserializedManifest map[string]any
				err := yaml.Unmarshal(manifest, &deserializedManifest)
				o.Expect(err).NotTo(o.HaveOccurred())
				groupVersion, ok := deserializedManifest["apiVersion"].(string)
				o.Expect(ok).To(o.BeTrue())
				groupVersionSlice := strings.Split(groupVersion, "/")
				kind, ok := deserializedManifest["kind"].(string)
				o.Expect(ok).To(o.BeTrue())

				// The oc client is smart enough to map kind to resource before making an API call.
				// There's no need to query the discovery endpoint of the API server ourselves to obtain the gvr.
				var resourceType, namespace, name string
				switch len(groupVersionSlice) {
				// The resource is a part of the core group
				case 1:
					resourceType = kind
				// The resource is not a part of the core group
				case 2:
					resourceType = fmt.Sprintf("%s.%s.%s", kind, groupVersionSlice[1], groupVersionSlice[0])
				default:
					g.Fail(fmt.Sprintf("Unexpected apiVersion format"), 1)
				}

				metadata, ok := deserializedManifest["metadata"].(map[string]any)
				o.Expect(ok).To(o.BeTrue())
				if _, isNamespaced := metadata["namespace"]; isNamespaced {
					namespace, ok = metadata["namespace"].(string)
					o.Expect(ok).To(o.BeTrue())
				}
				name, ok = metadata["name"].(string)
				o.Expect(ok).To(o.BeTrue())
				g.GinkgoT().Logf("Resource type = %v, namespace = %v, name = %v", resourceType, namespace, name)
				return resourceType, namespace, name
			}
		)

		// Get GitHub client
		ghClient := github.NewClient(nil)
		// Authenticate for a much larger rate limit
		if ghToken := os.Getenv("GITHUB_TOKEN"); ghToken != "" {
			ghClient = ghClient.WithAuthToken(ghToken)
		}

		// Get cluster version
		majorMinorVersion, _, err := getClusterVersion(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		targetBranch := fmt.Sprintf("release-%s", majorMinorVersion)

		// Get manifest dir of the CCO repo
		// There's no need to verify the absence of CredentialsRequests defined in other repos.
		// We only need to make sure the corresponding CRD is not found in-cluster.
		g.GinkgoT().Logf("Listing manifest directory of branch %v", targetBranch)
		_, dir, _, err := ghClient.
			Repositories.
			GetContents(context.Background(), "openshift", ccoRepo, ccoManifestPath, &github.RepositoryContentGetOptions{
				Ref: targetBranch,
			})
		if err != nil {
			// Check if it's a rate limit error
			if rateLimitErr, ok := err.(*github.RateLimitError); ok {
				g.GinkgoT().Logf("GitHub API rate limit exceeded. Remaining: %d, Reset: %v", rateLimitErr.Rate.Remaining, rateLimitErr.Rate.Reset.Time)
				g.Skip(fmt.Sprintf("GitHub API rate limit exceeded. Set GITHUB_TOKEN environment variable for higher rate limits. Rate reset in %v", rateLimitErr.Rate.Reset.Time.Sub(time.Now())))
			}
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		// Iterate through items in the manifest dir
		for _, manifest := range dir {
			if manifest.GetType() != "file" {
				continue
			}
			manifestName := manifest.GetName()
			if !strings.HasSuffix(manifestName, ".yaml") && !strings.HasSuffix(manifestName, ".yml") {
				continue
			}

			g.GinkgoT().Logf("Getting content of manifest %v", manifestName)
			content := getManifestContent(manifest)

			g.GinkgoT().Logf("Extracting resource info from manifest")
			resourceType, namespace, name := resourceInfoFromManifest(content)

			g.GinkgoT().Logf("Requesting manifest against the API server")
			getReqArgs := []string{resourceType, name}
			if namespace != "" {
				getReqArgs = append(getReqArgs, "-n", namespace)
			}
			// err is the error returned by executing an exec.Command
			// stderr captures the original error message return by the API server
			_, stderr, err := oc.AsAdmin().WithoutNamespace().Run("get").Args(getReqArgs...).Outputs()
			o.Expect(err).To(o.HaveOccurred())
			o.Expect(stderr).To(o.Or(
				o.ContainSubstring("not found"),
				o.ContainSubstring("the server doesn't have a resource type"),
			))
		}
	})
})
