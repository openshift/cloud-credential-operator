package extend

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
)

const (
	ccoCap                   = "CloudCredential"
	ccoRepo                  = "cloud-credential-operator"
	ccoManifestPath          = "manifests"
	defaultSTSCloudTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	DefaultTimeout           = 120
)

type prometheusQueryResult struct {
	Data struct {
		Result []struct {
			Metric struct {
				Name      string `json:"__name__"`
				Container string `json:"container"`
				Endpoint  string `json:"endpoint"`
				Instance  string `json:"instance"`
				Job       string `json:"job"`
				Mode      string `json:"mode"`
				Namespace string `json:"namespace"`
				Pod       string `json:"pod"`
				Service   string `json:"service"`
			} `json:"metric"`
			Value []interface{} `json:"value"`
		} `json:"result"`
		ResultType string `json:"resultType"`
	} `json:"data"`
	Status string `json:"status"`
}

type credentialsRequest struct {
	name      string
	namespace string
	provider  string
	template  string
}

type azureCredential struct {
	key   string
	value string
}

type gcpCredential struct {
	key   string
	value string
}

func doOcpReq(oc *CLI, verb string, notEmpty bool, args ...string) string {
	logf("running command : oc %s %s\n", verb, strings.Join(args, " "))
	res, err := oc.AsAdmin().WithoutNamespace().Run(verb).Args(args...).Output()
	o.Expect(err).ShouldNot(o.HaveOccurred())
	if notEmpty {
		o.Expect(res).ShouldNot(o.BeEmpty())
	}
	return res
}

func getCloudCredentialMode(oc *CLI) (string, error) {
	var (
		mode           string
		iaasPlatform   string
		rootSecretName string
		err            error
	)
	iaasPlatform, err = getIaasPlatform(oc)
	if err != nil {
		return "", err
	}
	if iaasPlatform == "none" || iaasPlatform == "baremetal" {
		mode = "none" //mode none is for baremetal
		return mode, nil
	}
	//Check if the cloud providers which support Manual mode only
	if iaasPlatform == "ibmcloud" || iaasPlatform == "alibabacloud" || iaasPlatform == "nutanix" {
		mode = "manual"
		return mode, nil
	}
	modeInCloudCredential, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("cloudcredential", "cluster", "-o=jsonpath={.spec.credentialsMode}").Output()
	if err != nil {
		return "", err
	}
	if modeInCloudCredential != "Manual" {
		rootSecretName, err = getRootSecretName(oc)
		if err != nil {
			return "", err
		}
		modeInSecretAnnotation, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", rootSecretName, "-n", KubeSystemNamespace, "-o=jsonpath={.metadata.annotations.cloudcredential\\.openshift\\.io/mode}").Output()
		if err != nil {
			if strings.Contains(modeInSecretAnnotation, "NotFound") {
				if iaasPlatform != "aws" && iaasPlatform != "azure" && iaasPlatform != "gcp" {
					mode = "passthrough"
					return mode, nil
				}
				mode = "credsremoved"
				return mode, nil
			}
			return "", err
		}
		if modeInSecretAnnotation == "insufficient" {
			mode = "degraded"
			return mode, nil
		}
		mode = modeInSecretAnnotation
		return mode, nil
	}
	if iaasPlatform == "aws" {
		if isSTSCluster(oc) {
			mode = "manualpodidentity"
			return mode, nil
		}
	}
	if iaasPlatform == "azure" {
		if isWorkloadIdentityCluster(oc) {
			mode = "manualpodidentity"
			return mode, nil
		}
	}
	mode = "manual"
	return mode, nil
}

func getRootSecretName(oc *CLI) (string, error) {
	iaasPlatform, err := getIaasPlatform(oc)
	if err != nil {
		return "", err
	}
	switch iaasPlatform {
	case "aws":
		return AWSRootSecretName, nil
	case "gcp":
		return GCPRootSecretName, nil
	case "azure":
		return AzureRootSecretName, nil
	case "vsphere":
		return VSphereRootSecretName, nil
	case "openstack":
		return OpenStackRootSecretName, nil
	case "ovirt":
		return OvirtRootSecretName, nil
	default:
		logf("Unsupported platform: %v\n", iaasPlatform)
		return "", nil
	}
}

func getIaasPlatform(oc *CLI) (string, error) {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("infrastructure", "cluster", "-o=jsonpath={.status.platformStatus.type}").Output()
	if err != nil {
		return "", err
	}
	iaasPlatform := strings.ToLower(output)

	if iaasPlatform == "external" {
		externalPlatformNameOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("infrastructure", "cluster", "-o=jsonpath={.spec.platformSpec.external.platformName}").Output()
		if err != nil {
			return "", fmt.Errorf("failed to get external platform name: %w", err)
		}
		iaasPlatform = strings.ToLower(externalPlatformNameOutput)
	}

	return iaasPlatform, nil
}

func checkPlatform(oc *CLI) string {
	p, err := getIaasPlatform(oc)
	if err != nil {
		// Keep existing behavior tolerant; callers will handle skips.
		return ""
	}
	return p
}

func skipIfPlatformTypeNot(oc *CLI, expected string) {
	platform, err := getIaasPlatform(oc)
	if err != nil {
		g.Skip(fmt.Sprintf("failed to detect platform: %v", err))
	}
	if strings.ToLower(platform) != strings.ToLower(expected) {
		g.Skip(fmt.Sprintf("platform is %q, expected %q", platform, expected))
	}
}

// isSTSCluster determines if an AWS cluster is using STS
func isSTSCluster(oc *CLI) bool {
	return isWorkloadIdentityCluster(oc)
}

// isWorkloadIdentityCluster judges whether the cluster is using Workload Identity
func isWorkloadIdentityCluster(oc *CLI) bool {
	serviceAccountIssuer, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("authentication", "cluster", "-o=jsonpath={.spec.serviceAccountIssuer}").Output()
	o.Expect(err).ShouldNot(o.HaveOccurred(), "Failed to get serviceAccountIssuer")
	return len(serviceAccountIssuer) > 0
}

func checkModeInMetric(oc *CLI, token string, mode string, modeInMetric *string) error {
	var data prometheusQueryResult
	return wait.Poll(10*time.Second, 3*time.Minute, func() (bool, error) {
		msg, _, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", OpenShiftMonitoringNamespace, "prometheus-k8s-0", "-c", "prometheus", "--", "curl", "-k", "-H", fmt.Sprintf("Authorization: Bearer %v", token), "https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query?query=cco_credentials_mode").Outputs()
		if err != nil {
			logf("Failed to query prometheus: %v\n", err)
			return false, nil
		}
		if msg == "" {
			logf("Empty response from prometheus query")
			return false, nil
		}
		if err := json.Unmarshal([]byte(msg), &data); err != nil {
			logf("Failed to unmarshal prometheus response: %v\n", err)
			return false, nil
		}
		if len(data.Data.Result) == 0 {
			logf("No results in prometheus query response")
			return false, nil
		}
		*modeInMetric = data.Data.Result[0].Metric.Mode
		logf("cco mode in metric is %v\n", *modeInMetric)
		if *modeInMetric != mode {
			logf("cco mode should be %v, but is %v in metric\n", mode, *modeInMetric)
			return false, nil
		}
		return true, nil
	})
}

func checkSTSStyle(oc *CLI, mode string) bool {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", CloudCredentialsSecretName, "-n", OpenShiftIngressOperatorNamespace, "-o=jsonpath={.data.credentials}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(output).NotTo(o.BeEmpty())
	credentials, err := base64.StdEncoding.DecodeString(output)
	o.Expect(err).NotTo(o.HaveOccurred())
	credConfig := strings.Split(string(credentials), "\n")
	//Credentials items are in different order for self-managed OCP and ROSA, so sort firstly
	sort.SliceStable(credConfig, func(i, j int) bool {
		return strings.Compare(credConfig[i], credConfig[j]) < 0
	})
	if mode == "manualpodidentity" {
		return strings.Contains(credConfig[0], "[default]") && strings.Contains(credConfig[1], "role_arn") && strings.Contains(credConfig[2], "sts_regional_endpoints") && strings.Contains(credConfig[3], "web_identity_token_file")
	}
	return strings.Contains(credConfig[0], "[default]") && strings.Contains(credConfig[1], "aws_access_key_id") && strings.Contains(credConfig[2], "aws_secret_access_key")
}

func patchResourceAsAdmin(oc *CLI, ns, resource, rsname, patch string) {
	err := oc.AsAdmin().WithoutNamespace().Run("patch").Args(resource, rsname, "--type=json", "-p", patch, "-n", ns).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

func (cr *credentialsRequest) create(oc *CLI) {
	applyNsResourceFromTemplate(oc, DefaultNamespace, "--ignore-unknown-parameters=true", "-f", cr.template, "-p", "NAME="+cr.name, "NAMESPACE="+cr.namespace, "PROVIDER="+cr.provider)
}

// Check if CCO conditions are healthy
func checkCCOHealth(oc *CLI, mode string) {
	availableStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "cloud-credential", `-o=jsonpath={.status.conditions[?(@.type=="Available")].status}`).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(availableStatus).To(o.Equal("True"))
	degradedStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "cloud-credential", `-o=jsonpath={.status.conditions[?(@.type=="Degraded")].status}`).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(degradedStatus).To(o.Equal("False"))
	var progressingStatus string
	err = wait.Poll(5*time.Second, 2*time.Minute, func() (bool, error) {
		progressingStatus, err = oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "cloud-credential", `-o=jsonpath={.status.conditions[?(@.type=="Progressing")].status}`).Output()
		if err != nil {
			return false, err
		}
		return progressingStatus == "False", nil
	})
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(progressingStatus).To(o.Equal("False"))
	upgradeableStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "cloud-credential", `-o=jsonpath={.status.conditions[?(@.type=="Upgradeable")].status}`).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	//when cco mode is manual or manual+sts, upgradeableStatus is "False" due to MissingUpgradeableAnnotation
	if mode == "manual" || mode == "manualpodidentity" {
		o.Expect(upgradeableStatus).To(o.Equal("False"))
		upgradeableReason, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "cloud-credential", `-o=jsonpath={.status.conditions[?(@.type=="Upgradeable")].reason}`).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(upgradeableReason).To(o.Equal("MissingUpgradeableAnnotation"))
	} else {
		o.Expect(upgradeableStatus).To(o.Equal("True"))
	}
}

// check webhook pod securityContext
func checkWebhookSecurityContext(oc *CLI, podnum int) {
	webHookPodName := make([]string, podnum)
	for i := 0; i < len(webHookPodName); i++ {
		var err error
		webHookPod, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-l", "app=pod-identity-webhook", "-n", DefaultNamespace, "-o=jsonpath={.items[*].metadata.name}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		webHookPodName = strings.Split(strings.TrimSpace(webHookPod), " ")
		o.Expect(len(webHookPodName)).To(o.BeNumerically(">", 0))
		logf("webHookPodName is %s\n", webHookPodName[i])
		allowPrivilegeEscalation, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", webHookPodName[i], "-n", DefaultNamespace, "-o=jsonpath={.spec.containers[*].securityContext.allowPrivilegeEscalation}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(allowPrivilegeEscalation).To(o.Equal("false"))
		drop, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", webHookPodName[i], "-n", DefaultNamespace, "-o=jsonpath={.spec.containers[*].securityContext.capabilities.drop}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		dropAllCount := strings.Count(drop, "ALL")
		o.Expect(dropAllCount).To(o.Equal(1))
		runAsNonRoot, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", webHookPodName[i], "-n", DefaultNamespace, "-o=jsonpath={.spec.securityContext.runAsNonRoot}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(runAsNonRoot).To(o.Equal("true"))
		seccompProfileType, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", webHookPodName[i], "-n", DefaultNamespace, "-o=jsonpath={.spec.securityContext.seccompProfile.type}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(seccompProfileType).To(o.Equal("RuntimeDefault"))
	}
}
