package extended

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	o "github.com/onsi/gomega"
	exutil "github.com/openshift/origin/test/extended/util"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

const (
	ccoNs                    = "openshift-cloud-credential-operator"
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
}

type azureCredential struct {
	key   string
	value string
}

type gcpCredential struct {
	key   string
	value string
}

type OcpClientVerb = string

func doOcpReq(oc *exutil.CLI, verb OcpClientVerb, notEmpty bool, args ...string) string {
	e2e.Logf("running command : oc %s %s", string(verb), strings.Join(args, " "))
	res, err := oc.AsAdmin().WithoutNamespace().Run(string(verb)).Args(args...).Output()
	o.Expect(err).ShouldNot(o.HaveOccurred())
	if notEmpty {
		o.Expect(res).ShouldNot(o.BeEmpty())
	}
	return res
}

func getCloudCredentialMode(oc *exutil.CLI) (string, error) {
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
		modeInSecretAnnotation, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", rootSecretName, "-n=kube-system", "-o=jsonpath={.metadata.annotations.cloudcredential\\.openshift\\.io/mode}").Output()
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
		if compat_otp.IsSTSCluster(oc) {
			mode = "manualpodidentity"
			return mode, nil
		}
	}
	if iaasPlatform == "azure" {
		if compat_otp.IsWorkloadIdentityCluster(oc) {
			mode = "manualpodidentity"
			return mode, nil
		}
	}
	mode = "manual"
	return mode, nil
}

func getRootSecretName(oc *exutil.CLI) (string, error) {
	var rootSecretName string

	iaasPlatform, err := getIaasPlatform(oc)
	if err != nil {
		return "", err
	}
	switch iaasPlatform {
	case "aws":
		rootSecretName = "aws-creds"
	case "gcp":
		rootSecretName = "gcp-credentials"
	case "azure":
		rootSecretName = "azure-credentials"
	case "vsphere":
		rootSecretName = "vsphere-creds"
	case "openstack":
		rootSecretName = "openstack-credentials"
	case "ovirt":
		rootSecretName = "ovirt-credentials"
	default:
		e2e.Logf("Unsupported platform: %v", iaasPlatform)
		return "", nil

	}
	return rootSecretName, nil
}

func getIaasPlatform(oc *exutil.CLI) (string, error) {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("infrastructure", "cluster", "-o=jsonpath={.status.platformStatus.type}").Output()
	if err != nil {
		return "", err
	}
	iaasPlatform := strings.ToLower(output)

	if iaasPlatform == "external" {
		externalPlatformNameOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("infrastructure", "cluster", "-o=jsonpath={.spec.platformSpec.external.platformName}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		iaasPlatform = strings.ToLower(externalPlatformNameOutput)
	}

	return iaasPlatform, nil
}

func checkModeInMetric(oc *exutil.CLI, token string, mode string) error {
	var (
		data         prometheusQueryResult
		modeInMetric string
	)
	return wait.Poll(10*time.Second, 3*time.Minute, func() (bool, error) {
		msg, _, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", "openshift-monitoring", "prometheus-k8s-0", "-c", "prometheus", "--", "curl", "-k", "-H", fmt.Sprintf("Authorization: Bearer %v", token), "https://prometheus-k8s.openshift-monitoring.svc:9091/api/v1/query?query=cco_credentials_mode").Outputs()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(msg).NotTo(o.BeEmpty())
		json.Unmarshal([]byte(msg), &data)
		modeInMetric = data.Data.Result[0].Metric.Mode
		e2e.Logf("cco mode in metric is %v", modeInMetric)
		if modeInMetric != mode {
			e2e.Logf("cco mode should be %v, but is %v in metric", mode, modeInMetric)
			return false, nil
		}
		return true, nil
	})
}

func checkSTSStyle(oc *exutil.CLI, mode string) bool {
	output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("secret", "cloud-credentials", "-n", "openshift-ingress-operator", "-o=jsonpath={.data.credentials}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(output).NotTo(o.BeEmpty())
	credentials, _ := base64.StdEncoding.DecodeString(output)
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

func patchResourceAsAdmin(oc *exutil.CLI, ns, resource, rsname, patch string) {
	err := oc.AsAdmin().WithoutNamespace().Run("patch").Args(resource, rsname, "--type=json", "-p", patch, "-n", ns).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

func (cr *credentialsRequest) create(oc *exutil.CLI) {
	crYAML := `apiVersion: cloudcredential.openshift.io/v1
kind: CredentialsRequest
metadata:
  name: ` + cr.name + `
  namespace: openshift-cloud-credential-operator
spec:
  secretRef:
    name: ` + cr.name + `
    namespace: ` + cr.namespace + `
  providerSpec:
    apiVersion: cloudcredential.openshift.io/v1
    kind: ` + cr.provider + `
    statementEntries:
    - action:
      - iam:GetUser
      - iam:GetUserPolicy
      - iam:ListAccessKeys
      effect: Allow
      resource: '*'
`
	err := oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", "-").InputString(crYAML).Execute()
	o.Expect(err).NotTo(o.HaveOccurred())
}

// Check if CCO conditions are health
func checkCCOHealth(oc *exutil.CLI, mode string) {
	availableStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "cloud-credential", `-o=jsonpath={.status.conditions[?(@.type=="Available")].status}`).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(availableStatus).To(o.Equal("True"))
	degradedStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "cloud-credential", `-o=jsonpath={.status.conditions[?(@.type=="Degraded")].status}`).Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(degradedStatus).To(o.Equal("False"))
	progressingStatus, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "cloud-credential", `-o=jsonpath={.status.conditions[?(@.type=="Progressing")].status}`).Output()
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
func checkWebhookSecurityContext(oc *exutil.CLI, podnum int) {
	webHookPodName := make([]string, podnum)
	for i := 0; i < len(webHookPodName); i++ {
		var err error
		webHookPod, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-l", "app=pod-identity-webhook", "-n", "openshift-cloud-credential-operator", "-o=jsonpath={.items[*].metadata.name}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		webHookPodName = strings.Split(strings.TrimSpace(webHookPod), " ")
		o.Expect(len(webHookPodName)).To(o.BeNumerically(">", 0))
		e2e.Logf("webHookPodName is %s ", webHookPodName[i])
		allowPrivilegeEscalation, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", webHookPodName[i], "-n", "openshift-cloud-credential-operator", "-o=jsonpath={.spec.containers[*].securityContext.allowPrivilegeEscalation}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(allowPrivilegeEscalation).To(o.Equal("false"))
		drop, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", webHookPodName[i], "-n", "openshift-cloud-credential-operator", "-o=jsonpath={.spec.containers[*].securityContext.capabilities.drop}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		dropAllCount := strings.Count(drop, "ALL")
		o.Expect(dropAllCount).To(o.Equal(1))
		runAsNonRoot, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", webHookPodName[i], "-n", "openshift-cloud-credential-operator", "-o=jsonpath={.spec.securityContext.runAsNonRoot}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(runAsNonRoot).To(o.Equal("true"))
		seccompProfileType, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", webHookPodName[i], "-n", "openshift-cloud-credential-operator", "-o=jsonpath={.spec.securityContext.seccompProfile.type}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(seccompProfileType).To(o.Equal("RuntimeDefault"))
	}
}
