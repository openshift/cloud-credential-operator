package common

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	o "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/wait"
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

var (
	IsExternalOIDCClusterFlag = ""
	IsKubernetesClusterFlag   = ""
)

func getRootSecretName(oc *CLI) (string, error) {
	var rootSecretName string

	iaasPlatform, err := GetIaasPlatform(oc)
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

func GetIaasPlatform(oc *CLI) (string, error) {
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

func GetCloudCredentialMode(oc *CLI) (string, error) {
	var (
		mode           string
		iaasPlatform   string
		rootSecretName string
		err            error
	)
	iaasPlatform, err = GetIaasPlatform(oc)
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
		if IsSTSCluster(oc) {
			mode = "manualpodidentity"
			return mode, nil
		}
	}
	if iaasPlatform == "azure" {
		if IsWorkloadIdentityCluster(oc) {
			mode = "manualpodidentity"
			return mode, nil
		}
	}
	mode = "manual"
	return mode, nil
}

func CheckModeInMetric(oc *CLI, token string, mode string) error {
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

// DuplicateFileToPath copies the file at srcPath to destPath.
func DuplicateFileToPath(srcPath string, destPath string) {
	var destFile, srcFile *os.File
	var err error

	srcFile, err = os.Open(srcPath)
	o.Expect(err).NotTo(o.HaveOccurred())
	defer func() {
		o.Expect(srcFile.Close()).NotTo(o.HaveOccurred())
	}()

	// If the file already exists, it is truncated. If the file does not exist, it is created with mode 0666.
	destFile, err = os.Create(destPath)
	o.Expect(err).NotTo(o.HaveOccurred())
	defer func() {
		o.Expect(destFile.Close()).NotTo(o.HaveOccurred())
	}()

	_, err = io.Copy(destFile, srcFile)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(destFile.Sync()).NotTo(o.HaveOccurred())
}

// DuplicateFileToTemp creates a temporary duplicate of the file at srcPath using destPattern for naming,
// returning the path of the duplicate.
func DuplicateFileToTemp(srcPath string, destPrefix string) string {
	destFile, err := os.CreateTemp(os.TempDir(), destPrefix)
	o.Expect(err).NotTo(o.HaveOccurred(), "Failed to create temporary file")
	o.Expect(destFile.Close()).NotTo(o.HaveOccurred(), "Failed to close temporary file")

	destPath := destFile.Name()
	DuplicateFileToPath(srcPath, destPath)
	return destPath
}
