package podidentity

import (
	"context"
	"fmt"
	"os"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/crypto"
	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const gcpFolder = "v4.1.0/gcp-pod-identity-webhook"

type GcpPodIdentity struct {
}

func (a GcpPodIdentity) ShouldBeDeployed(ctx context.Context, clientSet kubernetes.Interface, namespace string) (bool, error) {
	return true, nil
}

func (a GcpPodIdentity) Deployment() string {
	return fmt.Sprintf("%s/deployment.yaml", gcpFolder)
}

func (a GcpPodIdentity) Webhook() string {
	return fmt.Sprintf("%s/mutatingwebhook.yaml", gcpFolder)
}

func (a GcpPodIdentity) GetImagePullSpec() string {
	return os.Getenv("GCP_POD_IDENTITY_WEBHOOK_IMAGE")
}

func (a GcpPodIdentity) Name() string {
	return "gcp"
}

func (a GcpPodIdentity) ApplyDeploymentSubstitutionsInPlace(deployment *appsv1.Deployment, client client.Client, logger log.FieldLogger, tlsProfile *configv1.TLSProfileSpec) error {

	if tlsProfile.MinTLSVersion != "" {
		deployment.Spec.Template.Spec.Containers[0].Command = append(deployment.Spec.Template.Spec.Containers[0].Command,
			fmt.Sprintf("--tls-min-version=%s", tlsProfile.MinTLSVersion))
	}
	if len(tlsProfile.Ciphers) > 0 {
		deployment.Spec.Template.Spec.Containers[0].Command = append(deployment.Spec.Template.Spec.Containers[0].Command,
			fmt.Sprintf("--tls-cipher-suites=%s", strings.Join(crypto.OpenSSLToIANACipherSuites(tlsProfile.Ciphers), ",")))
	}

	return nil
}
