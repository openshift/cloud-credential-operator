package podidentity

import (
	"context"
	"fmt"
	"os"

	"k8s.io/client-go/kubernetes"
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
