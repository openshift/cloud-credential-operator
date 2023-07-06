package podidentity

import (
	"os"

	"k8s.io/client-go/kubernetes"
)

type AwsPodIdentity struct {
}

func (a AwsPodIdentity) ShouldBeDeployed(clientSet kubernetes.Interface, namespace string) (bool, error) {
	return true, nil
}

func (a AwsPodIdentity) Deployment() string {
	return "v4.1.0/aws-pod-identity-webhook/deployment.yaml"
}

func (a AwsPodIdentity) GetImagePullSpec() string {
	return os.Getenv("AWS_POD_IDENTITY_WEBHOOK_IMAGE")
}
