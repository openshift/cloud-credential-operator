package podidentity

import (
	"context"
	"fmt"
	"os"

	"k8s.io/client-go/kubernetes"
)

const awsFolder = "v4.1.0/aws-pod-identity-webhook"

type AwsPodIdentity struct {
}

func (a AwsPodIdentity) ShouldBeDeployed(ctx context.Context, clientSet kubernetes.Interface, namespace string) (bool, error) {
	return true, nil
}

func (a AwsPodIdentity) Deployment() string {
	return fmt.Sprintf("%s/deployment.yaml", awsFolder)
}

func (a AwsPodIdentity) Webhook() string {
	return fmt.Sprintf("%s/mutatingwebhook.yaml", awsFolder)
}

func (a AwsPodIdentity) GetImagePullSpec() string {
	return os.Getenv("AWS_POD_IDENTITY_WEBHOOK_IMAGE")
}

func (a AwsPodIdentity) Name() string {
	return "aws"
}
