package podidentity

import (
	"context"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	awsutils "github.com/openshift/cloud-credential-operator/pkg/operator/utils/aws"
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

func (a AwsPodIdentity) ApplyDeploymentSubstitutionsInPlace(deployment *appsv1.Deployment, client client.Client, logger log.FieldLogger) error {
	region, err := awsutils.LoadInfrastructureRegion(client, logger)
	if err != nil {
		return err
	}

	// adds --aws-default-region=${region} only when aws region is available from Infra object
	// default falls back to us-east-1 (which was also formerely the global STS endpoint)
	if region != "" {
		for i := range deployment.Spec.Template.Spec.Containers[0].Command {
			if strings.Contains(deployment.Spec.Template.Spec.Containers[0].Command[i], "--aws-default-region") {
				deployment.Spec.Template.Spec.Containers[0].Command[i] = fmt.Sprintf("--aws-default-region=%s", region)
			}
		}
	}

	return nil
}
