package podidentity

import (
	"context"
	"fmt"
	"os"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	azureTenantIdKey = "azure_tenant_id"
	azureFolder      = "v4.1.0/azure-pod-identity-webhook"
)

type AzurePodIdentity struct {
}

func (a AzurePodIdentity) ShouldBeDeployed(ctx context.Context, clientSet kubernetes.Interface, namespace string) (bool, error) {
	secret, err := clientSet.CoreV1().Secrets(namespace).Get(ctx,
		"azure-credentials", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, ok := secret.Data[azureTenantIdKey]
	return ok, nil
}

func (a AzurePodIdentity) Deployment() string {
	return fmt.Sprintf("%s/deployment.yaml", azureFolder)
}

func (a AzurePodIdentity) Webhook() string {
	return fmt.Sprintf("%s/mutatingwebhook.yaml", azureFolder)
}

func (a AzurePodIdentity) GetImagePullSpec() string {
	return os.Getenv("AZURE_POD_IDENTITY_WEBHOOK_IMAGE")
}

func (a AzurePodIdentity) Name() string {
	return "azure"
}
