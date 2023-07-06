package podidentity

import (
	"context"
	"os"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	azureTenantIdKey = "azure_tenant_id"
)

type AzurePodIdentity struct {
}

func (a AzurePodIdentity) ShouldBeDeployed(clientSet kubernetes.Interface, namespace string) (bool, error) {
	secret, err := clientSet.CoreV1().Secrets(namespace).Get(context.TODO(),
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
	return "v4.1.0/azure-pod-identity-webhook/deployment.yaml"
}

func (a AzurePodIdentity) GetImagePullSpec() string {
	return os.Getenv("AZURE_POD_IDENTITY_WEBHOOK_IMAGE")
}
