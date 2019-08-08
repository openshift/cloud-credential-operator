package azure_test

import (
	"context"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	configv1 "github.com/openshift/api/config/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/openshift/cloud-credential-operator/pkg/apis"

	ccazure "github.com/openshift/cloud-credential-operator/pkg/azure"
	. "github.com/openshift/cloud-credential-operator/pkg/controller/secretannotator/azure"
	annotatorconst "github.com/openshift/cloud-credential-operator/pkg/controller/secretannotator/constants"
)

const (
	testNamespace = "test"
)

func TestAzureSecretAnnotatorReconcile(t *testing.T) {
	apis.AddToScheme(scheme.Scheme)
	configv1.Install(scheme.Scheme)
	existingSecret := []runtime.Object{&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "azure-credentials",
			Namespace: testNamespace,
		},
		Data: map[string][]byte{
			ccazure.AzureClientID:       []byte("AZURE_CLIENT_ID"),
			ccazure.AzureClientSecret:   []byte("AZURE_CLIENT_SECRET"),
			ccazure.AzureRegion:         []byte("AZURE_REGION"),
			ccazure.AzureResourceGroup:  []byte("AZURE_RESOURCEGROUP"),
			ccazure.AzureResourcePrefix: []byte("AZURE_RESOURCE_PREFIX"),
			ccazure.AzureSubscriptionID: []byte("AZURE_SUBSCRIPTION_ID"),
			ccazure.AzureTenantID:       []byte("AZURE_TENANT_ID"),
		},
	}}

	fakeClient := fake.NewFakeClient(existingSecret...)

	rcc := &ReconcileCloudCredSecret{
		Client: fakeClient,
		Logger: log.WithField("controller", "testController"),
	}

	_, err := rcc.Reconcile(reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "azure-credentials",
			Namespace: testNamespace,
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	secret := &corev1.Secret{}
	fakeClient.Get(context.TODO(), client.ObjectKey{Name: "azure-credentials", Namespace: testNamespace}, secret)
	validateAnnotation(t, secret, annotatorconst.MintAnnotation)
}

func validateAnnotation(t *testing.T, secret *corev1.Secret, annotation string) {
	if secret.ObjectMeta.Annotations == nil {
		t.Errorf("unexpected empty annotations on secret")
	}
	if _, ok := secret.ObjectMeta.Annotations[annotatorconst.AnnotationKey]; !ok {
		t.Errorf("missing annotation")
	}

	assert.Exactly(t, annotation, secret.ObjectMeta.Annotations[annotatorconst.AnnotationKey])
}
