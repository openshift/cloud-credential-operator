package azure_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	operatorv1 "github.com/openshift/api/operator/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ccazure "github.com/openshift/cloud-credential-operator/pkg/azure"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	. "github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/azure"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
)

const (
	TestClientID       = "SomeClientID"
	TestClientSecret   = "SomeClientSecret"
	TestTenantID       = "SomeTenantID"
	TestRegion         = "SomeRegion"
	TestResourceGroup  = "SomeResourceGroup"
	TestAzurePrefix    = "SomeAzurePrefix"
	TestSubscriptionID = "SomeSubscriptionID"
	TestSecretName     = "azure-credentials"
	TestNamespace      = "test"
)

func TestAzureSecretAnnotatorReconcile(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	tests := []struct {
		name               string
		operatorConfig     *operatorv1.CloudCredential
		expectedAnnotation operatorv1.CloudCredentialsMode
	}{
		{
			name:               "default operatorconfig",
			operatorConfig:     testOperatorConfig(operatorv1.CloudCredentialsModeDefault),
			expectedAnnotation: constants.PassthroughAnnotation,
		},
		{
			name:               "explicit passthrough",
			operatorConfig:     testOperatorConfig(operatorv1.CloudCredentialsModePassthrough),
			expectedAnnotation: constants.PassthroughAnnotation,
		},
		{
			name:               "manual mode",
			operatorConfig:     testOperatorConfig(operatorv1.CloudCredentialsModeManual),
			expectedAnnotation: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			credsSecret := getInputSecret()

			fakeClient := fake.NewClientBuilder().WithObjects(test.operatorConfig).Build()
			fakeRootCredClient := fake.NewClientBuilder().WithRuntimeObjects(credsSecret).Build()

			rcc := &ReconcileCloudCredSecret{
				Client:         fakeClient,
				RootCredClient: fakeRootCredClient,
				Logger:         log.WithField("controller", "testSecretAnnotatorController"),
			}

			_, err := rcc.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      TestSecretName,
					Namespace: TestNamespace,
				},
			})

			require.NoError(t, err, "unexpected error in secret annotator controller")

			secret := &corev1.Secret{}
			err = fakeRootCredClient.Get(context.TODO(), client.ObjectKey{Name: TestSecretName, Namespace: TestNamespace}, secret)
			require.NoError(t, err, "error fetching object from fake client")

			assert.Equal(t, string(test.expectedAnnotation), string(secret.ObjectMeta.Annotations[constants.AnnotationKey]))
		})
	}
}

func getInputSecret() *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        TestSecretName,
			Namespace:   TestNamespace,
			Annotations: map[string]string{},
		},
		Data: map[string][]byte{
			ccazure.AzureClientID:       []byte(TestClientID),
			ccazure.AzureClientSecret:   []byte(TestClientSecret),
			ccazure.AzureRegion:         []byte(TestRegion),
			ccazure.AzureResourceGroup:  []byte(TestResourceGroup),
			ccazure.AzureResourcePrefix: []byte(TestAzurePrefix),
			ccazure.AzureSubscriptionID: []byte(TestSubscriptionID),
			ccazure.AzureTenantID:       []byte(TestTenantID),
		},
	}

}

func testOperatorConfig(mode operatorv1.CloudCredentialsMode) *operatorv1.CloudCredential {
	conf := &operatorv1.CloudCredential{
		ObjectMeta: metav1.ObjectMeta{
			Name: constants.CloudCredOperatorConfig,
		},
		Spec: operatorv1.CloudCredentialSpec{
			CredentialsMode: mode,
		},
	}

	return conf
}
