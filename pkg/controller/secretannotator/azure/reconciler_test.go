package azure_test

import (
	"context"
	"reflect"
	"testing"

	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	configv1 "github.com/openshift/api/config/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/openshift/cloud-credential-operator/pkg/apis"

	ccazure "github.com/openshift/cloud-credential-operator/pkg/azure"
	. "github.com/openshift/cloud-credential-operator/pkg/controller/secretannotator/azure"
	"github.com/openshift/cloud-credential-operator/pkg/controller/secretannotator/constants"
)

const (
	testNamespace = "test"
)

func TestAzureSecretAnnotatorReconcile(t *testing.T) {
	apis.AddToScheme(scheme.Scheme)
	configv1.Install(scheme.Scheme)

	tests := []struct {
		name     string
		wants    func(*corev1.Secret)
		existing func(*corev1.Secret)
	}{
		{
			name: "don't change existing annotation",
			wants: func(s *corev1.Secret) {
				s.Annotations[constants.AnnotationKey] = constants.PassthroughAnnotation
			},
			existing: func(s *corev1.Secret) {
				s.Annotations[constants.AnnotationKey] = constants.PassthroughAnnotation
			},
		},
		{
			name: "add annotation",
			wants: func(s *corev1.Secret) {
				s.Annotations[constants.AnnotationKey] = constants.MintAnnotation
			},
		},
		{
			name: "no annotations",
			wants: func(s *corev1.Secret) {
				s.Annotations = map[string]string{
					constants.AnnotationKey: constants.MintAnnotation,
				}
			},
			existing: func(s *corev1.Secret) {
				s.Annotations = nil
			},
		},
		{
			name: "invalid annotation",
			wants: func(s *corev1.Secret) {
				s.Annotations[constants.AnnotationKey] = constants.MintAnnotation
			},
			existing: func(s *corev1.Secret) {
				s.Annotations[constants.AnnotationKey] = "invalid"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := getInputSecret()
			if test.existing != nil {
				test.existing(base)
			}
			fakeClient := fake.NewFakeClient(base)

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
			expected := getInputSecret()
			if test.wants != nil {
				test.wants(expected)
			}
			if !reflect.DeepEqual(secret, expected) {
				t.Errorf("%s: expected result:\n %v \ngot result:\n %v \n", test.name, expected, secret)
			}
		})
	}
}

func getInputSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "azure-credentials",
			Namespace: testNamespace,
			Annotations: map[string]string{
				"foo": "bar",
			},
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
	}

}
