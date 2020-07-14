package azure_test

import (
	"context"
	"testing"

	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	configv1 "github.com/openshift/api/config/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ccazure "github.com/openshift/cloud-credential-operator/pkg/azure"
	. "github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/azure"
	"github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/azure/mock"
	"github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/constants"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
)

const (
	TestResource                = "SomeResource"
	TestClientID                = "SomeClientID"
	TestClientSecret            = "SomeClientSecret"
	TestTenantID                = "SomeTenantID"
	TestRegion                  = "SomeRegion"
	TestResourceGroup           = "SomeResourceGroup"
	TestAzurePrefix             = "SomeAzurePrefix"
	TestSubscriptionID          = "SomeSubscriptionID"
	TestSecretName              = "azure-credentials"
	TestNamespace               = "test"
	TestActiveDirectoryEndpoint = "https://login.test.com/"
)

var (
	testOAuthConfig, _ = adal.NewOAuthConfig(TestActiveDirectoryEndpoint, TestTenantID)
	TestOAuthConfig    = *testOAuthConfig
)

func TestAzureSecretAnnotatorReconcile(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	tests := []struct {
		name  string
		wants func(*corev1.Secret)
		roles []string
	}{
		{
			name: "mint mode",
			wants: func(s *corev1.Secret) {
				s.Annotations[constants.AnnotationKey] = constants.MintAnnotation
			},
			roles: []string{"Application.ReadWrite.OwnedBy"},
		},
		{
			name: "passthrough mode",
			wants: func(s *corev1.Secret) {
				s.Annotations[constants.AnnotationKey] = constants.PassthroughAnnotation
			},
			roles: []string{"Application.ReadWrite"},
		},
		{
			name: "invalid credentials",
			wants: func(s *corev1.Secret) {
				s.Annotations[constants.AnnotationKey] = constants.InsufficientAnnotation
			},
			roles: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := getInputSecret()
			fakeClient := fake.NewFakeClient(base)
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockAdalClient := mock.NewMockAdalService(mockCtrl)
			setupAdalMock(mockAdalClient.EXPECT(), test.roles)

			rcc := &ReconcileCloudCredSecret{
				Client: fakeClient,
				Logger: log.WithField("controller", "testController"),
				Adal:   mockAdalClient,
			}

			// error will end-up in InsufficientAnnotation on the secret
			rcc.Reconcile(reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      TestSecretName,
					Namespace: TestNamespace,
				},
			})

			secret := &corev1.Secret{}
			fakeClient.Get(context.TODO(), client.ObjectKey{Name: TestSecretName, Namespace: TestNamespace}, secret)
			secret.ObjectMeta.ResourceVersion = ""
			expected := getInputSecret()
			if test.wants != nil {
				test.wants(expected)
			}
			if !assert.Equal(t, expected, secret) {
				t.Errorf("%s: expected result:\n %v \ngot result:\n %v \n", test.name, expected, secret)
			}
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

func setupAdalMock(r *mock.MockAdalServiceMockRecorder, roles []string) {
	gomock.InOrder(
		// these methdods are extensivly tested in azure codebase
		r.NewOAuthConfig(gomock.Eq(azure.PublicCloud.ActiveDirectoryEndpoint), gomock.Eq(TestTenantID)).Return(&TestOAuthConfig, nil),
		r.NewServicePrincipalToken(gomock.Eq(TestOAuthConfig), gomock.Eq(TestClientID), gomock.Eq(TestClientSecret), gomock.Eq(azure.PublicCloud.GraphEndpoint)).Return(newServicePrincipalTokenManual(roles), nil),
	)
}

func newServicePrincipalTokenManual(roles []string) *adal.ServicePrincipalToken {
	token := newToken(roles)
	token.RefreshToken = "refreshtoken"
	spt, _ := adal.NewServicePrincipalTokenFromManualToken(TestOAuthConfig, TestClientID, TestClientSecret, token)
	return spt
}

func newToken(roles []string) adal.Token {
	token := adal.Token{
		ExpiresIn: "0",
		ExpiresOn: "0",
		NotBefore: "0",
	}

	mySigningKey := []byte("SigningKey")

	// Create the Claims
	if roles != nil {
		claims := &AzureClaim{
			Roles: roles,
		}
		t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		ss, _ := t.SignedString(mySigningKey)
		token.AccessToken = ss
	}
	return token
}
