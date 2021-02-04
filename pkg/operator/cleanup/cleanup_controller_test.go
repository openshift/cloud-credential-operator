package cleanup

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	mockaws "github.com/openshift/cloud-credential-operator/pkg/aws/mock"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
)

const (
	testStaleCRGeneration      = 1
	testStaleCRName            = "openshift-component-a"
	testNamespace              = "openshift-cloud-credential-operator"
	testStaleSecretName        = "test-secret"
	testStaleSecretNamespace   = "myproject"
	testRootAWSAccessKeyID     = "rootaccesskey"
	testRootAWSSecretAccessKey = "rootsecretkey"
	testAWSAccessKeyID         = "FAKEAWSACCESSKEYID"
	testAWSSecretAccessKey     = "KEEPITSECRET"
	testInfraName              = "testcluster-abc123"
	testAWSUser                = "mycluster-test-aws-user"
	testClusterID              = "e415fe1c-f894-11e8-8eb2-f2801f1b9fd1"
)

type ExpectedCondition struct {
	conditionType minterv1.CredentialsRequestConditionType
	reason        string
	status        corev1.ConditionStatus
}

type ExpectedCOCondition struct {
	conditionType configv1.ClusterStatusConditionType
	reason        string
	status        corev1.ConditionStatus
}

func TestStaleCredentialsRequestReconcile(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	// Utility function to get the test credentials request from the fake client
	getCR := func(c client.Client) *minterv1.CredentialsRequest {
		cr := &minterv1.CredentialsRequest{}
		err := c.Get(context.TODO(), client.ObjectKey{Name: testStaleCRName, Namespace: testNamespace}, cr)
		if err == nil {
			return cr
		}
		return nil
	}

	tests := []struct {
		name               string
		existing           []runtime.Object
		expectErr          bool
		expectDeletion     bool
		mockRootAWSClient  func(mockCtrl *gomock.Controller) *mockaws.MockClient
		expectedConditions []ExpectedCondition
	}{
		{
			name: "cleanup stale credentials request",
			existing: []runtime.Object{
				testOperatorConfig(""),
				createTestNamespace(testNamespace),
				createTestNamespace(testStaleSecretNamespace),
				testStaleCredentialsRequest(t),
				testAWSCredsSecret("kube-system", "aws-creds", testRootAWSAccessKeyID, testRootAWSSecretAccessKey),
				testAWSCredsSecret(testStaleSecretNamespace, testStaleSecretName, testAWSAccessKeyID, testAWSSecretAccessKey),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			expectDeletion: true,
		},
		{
			name: "cleanup stale credentials request in a manual mode",
			existing: []runtime.Object{
				testOperatorConfig("Manual"),
				createTestNamespace(testNamespace),
				createTestNamespace(testStaleSecretNamespace),
				testStaleCredentialsRequest(t),
				testAWSCredsSecret(testStaleSecretNamespace, testStaleSecretName, testAWSAccessKeyID, testAWSSecretAccessKey),
				testClusterVersion(),
				testInfrastructure(testInfraName),
			},
			expectDeletion: false,
			expectedConditions: []ExpectedCondition{
				{
					conditionType: minterv1.StaleCredentials,
					reason:        "CredentialsNoLongerRequired",
					status:        corev1.ConditionTrue,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			fakeClient := fake.NewFakeClient(test.existing...)
			rscr := &ReconcileStaleCredentialsRequest{
				Client: fakeClient,
			}

			_, err := rscr.Reconcile(reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      testStaleCRName,
					Namespace: testNamespace,
				},
			})

			if err != nil && !test.expectErr {
				require.NoError(t, err, "Unexpected error: %v", err)
			}
			if err == nil && test.expectErr {
				t.Errorf("Expected error but got none")
			}

			cr := getCR(fakeClient)
			if test.expectDeletion {
				assert.Nil(t, cr, "expected credentials request to be deleted")
			} else {
				require.NotNil(t, cr, "expected credentials request to exist")
				for _, condition := range test.expectedConditions {
					foundCondition := utils.FindCredentialsRequestCondition(cr.Status.Conditions, condition.conditionType)
					require.NotNil(t, foundCondition, "unexpected unable to find condition")
					assert.Exactly(t, condition.status, foundCondition.Status)
					assert.Exactly(t, condition.reason, foundCondition.Reason)
				}
			}
		})
	}
}

func testAWSCredsSecret(namespace, name, accessKeyID, secretAccessKey string) *corev1.Secret {
	s := testLegacyAWSCredsSecret(namespace, name, accessKeyID, secretAccessKey)

	s.Data["credentials"] = []byte(fmt.Sprintf(`[default]
aws_access_key_id = %s
aws_secret_access_key = %s`, accessKeyID, secretAccessKey))

	return s
}

func testLegacyAWSCredsSecret(namespace, name, accessKeyID, secretAccessKey string) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				constants.AnnotationKey: constants.MintAnnotation,
			},
		},
		Data: map[string][]byte{
			"aws_access_key_id":     []byte(accessKeyID),
			"aws_secret_access_key": []byte(secretAccessKey),
		},
	}
	return s
}

func testInfrastructure(infraName string) *configv1.Infrastructure {
	return &configv1.Infrastructure{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Status: configv1.InfrastructureStatus{
			Platform:           configv1.AWSPlatformType,
			InfrastructureName: infraName,
			PlatformStatus: &configv1.PlatformStatus{
				AWS: &configv1.AWSPlatformStatus{
					Region: "test-region-2",
				},
			},
		},
	}
}

func testClusterVersion() *configv1.ClusterVersion {
	return &configv1.ClusterVersion{
		ObjectMeta: metav1.ObjectMeta{
			Name: "version",
		},
		Spec: configv1.ClusterVersionSpec{
			ClusterID: testClusterID,
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

func createTestNamespace(namespace string) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
}

func testStaleCredentialsRequest(t *testing.T) *minterv1.CredentialsRequest {
	cr := testPassthroughCredentialsRequest(t)

	codec, err := minterv1.NewCodec()
	if err != nil {
		t.Logf("error creating new codec: %v", err)
		t.FailNow()
		return nil
	}

	awsStatus, err := codec.EncodeProviderStatus(
		&minterv1.AWSProviderStatus{
			User: testAWSUser,
		})
	if err != nil {
		t.Logf("error encoding: %v", err)
		t.FailNow()
		return nil
	}

	cr.Status.ProviderStatus = awsStatus
	return cr
}

func testPassthroughCredentialsRequest(t *testing.T) *minterv1.CredentialsRequest {
	codec, err := minterv1.NewCodec()
	if err != nil {
		t.Logf("error creating new codec: %v", err)
		t.FailNow()
		return nil
	}
	awsProvSpec, err := codec.EncodeProviderSpec(
		&minterv1.AWSProviderSpec{
			TypeMeta: metav1.TypeMeta{
				Kind: "AWSProviderSpec",
			},
			StatementEntries: []minterv1.StatementEntry{
				{
					Effect: "Allow",
					Action: []string{
						"iam:GetUser",
						"iam:GetUserPolicy",
						"iam:ListAccessKeys",
					},
					Resource: "*",
				},
			},
		})
	if err != nil {
		t.Logf("error encoding: %v", err)
		t.FailNow()
		return nil
	}

	return &minterv1.CredentialsRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:        testStaleCRName,
			Namespace:   testNamespace,
			Finalizers:  []string{minterv1.FinalizerDeprovision},
			UID:         types.UID("1234"),
			Annotations: map[string]string{},
			Generation:  testStaleCRGeneration,
		},
		Spec: minterv1.CredentialsRequestSpec{
			SecretRef:    corev1.ObjectReference{Name: testStaleSecretName, Namespace: testStaleSecretNamespace},
			ProviderSpec: awsProvSpec,
		},
	}
}

func TestIsStaleCredentialsRequest(t *testing.T) {
	tests := []struct {
		name                               string
		existingStaleCredentialsRequest    []types.NamespacedName
		watchedCredentialsRequestName      string
		watchedCredentialsRequestNamespace string
		isStaleCredentialsRequest          bool
	}{
		{
			name: "is a stale credentials request",
			existingStaleCredentialsRequest: []types.NamespacedName{
				{
					Name:      "stale-credentials-request-name-1",
					Namespace: "stale-credentials-request-namespace-1",
				},
				{
					Name:      "stale-credentials-request-name-2",
					Namespace: "stale-credentials-request-namespace-2",
				},
			},
			watchedCredentialsRequestName:      "stale-credentials-request-name-1",
			watchedCredentialsRequestNamespace: "stale-credentials-request-namespace-1",
			isStaleCredentialsRequest:          true,
		},
		{
			name: "is not a stale credentials request",
			existingStaleCredentialsRequest: []types.NamespacedName{
				{
					Name:      "stale-credentials-request-name-1",
					Namespace: "stale-credentials-request-namespace-1",
				},
				{
					Name:      "stale-credentials-request-name-2",
					Namespace: "stale-credentials-request-namespace-2",
				},
			},
			watchedCredentialsRequestName:      "dummy-credentials-request-name-1",
			watchedCredentialsRequestNamespace: "dummy-credentials-request-namespace-1",
			isStaleCredentialsRequest:          false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			constants.StaleCredentialsRequests = test.existingStaleCredentialsRequest

			assert.Equal(t, test.isStaleCredentialsRequest, isStaleCredentialsRequest(test.watchedCredentialsRequestNamespace, test.watchedCredentialsRequestName))
		})
	}
}
