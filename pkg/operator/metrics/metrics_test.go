package metrics

import (
	"fmt"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/azure"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
)

var (
	missingTargetNamespaceCond = credreqv1.CredentialsRequestCondition{
		Type:   credreqv1.MissingTargetNamespace,
		Status: corev1.ConditionTrue,
	}

	ignoredCond = credreqv1.CredentialsRequestCondition{
		Type:   credreqv1.Ignored,
		Status: corev1.ConditionTrue,
	}

	provisionFailedCond = credreqv1.CredentialsRequestCondition{
		Type:   credreqv1.CredentialsProvisionFailure,
		Status: corev1.ConditionTrue,
	}

	insufficientCredsCond = credreqv1.CredentialsRequestCondition{
		Type:   credreqv1.InsufficientCloudCredentials,
		Status: corev1.ConditionTrue,
	}

	staleCredsCond = credreqv1.CredentialsRequestCondition{
		Type:   credreqv1.StaleCredentials,
		Status: corev1.ConditionTrue,
	}

	azurePassthroughCredsTemplate = `azure_client_id: %s
azure_client_secret: %s
azure_region: %s
azure_resource_prefix: %s
azure_resourcegroup: %s
azure_subscription_id: %s
azure_tenant_id: %s`
)

func TestSecretGetter(t *testing.T) {
	err := configv1.Install(scheme.Scheme)
	assert.NoError(t, err, "error installing configv1 types to scheme")

	logger := log.WithField("controller", "metricscontrollertest")

	tests := []struct {
		name             string
		cloudCredsSecret *corev1.Secret
		clusterInfra     *configv1.Infrastructure
		validate         func(*testing.T, *corev1.Secret, error)
	}{
		{
			name:             "aws cloud creds exist",
			clusterInfra:     testClusterInfra("aws"),
			cloudCredsSecret: testCloudCredSecret(constants.AWSCloudCredSecretName, "anyAnnotation"),
			validate: func(t *testing.T, secret *corev1.Secret, err error) {
				assert.NoError(t, err, "unexpected error")
				assert.NotNil(t, secret, "secret should not be nil")
			},
		},
		{
			name:             "aws cloud creds missing",
			clusterInfra:     testClusterInfra("aws"),
			cloudCredsSecret: testCloudCredSecret("not-aws-creds", "anyAnnotation"),
			validate: func(t *testing.T, secret *corev1.Secret, err error) {
				notFound := errors.IsNotFound(err)
				assert.True(t, notFound)
			},
		},
		{
			name:             "gcp cloud creds exist",
			clusterInfra:     testClusterInfra("gcp"),
			cloudCredsSecret: testCloudCredSecret(constants.GCPCloudCredSecretName, "anyAnnotation"),
			validate: func(t *testing.T, secret *corev1.Secret, err error) {
				assert.NoError(t, err, "unexpected error")
				assert.NotNil(t, secret, "secret should not be nil")
			},
		},
		{
			name:             "infra get error",
			clusterInfra:     &configv1.Infrastructure{},
			cloudCredsSecret: &corev1.Secret{},
			validate: func(t *testing.T, secret *corev1.Secret, err error) {
				assert.Error(t, err, "expected error when infra is missing")
			},
		},
		{
			name: "unsupported cloud",
			clusterInfra: &configv1.Infrastructure{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				// no platformtype set
			},
			cloudCredsSecret: &corev1.Secret{},
			validate: func(t *testing.T, secret *corev1.Secret, err error) {
				assert.Nil(t, secret)
				assert.Nil(t, err)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithRuntimeObjects(test.clusterInfra).Build()
			fakeRootClient := fake.NewClientBuilder().WithRuntimeObjects(test.cloudCredsSecret).Build()
			calc := &Calculator{
				Client:     fakeClient,
				rootClient: fakeRootClient,
				log:        logger,
			}

			secret, err := calc.getCloudSecret()
			test.validate(t, secret, err)
		})
	}

}

func TestCredentialsRequests(t *testing.T) {
	logger := log.WithField("controller", "metricscontrollertest")

	tests := []struct {
		name            string
		existingObjects []runtime.Object
		credReqs        []credreqv1.CredentialsRequest
		ccoDisabled     bool
		validate        func(*testing.T, *credRequestAccumulator)
	}{
		{
			name: "mixed credentials",
			credReqs: []credreqv1.CredentialsRequest{
				// just a regular cred request
				testAWSCredRequest("aregular"),
				// missing namespace condition
				testCredReqWithConditions(testAWSCredRequest("amissingnamespace"), []credreqv1.CredentialsRequestCondition{missingTargetNamespaceCond}),
				// provision failed condition
				testCredReqWithConditions(testAWSCredRequest("aprovisionfailed"), []credreqv1.CredentialsRequestCondition{provisionFailedCond}),
				// provision failed false condition
				func() credreqv1.CredentialsRequest {
					cr := testCredReqWithConditions(testAWSCredRequest("aprovisionnotfailed"), []credreqv1.CredentialsRequestCondition{provisionFailedCond})
					cr.Status.Conditions[0].Status = corev1.ConditionFalse
					return cr
				}(),
				// insufficient cloud creds condition
				testCredReqWithConditions(testAWSCredRequest("ainsufficientcreds"), []credreqv1.CredentialsRequestCondition{insufficientCredsCond}),
				// stale creds condition
				testCredReqWithConditions(testAWSCredRequest("astalecreds"), []credreqv1.CredentialsRequestCondition{staleCredsCond}),

				// regular GCP credreq
				testGCPCredRequest("gregular"),
				// GCP credreq with condition set
				testCredReqWithConditions(testGCPCredRequest("gignored"), []credreqv1.CredentialsRequestCondition{ignoredCond}),
				//testClusterInfra("aws"),
			},
			validate: func(t *testing.T, accumulator *credRequestAccumulator) {
				// total cred requests
				assert.Equal(t, 6, accumulator.crTotals["aws"])
				assert.Equal(t, 2, accumulator.crTotals["gcp"])

				// conditions
				assert.Equal(t, 1, accumulator.crConditions[credreqv1.MissingTargetNamespace])
				assert.Equal(t, 1, accumulator.crConditions[credreqv1.CredentialsProvisionFailure])
				assert.Equal(t, 1, accumulator.crConditions[credreqv1.Ignored])
				assert.Equal(t, 1, accumulator.crConditions[credreqv1.InsufficientCloudCredentials])
				assert.Equal(t, 0, accumulator.crConditions[credreqv1.StaleCredentials])
			},
		},
		{
			name:        "cco disabled report no conditions",
			ccoDisabled: true,
			credReqs: []credreqv1.CredentialsRequest{
				// missing namespace condition
				testCredReqWithConditions(testAWSCredRequest("amissingnamespace"), []credreqv1.CredentialsRequestCondition{missingTargetNamespaceCond}),
				// provision failed condition
				testCredReqWithConditions(testAWSCredRequest("aprovisionfailed"), []credreqv1.CredentialsRequestCondition{provisionFailedCond}),
				// insufficient cloud creds condition
				testCredReqWithConditions(testAWSCredRequest("ainsufficientcreds"), []credreqv1.CredentialsRequestCondition{insufficientCredsCond}),
				// stale creds condition
				testCredReqWithConditions(testAWSCredRequest("astalecreds"), []credreqv1.CredentialsRequestCondition{staleCredsCond}),

				// GCP credreq with condition set
				testCredReqWithConditions(testGCPCredRequest("gignored"), []credreqv1.CredentialsRequestCondition{ignoredCond}),
			},
			validate: func(t *testing.T, accumulator *credRequestAccumulator) {
				// total cred requests
				assert.Equal(t, 4, accumulator.crTotals["aws"])
				assert.Equal(t, 1, accumulator.crTotals["gcp"])

				// failure conditions should all be zero as CCO is disabled
				for _, cond := range credreqv1.FailureConditionTypes {
					assert.Equal(t, 0, accumulator.crConditions[cond])
				}
				// stale conditions should be reported when cco is disabled
				assert.Equal(t, 1, accumulator.crConditions[credreqv1.StaleCredentials])
			},
		},
		{
			name:        "cco manual mode with AWS STS",
			ccoDisabled: true,
			existingObjects: []runtime.Object{
				testSecret("sts-namespace", "sts-name", map[string][]byte{
					"credentials": []byte("[default]\nweb_identity_token_file=/path/to/token"),
				}),
				testSecret("notsts-namespace", "notsts-name", map[string][]byte{
					"credentials": []byte("[default]\naws_access_key_id=AKSOMETHING\naws_secret_access_key=somesecretaccesskey"),
				}),
			},
			credReqs: []credreqv1.CredentialsRequest{
				testCredRequestWithSecretRef(testAWSCredRequest("stsstyle"), "sts-namespace", "sts-name"),
				testCredRequestWithSecretRef(testAWSCredRequest("notsts"), "notsts-namespace", "notsts-name"),
			},
			validate: func(t *testing.T, accumulator *credRequestAccumulator) {
				assert.Equal(t, 2, accumulator.crTotals["aws"])
				assert.Equal(t, 1, accumulator.podIdentityCredentials)
			},
		},
		{
			name:        "cco manual mode with Azure Workload Identity",
			ccoDisabled: true,
			existingObjects: []runtime.Object{
				testSecret("wi-namespace", "wi-name", map[string][]byte{
					azure.AzureFederatedTokenFile: []byte("/path/to/mounted/service/account/token"),
				}),
				testSecret("non-wi-namespace", "non-wi-name", map[string][]byte{
					"credentials": []byte(fmt.Sprintf(azurePassthroughCredsTemplate, "foo", "bar", "baz", "quux", "fred", "thud", "grault")),
				}),
			},
			credReqs: []credreqv1.CredentialsRequest{
				testCredRequestWithSecretRef(testAzureCredRequest("wi-style"), "wi-namespace", "wi-name"),
				testCredRequestWithSecretRef(testAzureCredRequest("non-wi-style"), "non-wi-namespace", "non-wi-name"),
			},
			validate: func(t *testing.T, accumulator *credRequestAccumulator) {
				assert.Equal(t, 2, accumulator.crTotals["azure"])
				assert.Equal(t, 1, accumulator.podIdentityCredentials)
			},
		},
		{
			name:        "cco manual mode with GCP Workload Identity Federation",
			ccoDisabled: true,
			existingObjects: []runtime.Object{
				testSecret("wif-namespace", "wif-name", map[string][]byte{
					"service_account.json": []byte(`{"type": "external_account", "audience": "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider"}`),
				}),
				testSecret("non-wif-namespace", "non-wif-name", map[string][]byte{
					"service_account.json": []byte(`{"type": "service_account", "project_id": "my-project"}`),
				}),
			},
			credReqs: []credreqv1.CredentialsRequest{
				testCredRequestWithSecretRef(testGCPCredRequest("wif-style"), "wif-namespace", "wif-name"),
				testCredRequestWithSecretRef(testGCPCredRequest("non-wif-style"), "non-wif-namespace", "non-wif-name"),
			},
			validate: func(t *testing.T, accumulator *credRequestAccumulator) {
				assert.Equal(t, 2, accumulator.crTotals["gcp"])
				assert.Equal(t, 1, accumulator.podIdentityCredentials)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithRuntimeObjects(test.existingObjects...).Build()

			accumulator := newAccumulator(fakeClient, logger)

			for _, cr := range test.credReqs {
				accumulator.processCR(&cr, test.ccoDisabled)
			}

			test.validate(t, accumulator)
		})
	}

}

func TestCredentialsMode(t *testing.T) {
	configv1.AddToScheme(scheme.Scheme)
	credreqv1.AddToScheme(scheme.Scheme)

	logger := log.WithField("controller", "metricscontrollertest")

	tests := []struct {
		name                        string
		cloudCredSecret             *corev1.Secret
		secretMissing               bool
		ccoMode                     operatorv1.CloudCredentialsMode
		foundPodIdentityCredentials bool
		expectedMode                constants.CredentialsMode
	}{
		{
			name:            "mint mode",
			cloudCredSecret: testCloudCredSecret(constants.AWSCloudCredSecretName, constants.MintAnnotation),
			expectedMode:    constants.ModeMint,
		},
		{
			name:            "passthrough mode",
			cloudCredSecret: testCloudCredSecret(constants.AWSCloudCredSecretName, constants.PassthroughAnnotation),
			expectedMode:    constants.ModePassthrough,
		},
		{
			name:            "degraded mode",
			cloudCredSecret: testCloudCredSecret(constants.AWSCloudCredSecretName, constants.InsufficientAnnotation),
			expectedMode:    constants.ModeDegraded,
		},
		{
			name:          "manual mode",
			ccoMode:       operatorv1.CloudCredentialsModeManual,
			secretMissing: true,
			expectedMode:  constants.ModeManual,
		},
		{
			name:          "cred removed mode",
			secretMissing: true,
			expectedMode:  constants.ModeCredsRemoved,
		},
		{
			name:            "unexpected secret annotation",
			cloudCredSecret: testCloudCredSecret(constants.AWSCloudCredSecretName, "unexpectedAnnotation"),
			expectedMode:    constants.ModeUnknown,
		},
		{
			name:            "unannotated secret",
			cloudCredSecret: testCloudCredSecret(constants.AWSCloudCredSecretName, ""),
			expectedMode:    constants.ModeUnknown,
		},
		{
			name:                        "sts secret found",
			ccoMode:                     operatorv1.CloudCredentialsModeManual,
			foundPodIdentityCredentials: true,
			expectedMode:                constants.ModeManualPodIdentity,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			state := &clusterState{
				mode:                        test.ccoMode,
				rootSecret:                  test.cloudCredSecret,
				rootSecretNotFound:          test.secretMissing,
				foundPodIdentityCredentials: test.foundPodIdentityCredentials,
			}
			detectedMode := determineCredentialsMode(state, logger)
			assert.Equal(t, test.expectedMode, detectedMode)
		})
	}

}

func TestMetricsInitialization(t *testing.T) {
	logger := log.WithField("controller", "metricscontrollertest")

	accumulator := newAccumulator(nil, logger)

	// Assert that all possible conditions have explicit '0' values
	// after initializing the accumulator.
	for _, c := range credreqv1.FailureConditionTypes {
		assert.Zero(t, accumulator.crConditions[c])
	}

	for _, m := range constants.CredentialsModeList {
		assert.Zero(t, accumulator.crMode[m])
	}
}

func testSecret(namespace, name string, data map[string][]byte) *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
	}
	return secret
}
func testCredRequestWithSecretRef(cr credreqv1.CredentialsRequest, secretNamespace, secretName string) credreqv1.CredentialsRequest {
	cr.Spec.SecretRef = corev1.ObjectReference{
		Name:      secretName,
		Namespace: secretNamespace,
	}
	return cr
}

func testCredReqWithConditions(cr credreqv1.CredentialsRequest, conditions []credreqv1.CredentialsRequestCondition) credreqv1.CredentialsRequest {
	cr.Status.Conditions = conditions
	return cr
}

func testAWSCredRequest(name string) credreqv1.CredentialsRequest {
	cr := credreqv1.CredentialsRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-cloud-credential-operator",
		},
		Spec: credreqv1.CredentialsRequestSpec{},
	}

	awsProviderSpec, err := credreqv1.Codec.EncodeProviderSpec(
		&credreqv1.AWSProviderSpec{
			TypeMeta: metav1.TypeMeta{
				Kind: "AWSProviderSpec",
			},
		},
	)
	if err != nil {
		panic("failed to encode AWSProviderSpec for test")
	}
	cr.Spec.ProviderSpec = awsProviderSpec
	return cr
}

func testAzureCredRequest(name string) credreqv1.CredentialsRequest {
	cr := credreqv1.CredentialsRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "openshift-cloud-credential-operator",
		},
		Spec: credreqv1.CredentialsRequestSpec{},
	}

	azureProviderSpec, err := credreqv1.Codec.EncodeProviderSpec(
		&credreqv1.AzureProviderSpec{
			TypeMeta: metav1.TypeMeta{
				Kind: "AzureProviderSpec",
			},
		},
	)
	if err != nil {
		panic("failed to encode AzureProviderSpec for test")
	}
	cr.Spec.ProviderSpec = azureProviderSpec
	return cr
}

func testGCPCredRequest(name string) credreqv1.CredentialsRequest {
	gcpProviderSpec, err := credreqv1.Codec.EncodeProviderSpec(
		&credreqv1.GCPProviderSpec{
			TypeMeta: metav1.TypeMeta{
				Kind: "GCPProviderSpec",
			},
		},
	)
	if err != nil {
		panic("failed to encode GCPProviderSpec for test")
	}
	cr := testAWSCredRequest(name)
	cr.Spec.ProviderSpec = gcpProviderSpec

	return cr
}

func testCloudCredSecret(secretName, annotation string) *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: constants.CloudCredSecretNamespace,
			Annotations: map[string]string{
				constants.AnnotationKey: annotation,
			},
		},
	}

	return secret
}

func testClusterInfra(cloud string) *configv1.Infrastructure {
	infra := &configv1.Infrastructure{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster",
		},
		Status: configv1.InfrastructureStatus{},
	}
	switch cloud {
	case "aws":
		infra.Status.Platform = configv1.AWSPlatformType
	case "azure":
		infra.Status.Platform = configv1.AzurePlatformType
	case "gcp":
		infra.Status.Platform = configv1.GCPPlatformType
	default:
		panic("unsupported cloud for creating test infrastructure object")
	}

	return infra
}
