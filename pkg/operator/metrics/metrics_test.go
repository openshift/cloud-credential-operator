package metrics

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/constants"
)

var (
	codec *credreqv1.ProviderCodec

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
)

func TestCredentialsRequests(t *testing.T) {
	var err error
	codec, err = credreqv1.NewCodec()
	if err != nil {
		t.Fatalf("failed to create codec: %v", err)
	}

	logger := log.WithField("controller", "metricscontrollertest")

	tests := []struct {
		name        string
		credReqs    []credreqv1.CredentialsRequest
		ccoDisabled bool
		validate    func(*credRequestAccumulator, *testing.T)
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

				// regular GCP credreq
				testGCPCredRequest("gregular"),
				// GCP credreq with condition set
				testCredReqWithConditions(testGCPCredRequest("gignored"), []credreqv1.CredentialsRequestCondition{ignoredCond}),
			},
			validate: func(accumulator *credRequestAccumulator, t *testing.T) {
				// total cred requests
				assert.Equal(t, 5, accumulator.crTotals["aws"])
				assert.Equal(t, 2, accumulator.crTotals["gcp"])

				// conditions
				assert.Equal(t, 1, accumulator.crConditions[credreqv1.MissingTargetNamespace])
				assert.Equal(t, 1, accumulator.crConditions[credreqv1.CredentialsProvisionFailure])
				assert.Equal(t, 1, accumulator.crConditions[credreqv1.Ignored])
				assert.Equal(t, 1, accumulator.crConditions[credreqv1.InsufficientCloudCredentials])
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

				// GCP credreq with condition set
				testCredReqWithConditions(testGCPCredRequest("gignored"), []credreqv1.CredentialsRequestCondition{ignoredCond}),
			},
			validate: func(accumulator *credRequestAccumulator, t *testing.T) {
				// total cred requests
				assert.Equal(t, 3, accumulator.crTotals["aws"])
				assert.Equal(t, 1, accumulator.crTotals["gcp"])

				// failure conditions should all be zero as CCO is disabled
				for _, cond := range constants.FailureConditionTypes {
					assert.Equal(t, 0, accumulator.crConditions[cond])
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			accumulator := newAccumulator(logger)

			for _, cr := range test.credReqs {
				accumulator.processCR(&cr, test.ccoDisabled)
			}

			test.validate(accumulator, t)
		})
	}

}

func TestMetricsInitialization(t *testing.T) {
	logger := log.WithField("controller", "metricscontrollertest")

	accumulator := newAccumulator(logger)

	// Assert that all possible conditions have explicit '0' values
	// after initializing the accumulator.
	for _, c := range constants.FailureConditionTypes {
		assert.Zero(t, accumulator.crConditions[c])
	}
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

	awsProviderSpec, err := codec.EncodeProviderSpec(
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

func testGCPCredRequest(name string) credreqv1.CredentialsRequest {
	gcpProviderSpec, err := codec.EncodeProviderSpec(
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
