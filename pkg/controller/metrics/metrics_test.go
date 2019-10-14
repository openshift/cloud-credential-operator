package metrics

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
)

var (
	codec *credreqv1.ProviderCodec
)

func TestCredentialsRequests(t *testing.T) {
	var err error
	codec, err = credreqv1.NewCodec()
	if err != nil {
		t.Fatalf("failed to create codec: %v", err)
	}

	logger := log.WithField("controller", "metricscontrollertest")

	awsCredRequests := []credreqv1.CredentialsRequest{
		testAWSCredRequest("a1"),
	}

	gcpCredRequests := []credreqv1.CredentialsRequest{
		testGCPCredRequest("g1"),
	}

	credRequests := []credreqv1.CredentialsRequest{}
	credRequests = append(credRequests, awsCredRequests...)
	credRequests = append(credRequests, gcpCredRequests...)

	accumulator := newAccumulator(logger)

	for _, cr := range credRequests {
		accumulator.processCR(&cr)
	}

	assert.Equal(t, len(awsCredRequests), accumulator.crTotals["aws"])
	assert.Equal(t, len(gcpCredRequests), accumulator.crTotals["gcp"])
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
