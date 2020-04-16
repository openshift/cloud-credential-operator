package aws

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aws/aws-sdk-go/service/iam"

	configv1 "github.com/openshift/api/config/v1"

	ccaws "github.com/openshift/cloud-credential-operator/pkg/aws"
)

const (
	testInfraName = "test-cluster-abcde"
	testRegion    = "regionA"
	testIAMURL    = "http://some.endpoint.com"
)

func TestClientSetup(t *testing.T) {
	tests := []struct {
		name           string
		infrastructure *configv1.Infrastructure
		expectedParams *ccaws.ClientParams
	}{
		{
			name: "only infraname",
			infrastructure: &configv1.Infrastructure{
				Status: configv1.InfrastructureStatus{
					InfrastructureName: testInfraName,
				},
			},
			expectedParams: &ccaws.ClientParams{
				InfraName: testInfraName,
			},
		},
		{
			name: "use region for client",
			infrastructure: &configv1.Infrastructure{
				Status: configv1.InfrastructureStatus{
					InfrastructureName: testInfraName,
					PlatformStatus: &configv1.PlatformStatus{
						AWS: &configv1.AWSPlatformStatus{
							Region: testRegion,
						},
					},
				},
			},
			expectedParams: &ccaws.ClientParams{
				InfraName: testInfraName,
				Region:    testRegion,
			},
		},
		{
			name: "use provided IAM endpoint",
			infrastructure: &configv1.Infrastructure{
				Status: configv1.InfrastructureStatus{
					InfrastructureName: testInfraName,
					PlatformStatus: &configv1.PlatformStatus{
						AWS: &configv1.AWSPlatformStatus{
							Region: testRegion,
							ServiceEndpoints: []configv1.AWSServiceEndpoint{
								{
									Name: iam.ServiceName,
									URL:  testIAMURL,
								},
								{
									Name: "EC2",
									URL:  "http://ignore.this.com",
								},
							},
						},
					},
				},
			},
			expectedParams: &ccaws.ClientParams{
				InfraName: testInfraName,
				Region:    testRegion,
				Endpoint:  testIAMURL,
			},
		},
		{
			name: "endpoint not provided",
			infrastructure: &configv1.Infrastructure{
				Status: configv1.InfrastructureStatus{
					InfrastructureName: testInfraName,
					PlatformStatus: &configv1.PlatformStatus{
						AWS: &configv1.AWSPlatformStatus{
							Region: testRegion,
							ServiceEndpoints: []configv1.AWSServiceEndpoint{
								{
									Name: "EC2",
									URL:  "http://ignore.this.com",
								},
							},
						},
					},
				},
			},
			expectedParams: &ccaws.ClientParams{
				InfraName: testInfraName,
				Region:    testRegion,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			params := setupClientParams(test.infrastructure)

			assert.Equal(t, test.expectedParams, params)
		})
	}
}
