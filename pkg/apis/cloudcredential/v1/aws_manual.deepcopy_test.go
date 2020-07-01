package v1

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime"

	"github.com/stretchr/testify/assert"
)

func TestAWSProviderSpecDeepCopy(t *testing.T) {

	tests := []struct {
		name         string
		providerSpec *AWSCredentialsProviderSpec
	}{
		{
			name: "basic provider spec",
			providerSpec: &AWSCredentialsProviderSpec{
				StatementEntries: []StatementEntry{
					{
						Effect: "Allow",
						Action: []string{
							"iam:Action1",
							"iam:Action2",
						},
						Resource: "*",
					},
				},
			},
		},
		{
			name: "with conditions",
			providerSpec: &AWSCredentialsProviderSpec{
				StatementEntries: []StatementEntry{
					{
						Effect: "Allow",
						Action: []string{
							"iam:Action1",
							"iam:Action2",
						},
						Resource: "*",
						PolicyCondition: IAMPolicyCondition{
							"StringEquals": IAMPolicyConditionKeyValue{
								"aws:userid": "testuser",
							},
							"StringNotEquals": IAMPolicyConditionKeyValue{
								"aws:SourceVpc": "vpc-12345",
							},
						},
					},
				},
			},
		},
		{
			name:         "nil provider spec",
			providerSpec: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dCopy := test.providerSpec.DeepCopy()
			assert.Equal(t, test.providerSpec, dCopy, "expected the DeepCopy() results to be deeply equal")

			if test.providerSpec != nil {
				newAWSProviderSpec := &AWSCredentialsProviderSpec{}
				test.providerSpec.DeepCopyInto(newAWSProviderSpec)
				assert.Equal(t, test.providerSpec, newAWSProviderSpec, "expected the DeepCopyInto() results to be deeply equal")

				dCopyObject := test.providerSpec.DeepCopyObject()
				testProviderSpecObject := runtime.Object(test.providerSpec)
				assert.Equal(t, testProviderSpecObject, dCopyObject, "expected the DeepCopyObject() results to be equal")
			}
		})
	}
}
