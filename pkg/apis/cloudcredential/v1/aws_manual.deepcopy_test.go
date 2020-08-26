package v1

import (
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
)

func TestAWSProviderSpecDeepCopy(t *testing.T) {

	tests := []struct {
		name         string
		providerSpec *AWSProviderSpec
		expected     *AWSProviderSpec
	}{
		{
			name: "basic provider spec",
			providerSpec: &AWSProviderSpec{
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
			expected: &AWSProviderSpec{
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
			providerSpec: &AWSProviderSpec{
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
								"aws:userid": []string{"testuser1", "testuser2"},
							},
							"StringNotEquals": IAMPolicyConditionKeyValue{
								"aws:SourceVpc": "vpc-12345",
							},
						},
					},
				},
			},
			expected: &AWSProviderSpec{
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
								"aws:userid": []string{"testuser1", "testuser2"},
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
			name: "multiple statements multiple conditions",
			providerSpec: &AWSProviderSpec{
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
								"aws:userid": []string{"testuser1", "testuser2"},
							},
							"StringNotEquals": IAMPolicyConditionKeyValue{
								"aws:SourceVpc": "vpc-12345",
							},
						},
					},
					{
						Effect: "Deny",
						Action: []string{
							"iam:DeleteAccount",
							"iam:DoSAWS",
						},
						Resource: "*",
						PolicyCondition: IAMPolicyCondition{
							"StringEquals": IAMPolicyConditionKeyValue{
								"aws:userid": "rogueuser1",
							},
						},
					},
				},
			},
			expected: &AWSProviderSpec{
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
								"aws:userid": []string{"testuser1", "testuser2"},
							},
							"StringNotEquals": IAMPolicyConditionKeyValue{
								"aws:SourceVpc": "vpc-12345",
							},
						},
					},
					{
						Effect: "Deny",
						Action: []string{
							"iam:DeleteAccount",
							"iam:DoSAWS",
						},
						Resource: "*",
						PolicyCondition: IAMPolicyCondition{
							"StringEquals": IAMPolicyConditionKeyValue{
								"aws:userid": "rogueuser1",
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

			if test.providerSpec != nil {
				// Test DeepCopyInto()
				newAWSProviderSpec := &AWSProviderSpec{}
				test.providerSpec.DeepCopyInto(newAWSProviderSpec)

				// Test DeepCopyObject()
				dCopyObject := test.providerSpec.DeepCopyObject()
				testProviderSpecObject := runtime.Object(test.expected)

				// Mess with the original struct
				test.providerSpec.StatementEntries[0].Action = []string{"messingWithOriginalObject"}
				test.providerSpec.StatementEntries[0].PolicyCondition = IAMPolicyCondition{}
				test.providerSpec.StatementEntries[0].PolicyCondition["StringEquals2"] = IAMPolicyConditionKeyValue{"more": "modifications"}

				if !reflect.DeepEqual(test.expected, dCopy) {
					t.Fatalf("DeepCopy Failure\nExpected:\t%#v\nBut found:\t%#v\n", *test.expected, *dCopy)
				}

				if !reflect.DeepEqual(test.expected, newAWSProviderSpec) {
					t.Fatalf("DeepCopyInto Failure\nExpected:\t%#v,But found:\t%#v\n", *test.expected, *newAWSProviderSpec)
				}

				if !reflect.DeepEqual(testProviderSpecObject, dCopyObject) {
					t.Fatalf("DeepCopyObject Failure\nExpected:\t%#v\nBut found:\t%#v\n", testProviderSpecObject, dCopyObject)
				}

			} else {
				if dCopy != nil {
					t.Fatal("Expected the copied object to be nil when the source is nil")
				}
			}
		})
	}
}
