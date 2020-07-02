package clusteroperator

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConditionsEqual(t *testing.T) {
	testCases := []struct {
		description string
		expected    bool
		a, b        configv1.ClusterOperatorStatusCondition
	}{
		{
			description: "empty conditions should be equal",
			expected:    true,
		},
		{
			description: "condition LastTransitionTime should be ignored",
			expected:    true,
			a: configv1.ClusterOperatorStatusCondition{
				Type:               configv1.OperatorAvailable,
				Status:             configv1.ConditionTrue,
				LastTransitionTime: metav1.Unix(0, 0),
			},
			b: configv1.ClusterOperatorStatusCondition{
				Type:               configv1.OperatorAvailable,
				Status:             configv1.ConditionTrue,
				LastTransitionTime: metav1.Unix(1, 0),
			},
		},
		{
			description: "check condition reason differs",
			expected:    false,
			a: configv1.ClusterOperatorStatusCondition{
				Type:   configv1.OperatorAvailable,
				Status: configv1.ConditionFalse,
				Reason: "foo",
			},
			b: configv1.ClusterOperatorStatusCondition{

				Type:   configv1.OperatorAvailable,
				Status: configv1.ConditionFalse,
				Reason: "bar",
			},
		},
		{
			description: "check condition message differs",
			expected:    false,
			a: configv1.ClusterOperatorStatusCondition{

				Type:    configv1.OperatorAvailable,
				Status:  configv1.ConditionFalse,
				Message: "foo",
			},

			b: configv1.ClusterOperatorStatusCondition{

				Type:    configv1.OperatorAvailable,
				Status:  configv1.ConditionFalse,
				Message: "bar",
			},
		},
	}

	for _, tc := range testCases {
		actual := conditionEqual(tc.a, tc.b)
		if actual != tc.expected {
			t.Fatalf("%q: expected %v, got %v", tc.description,
				tc.expected, actual)
		}
	}
}
