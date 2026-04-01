package status

import (
	"context"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1 "github.com/openshift/api/config/v1"

	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
)

// ================================================================
// Helper unit tests: pure functions, no reconciler
// ================================================================

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
			description: "check condition status differs",
			expected:    false,
			a: configv1.ClusterOperatorStatusCondition{
				Type:   configv1.OperatorAvailable,
				Status: configv1.ConditionTrue,
			},
			b: configv1.ClusterOperatorStatusCondition{
				Type:   configv1.OperatorAvailable,
				Status: configv1.ConditionFalse,
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
		t.Run(tc.description, func(t *testing.T) {
			actual := conditionEqual(tc.a, tc.b)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestSetLastTransitionTime(t *testing.T) {
	now := metav1.Now()
	hourAgo := metav1.Time{Time: time.Now().Add(-1 * time.Hour)}

	tests := []struct {
		name                    string
		oldConditions           []configv1.ClusterOperatorStatusCondition
		newConditions           []configv1.ClusterOperatorStatusCondition
		expectTransitionUpdated []bool // true = transition time should be recent (updated), false = preserved
	}{
		{
			name:          "new condition with no old - transition time updated",
			oldConditions: []configv1.ClusterOperatorStatusCondition{},
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{Type: configv1.OperatorAvailable, Status: configv1.ConditionTrue},
			},
			expectTransitionUpdated: []bool{true},
		},
		{
			name: "status unchanged - transition time preserved",
			oldConditions: []configv1.ClusterOperatorStatusCondition{
				{Type: configv1.OperatorAvailable, Status: configv1.ConditionTrue, LastTransitionTime: hourAgo},
			},
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{Type: configv1.OperatorAvailable, Status: configv1.ConditionTrue},
			},
			expectTransitionUpdated: []bool{false},
		},
		{
			name: "status changed - transition time updated",
			oldConditions: []configv1.ClusterOperatorStatusCondition{
				{Type: configv1.OperatorAvailable, Status: configv1.ConditionTrue, LastTransitionTime: hourAgo},
			},
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{Type: configv1.OperatorAvailable, Status: configv1.ConditionFalse},
			},
			expectTransitionUpdated: []bool{true},
		},
		{
			name: "multiple conditions - mixed preservation",
			oldConditions: []configv1.ClusterOperatorStatusCondition{
				{Type: configv1.OperatorAvailable, Status: configv1.ConditionTrue, LastTransitionTime: hourAgo},
				{Type: configv1.OperatorDegraded, Status: configv1.ConditionFalse, LastTransitionTime: hourAgo},
			},
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{Type: configv1.OperatorAvailable, Status: configv1.ConditionTrue}, // unchanged
				{Type: configv1.OperatorDegraded, Status: configv1.ConditionTrue},  // changed
			},
			expectTransitionUpdated: []bool{false, true},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setLastTransitionTime(test.oldConditions, test.newConditions)

			for i, cond := range test.newConditions {
				if test.expectTransitionUpdated[i] {
					assert.True(t, cond.LastTransitionTime.Time.After(now.Add(-5*time.Second)),
						"condition %s: expected transition time to be updated to now", cond.Type)
				} else {
					assert.Equal(t, hourAgo.Time, cond.LastTransitionTime.Time,
						"condition %s: expected transition time to be preserved", cond.Type)
				}
			}
		})
	}
}

func TestSortedStatus(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)
	time := metav1.Now()
	tests := []struct {
		name     string
		status   configv1.ClusterOperatorStatus
		expected configv1.ClusterOperatorStatus
	}{
		{
			name: "should sort conditions by type",
			status: configv1.ClusterOperatorStatus{
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{
						Type:               configv1.OperatorDegraded,
						Status:             configv1.ConditionFalse,
						Reason:             "",
						LastTransitionTime: time,
					},
					{
						Type:               configv1.OperatorAvailable,
						Status:             configv1.ConditionFalse,
						Reason:             "",
						LastTransitionTime: time,
					},
					{
						Type:               configv1.OperatorUpgradeable,
						Status:             configv1.ConditionFalse,
						Reason:             "",
						LastTransitionTime: time,
					},
					{
						Type:               configv1.OperatorProgressing,
						Status:             configv1.ConditionFalse,
						Reason:             "",
						LastTransitionTime: time,
					},
				},
			},
			expected: configv1.ClusterOperatorStatus{
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{
						Type:               configv1.OperatorAvailable,
						Status:             configv1.ConditionFalse,
						Reason:             "",
						LastTransitionTime: time,
					},
					{
						Type:               configv1.OperatorDegraded,
						Status:             configv1.ConditionFalse,
						Reason:             "",
						LastTransitionTime: time,
					},
					{
						Type:               configv1.OperatorProgressing,
						Status:             configv1.ConditionFalse,
						Reason:             "",
						LastTransitionTime: time,
					},
					{
						Type:               configv1.OperatorUpgradeable,
						Status:             configv1.ConditionFalse,
						Reason:             "",
						LastTransitionTime: time,
					},
				},
			},
		},
		{
			name: "should sort related objects by name",
			status: configv1.ClusterOperatorStatus{
				RelatedObjects: []configv1.ObjectReference{
					{
						Namespace: "sample",
						Name:      "omega",
					},
					{
						Namespace: "sample",
						Name:      "alpha",
					},
					{
						Namespace: "sample",
						Name:      "beta",
					},
				},
			},
			expected: configv1.ClusterOperatorStatus{
				RelatedObjects: []configv1.ObjectReference{
					{
						Namespace: "sample",
						Name:      "alpha",
					},
					{
						Namespace: "sample",
						Name:      "beta",
					},
					{
						Namespace: "sample",
						Name:      "omega",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sortStatusArrays(&test.status)
			assert.ElementsMatchf(t, test.status.Conditions, test.expected.Conditions, "conditions = %v, want %v", test.status.Conditions, test.expected.Conditions)
			assert.ElementsMatchf(t, test.status.RelatedObjects, test.expected.RelatedObjects, "related objects = %v, want %v", test.status.RelatedObjects, test.expected.RelatedObjects)

			for i, expected := range test.expected.Conditions {
				assert.Equal(t, expected, test.status.Conditions[i])
			}

			for i, expected := range test.expected.RelatedObjects {
				assert.Equal(t, expected, test.status.RelatedObjects[i])
			}

			assert.Equal(t, test.expected, test.status)
		})
	}
}

// ================================================================
// Infrastructure: defaults, handler merging, error handling, creation
// ================================================================

type expectedCondition struct {
	conditionType configv1.ClusterStatusConditionType
	reason        string
	status        configv1.ConditionStatus
}

func TestDefaultConditionsAndHandlerMerging(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	tests := []struct {
		name               string
		statusHandlers     []Handler
		expectedConditions []expectedCondition
	}{
		{
			name: "set default conditions",
			expectedConditions: []expectedCondition{
				{
					conditionType: configv1.OperatorAvailable,
					status:        configv1.ConditionTrue,
				},
				{
					conditionType: configv1.OperatorProgressing,
					status:        configv1.ConditionFalse,
				},
				{
					conditionType: configv1.OperatorDegraded,
					status:        configv1.ConditionFalse,
				},
				{
					conditionType: configv1.OperatorUpgradeable,
					status:        configv1.ConditionTrue,
				},
			},
		},
		{
			name: "handler returning degraded condition",
			statusHandlers: []Handler{
				newHandler("handlerA",
					[]configv1.ClusterOperatorStatusCondition{
						{
							Type:   configv1.OperatorDegraded,
							Status: configv1.ConditionTrue,
							Reason: "handlerA reasons",
						},
					},
				),
			},
			expectedConditions: []expectedCondition{
				{
					conditionType: configv1.OperatorAvailable,
					status:        configv1.ConditionTrue,
				},
				{
					conditionType: configv1.OperatorProgressing,
					status:        configv1.ConditionFalse,
				},
				{
					conditionType: configv1.OperatorDegraded,
					status:        configv1.ConditionTrue,
					reason:        "handlerA reasons",
				},
				{
					conditionType: configv1.OperatorUpgradeable,
					status:        configv1.ConditionTrue,
				},
			},
		},
		{
			name: "multiple handlers returning degraded condition",
			statusHandlers: []Handler{
				newHandler("handlerA",
					[]configv1.ClusterOperatorStatusCondition{
						{
							Type:   configv1.OperatorDegraded,
							Status: configv1.ConditionTrue,
							Reason: "handlerA reasons",
						},
					},
				),
				newHandler("handlerB",
					[]configv1.ClusterOperatorStatusCondition{
						{
							Type:   configv1.OperatorDegraded,
							Status: configv1.ConditionTrue,
							Reason: "handlerB reasons",
						},
					},
				),
			},
			expectedConditions: []expectedCondition{
				{
					conditionType: configv1.OperatorAvailable,
					status:        configv1.ConditionTrue,
				},
				{
					conditionType: configv1.OperatorProgressing,
					status:        configv1.ConditionFalse,
				},
				{
					conditionType: configv1.OperatorDegraded,
					status:        configv1.ConditionTrue,
					reason:        "handlerA reasons",
				},
				{
					conditionType: configv1.OperatorUpgradeable,
					status:        configv1.ConditionTrue,
				},
			},
		},
		{
			name: "multiple handlers returning conditions",
			statusHandlers: []Handler{
				newHandler("handlerA",
					[]configv1.ClusterOperatorStatusCondition{
						{
							Type:   configv1.OperatorDegraded,
							Status: configv1.ConditionTrue,
							Reason: "degraded reasons",
						},
					},
				),
				newHandler("handlerB",
					[]configv1.ClusterOperatorStatusCondition{
						{
							Type:   configv1.OperatorUpgradeable,
							Status: configv1.ConditionFalse,
							Reason: "upgradeable reasons",
						},
					},
				),
			},
			expectedConditions: []expectedCondition{
				{
					conditionType: configv1.OperatorAvailable,
					status:        configv1.ConditionTrue,
				},
				{
					conditionType: configv1.OperatorProgressing,
					status:        configv1.ConditionFalse,
				},
				{
					conditionType: configv1.OperatorDegraded,
					status:        configv1.ConditionTrue,
					reason:        "degraded reasons",
				},
				{
					conditionType: configv1.OperatorUpgradeable,
					status:        configv1.ConditionFalse,
					reason:        "upgradeable reasons",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearHandlers()
			defer clearHandlers()

			basicClusterOperator := testBasicClusterOperator()
			objects := []runtime.Object{
				basicClusterOperator,
				testOperatorConfig(""),
				testClusterVersion(false),
			}

			fakeClient := fake.NewClientBuilder().
				WithStatusSubresource(basicClusterOperator).
				WithRuntimeObjects(objects...).Build()

			t.Setenv("RELEASE_VERSION", "ANYVERSION")

			r := &ReconcileStatus{
				Client:   fakeClient,
				Logger:   log.WithField("controller", controllerName),
				platform: configv1.AWSPlatformType,
			}

			for _, handler := range test.statusHandlers {
				AddHandler(handler.Name(), handler)
			}

			_, err := r.Reconcile(context.TODO(), reconcile.Request{})

			require.NoError(t, err, "unexpected error")

			co := getClusterOperator(fakeClient)
			require.NotNil(t, co)

			// defaultUnsetConditions always produces exactly 4 conditions
			assert.Len(t, co.Status.Conditions, 4)

			for _, condition := range test.expectedConditions {
				foundCondition, _ := findClusterOperatorCondition(co.Status.Conditions, condition.conditionType)
				require.NotNil(t, foundCondition, "condition %s not found", condition.conditionType)
				assert.Equal(t, string(condition.status), string(foundCondition.Status), "condition %s had unexpected status", condition.conditionType)
				if condition.reason != "" {
					assert.Exactly(t, condition.reason, foundCondition.Reason)
				}
			}
		})
	}
}

func TestWorstWinsMerging(t *testing.T) {
	logger := log.WithField("controller", "test")

	t.Run("Degraded True wins over False", func(t *testing.T) {
		existing := []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorDegraded, Status: configv1.ConditionFalse, Reason: "AllGood", Message: "handler A is fine"},
		}
		incoming := []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorDegraded, Status: configv1.ConditionTrue, Reason: "Broken", Message: "handler B is broken"},
		}
		result := mergeConditions(existing, incoming, "handlerB", logger)
		require.Len(t, result, 1)
		assert.Equal(t, configv1.ConditionTrue, result[0].Status, "True (worse) should win for Degraded")
		assert.Equal(t, "Broken", result[0].Reason, "winner's reason should be kept")
		assert.Contains(t, result[0].Message, "handler B is broken")
		assert.Contains(t, result[0].Message, "handler A is fine", "loser's message should be appended")
	})

	t.Run("Degraded False does not overwrite True", func(t *testing.T) {
		existing := []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorDegraded, Status: configv1.ConditionTrue, Reason: "Broken", Message: "handler A is broken"},
		}
		incoming := []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorDegraded, Status: configv1.ConditionFalse, Reason: "AllGood", Message: "handler B is fine"},
		}
		result := mergeConditions(existing, incoming, "handlerB", logger)
		require.Len(t, result, 1)
		assert.Equal(t, configv1.ConditionTrue, result[0].Status, "True (worse) should be preserved for Degraded")
		assert.Equal(t, "Broken", result[0].Reason)
		assert.Contains(t, result[0].Message, "handler A is broken")
		assert.Contains(t, result[0].Message, "handler B is fine")
	})

	t.Run("Available False wins over True", func(t *testing.T) {
		existing := []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorAvailable, Status: configv1.ConditionTrue, Reason: "Ready", Message: "handler A is available"},
		}
		incoming := []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorAvailable, Status: configv1.ConditionFalse, Reason: "Down", Message: "handler B is down"},
		}
		result := mergeConditions(existing, incoming, "handlerB", logger)
		require.Len(t, result, 1)
		assert.Equal(t, configv1.ConditionFalse, result[0].Status, "False (worse) should win for Available")
		assert.Equal(t, "Down", result[0].Reason)
		assert.Contains(t, result[0].Message, "handler B is down")
		assert.Contains(t, result[0].Message, "handler A is available")
	})

	t.Run("same status concatenates messages", func(t *testing.T) {
		existing := []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorDegraded, Status: configv1.ConditionTrue, Reason: "ReasonA", Message: "problem A"},
		}
		incoming := []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorDegraded, Status: configv1.ConditionTrue, Reason: "ReasonB", Message: "problem B"},
		}
		result := mergeConditions(existing, incoming, "handlerB", logger)
		require.Len(t, result, 1)
		assert.Equal(t, configv1.ConditionTrue, result[0].Status)
		assert.Equal(t, "ReasonA", result[0].Reason, "first handler's reason should be kept when status is equal")
		assert.Equal(t, "problem A; problem B", result[0].Message, "messages should be concatenated with semicolon")
	})
}

func TestWorstWinsEmptyMessages(t *testing.T) {
	logger := log.WithField("controller", "test")

	t.Run("empty existing message", func(t *testing.T) {
		existing := []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorDegraded, Status: configv1.ConditionTrue, Reason: "A", Message: ""},
		}
		incoming := []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorDegraded, Status: configv1.ConditionTrue, Reason: "B", Message: "problem B"},
		}
		result := mergeConditions(existing, incoming, "handlerB", logger)
		assert.Equal(t, "; problem B", result[0].Message,
			"empty first message produces leading semicolon — known cosmetic issue")
	})

	t.Run("both messages empty", func(t *testing.T) {
		existing := []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorDegraded, Status: configv1.ConditionTrue, Reason: "A", Message: ""},
		}
		incoming := []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorDegraded, Status: configv1.ConditionTrue, Reason: "B", Message: ""},
		}
		result := mergeConditions(existing, incoming, "handlerB", logger)
		assert.Equal(t, "; ", result[0].Message,
			"two empty messages produce bare separator — known cosmetic issue")
	})

	t.Run("empty incoming message", func(t *testing.T) {
		existing := []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorDegraded, Status: configv1.ConditionTrue, Reason: "A", Message: "problem A"},
		}
		incoming := []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorDegraded, Status: configv1.ConditionTrue, Reason: "B", Message: ""},
		}
		result := mergeConditions(existing, incoming, "handlerB", logger)
		assert.Equal(t, "problem A; ", result[0].Message,
			"empty second message produces trailing semicolon — known cosmetic issue")
	})
}

func TestSetLastTransitionTimeReasonChange(t *testing.T) {
	hourAgo := metav1.Time{Time: time.Now().Add(-1 * time.Hour)}

	// Status unchanged but reason differs — transition time should be preserved
	oldConditions := []configv1.ClusterOperatorStatusCondition{
		{Type: configv1.OperatorDegraded, Status: configv1.ConditionTrue, Reason: "ReasonA",
			LastTransitionTime: hourAgo},
	}
	newConditions := []configv1.ClusterOperatorStatusCondition{
		{Type: configv1.OperatorDegraded, Status: configv1.ConditionTrue, Reason: "ReasonB"},
	}

	setLastTransitionTime(oldConditions, newConditions)

	assert.Equal(t, hourAgo.Time, newConditions[0].LastTransitionTime.Time,
		"transition time should be preserved when only reason changes, not status")
}

func TestFindClusterOperatorConditionIndex(t *testing.T) {
	conditions := []configv1.ClusterOperatorStatusCondition{
		{Type: configv1.OperatorAvailable, Status: configv1.ConditionTrue},
		{Type: configv1.OperatorDegraded, Status: configv1.ConditionFalse},
		{Type: configv1.OperatorProgressing, Status: configv1.ConditionFalse},
	}

	t.Run("returns correct index", func(t *testing.T) {
		cond, idx := findClusterOperatorCondition(conditions, configv1.OperatorDegraded)
		require.NotNil(t, cond)
		assert.Equal(t, 1, idx)
		assert.Equal(t, configv1.OperatorDegraded, cond.Type)
	})

	t.Run("returns nil and 0 for missing condition", func(t *testing.T) {
		cond, idx := findClusterOperatorCondition(conditions, configv1.OperatorUpgradeable)
		assert.Nil(t, cond)
		assert.Equal(t, 0, idx)
	})

	t.Run("returns pointer into slice", func(t *testing.T) {
		cond, _ := findClusterOperatorCondition(conditions, configv1.OperatorAvailable)
		require.NotNil(t, cond)
		cond.Reason = "Modified"
		assert.Equal(t, "Modified", conditions[0].Reason,
			"pointer should modify original slice element")
	})
}

func TestClusterVersionWithoutProgressingCondition(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	// ClusterVersion exists but has no Progressing condition at all
	cv := &configv1.ClusterVersion{
		ObjectMeta: metav1.ObjectMeta{Name: "version"},
		Status:     configv1.ClusterVersionStatus{
			// No conditions
		},
	}

	basicCO := testBasicClusterOperator()
	operatorConfig := testOperatorConfig("")

	clearHandlers()
	AddHandler("test-degraded", newHandler("test-degraded", []configv1.ClusterOperatorStatusCondition{
		{Type: configv1.OperatorDegraded, Status: configv1.ConditionTrue, Reason: "TestDegraded", Message: "test"},
	}))
	defer clearHandlers()

	fakeClient := fake.NewClientBuilder().
		WithStatusSubresource(basicCO).
		WithRuntimeObjects(basicCO, operatorConfig, cv).Build()

	t.Setenv("RELEASE_VERSION", "ANYVERSION")

	rs := &ReconcileStatus{
		Client:   fakeClient,
		Logger:   log.WithField("controller", "teststatus"),
		platform: configv1.AWSPlatformType,
	}
	_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
	require.NoError(t, err, "reconcile should succeed when ClusterVersion has no Progressing condition")

	co := getClusterOperator(fakeClient)
	require.NotNil(t, co)

	// Missing Progressing on ClusterVersion means not upgrading — Degraded should NOT be suppressed
	degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
	require.NotNil(t, degraded)
	assert.Equal(t, configv1.ConditionTrue, degraded.Status,
		"Degraded should not be suppressed when ClusterVersion has no Progressing condition")
}

func TestEmptyReleaseVersion(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	basicCO := testBasicClusterOperator()
	operatorConfig := testOperatorConfig("")
	cv := testClusterVersion(false)

	clearHandlers()
	defer clearHandlers()

	fakeClient := fake.NewClientBuilder().
		WithStatusSubresource(basicCO).
		WithRuntimeObjects(basicCO, operatorConfig, cv).Build()

	// Set RELEASE_VERSION to empty string
	t.Setenv("RELEASE_VERSION", "")

	rs := &ReconcileStatus{
		Client:   fakeClient,
		Logger:   log.WithField("controller", "teststatus"),
		platform: configv1.AWSPlatformType,
	}
	_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
	require.NoError(t, err, "reconcile should succeed with empty RELEASE_VERSION")

	co := getClusterOperator(fakeClient)
	require.NotNil(t, co)

	require.Len(t, co.Status.Versions, 1)
	assert.Equal(t, "", co.Status.Versions[0].Version,
		"empty RELEASE_VERSION should produce empty version string")
}

func TestHandlerErrorDoesNotCrashReconcile(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	basicCO := testBasicClusterOperator()
	operatorConfig := testOperatorConfig("")
	cv := testClusterVersion(false)

	clearHandlers()
	// Register a handler that always errors
	AddHandler("broken-handler", &errorHandler{name: "broken-handler"})
	// Register a healthy handler that sets Degraded=True
	AddHandler("healthy-handler", newHandler("healthy-handler", []configv1.ClusterOperatorStatusCondition{
		{
			Type:    configv1.OperatorDegraded,
			Status:  configv1.ConditionTrue,
			Reason:  "HealthyHandlerDegraded",
			Message: "healthy handler reported degraded",
		},
	}))
	defer clearHandlers()

	fakeClient := fake.NewClientBuilder().
		WithStatusSubresource(basicCO).
		WithRuntimeObjects(basicCO, operatorConfig, cv).Build()

	t.Setenv("RELEASE_VERSION", "ANYVERSION")

	rs := &ReconcileStatus{
		Client:   fakeClient,
		Logger:   log.WithField("controller", "teststatus"),
		platform: configv1.AWSPlatformType,
	}
	_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
	// Reconcile should fail when a handler errors — aborting preserves the
	// last published status instead of letting defaultUnsetConditions fill
	// in "AsExpected" for the failed handler's missing conditions.
	require.Error(t, err, "reconcile should fail when a handler returns an error")
	assert.Contains(t, err.Error(), "broken-handler")
}

func TestClusterOperatorCreatedWhenNotFound(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	// Do NOT create a ClusterOperator object — simulate the not-found path
	operatorConfig := testOperatorConfig("")
	cv := testClusterVersion(false)

	fakeClient := fake.NewClientBuilder().
		WithStatusSubresource(&configv1.ClusterOperator{}).
		WithRuntimeObjects(operatorConfig, cv).Build()

	clearHandlers()
	defer clearHandlers()

	t.Setenv("RELEASE_VERSION", "ANYVERSION")

	rs := &ReconcileStatus{
		Client:   fakeClient,
		Logger:   log.WithField("controller", "teststatus"),
		platform: configv1.AWSPlatformType,
	}
	_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
	require.NoError(t, err, "reconcile should not fail when ClusterOperator does not exist")

	co := getClusterOperator(fakeClient)
	require.NotNil(t, co, "ClusterOperator should be created when not found")
	assert.Equal(t, constants.CloudCredClusterOperatorName, co.Name)
}
