package status

import (
	"context"
	"os"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
)

func TestClusterOperatorVersion(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	twentyHoursAgo := metav1.Time{
		Time: time.Now().Add(-20 * time.Hour),
	}

	tests := []struct {
		name                             string
		releaseVersionEnv                string
		currentProgressingLastTransition metav1.Time
		currentVersion                   string
		expectProgressingTransition      bool
	}{
		{
			name:                             "test version upgraded",
			currentProgressingLastTransition: twentyHoursAgo,
			currentVersion:                   "4.0.0-5",
			releaseVersionEnv:                "4.0.0-10",
			expectProgressingTransition:      true,
		},
		{
			name:                             "test version constant",
			currentProgressingLastTransition: twentyHoursAgo,
			currentVersion:                   "4.0.0-5",
			releaseVersionEnv:                "4.0.0-5",
			expectProgressingTransition:      false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			existingCO := testClusterOperator("4.0.0-5", twentyHoursAgo)
			operatorConfig := testOperatorConfig("")
			existing := []runtime.Object{existingCO, operatorConfig}
			fakeClient := fake.NewClientBuilder().WithRuntimeObjects(existing...).Build()

			require.NoError(t, os.Setenv("RELEASE_VERSION", test.releaseVersionEnv), "unable to set environment variable for testing")

			rs := &ReconcileStatus{
				Client:   fakeClient,
				Logger:   log.WithField("controller", "teststatus"),
				platform: configv1.AWSPlatformType,
			}
			_, err := rs.Reconcile(context.TODO(), reconcile.Request{})

			require.NoError(t, err, "unexpected error")

			clusterop := &configv1.ClusterOperator{}

			err = fakeClient.Get(context.TODO(), client.ObjectKey{Name: constants.CloudCredClusterOperatorName}, clusterop)
			assert.NoError(t, err)

			foundVersion := false
			for _, version := range clusterop.Status.Versions {
				if version.Name == "operator" {
					foundVersion = true
					assert.Equal(t, test.releaseVersionEnv, version.Version)
				}
			}
			assert.True(t, foundVersion, "didn't find an entry named 'operator' in the version list")

			progCond, _ := findClusterOperatorCondition(clusterop.Status.Conditions,
				configv1.OperatorProgressing)
			require.NotNil(t, progCond)
			if test.expectProgressingTransition {
				assert.True(t, progCond.LastTransitionTime.Time.After(
					test.currentProgressingLastTransition.Time))
			} else {
				assert.Equal(t, test.currentProgressingLastTransition.Time.Format(time.UnixDate),
					progCond.LastTransitionTime.Time.Format(time.UnixDate))
			}
		})
	}
}

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

type expectedCondition struct {
	conditionType configv1.ClusterStatusConditionType
	reason        string
	status        configv1.ConditionStatus
}

func TestConditions(t *testing.T) {
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
					conditionType: configv1.OperatorDegraded,
					status:        configv1.ConditionTrue,
					reason:        "handlerA reasons",
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
							Reason: "handerB reasons",
						},
					},
				),
			},
			expectedConditions: []expectedCondition{
				{
					conditionType: configv1.OperatorDegraded,
					status:        configv1.ConditionTrue,
					// can't predict reason b/c order that handlers are called is non-deterministic
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

		// Make sure we have a clean ClusterOperator and CCO config for each test run
		objects := []runtime.Object{
			testBasicClusterOperator(),
			testOperatorConfig(""),
		}

		fakeClient := fake.NewClientBuilder().WithRuntimeObjects(objects...).Build()

		r := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", controllerName),
			platform: configv1.AWSPlatformType,
		}

		for _, handler := range test.statusHandlers {
			AddHandler(handler.Name(), handler)
		}
		defer clearHandlers()

		_, err := r.Reconcile(context.TODO(), reconcile.Request{})

		require.NoError(t, err, "unexpected error")

		for _, condition := range test.expectedConditions {
			co := getClusterOperator(fakeClient)
			assert.NotNil(t, co)
			foundCondition, _ := findClusterOperatorCondition(co.Status.Conditions, condition.conditionType)
			require.NotNil(t, foundCondition)
			assert.Equal(t, string(condition.status), string(foundCondition.Status), "condition %s had unexpected status", condition.conditionType)
			if condition.reason != "" {
				assert.Exactly(t, condition.reason, foundCondition.Reason)
			}
		}
	}
}

func getClusterOperator(c client.Client) *configv1.ClusterOperator {
	co := &configv1.ClusterOperator{ObjectMeta: metav1.ObjectMeta{Name: constants.CloudCredClusterOperatorName}}
	err := c.Get(context.TODO(), types.NamespacedName{Name: co.Name}, co)
	if err != nil {
		return nil
	}
	return co
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

func testBasicClusterOperator() *configv1.ClusterOperator {
	now := metav1.Time{
		Time: time.Now(),
	}
	return testClusterOperator("ANYVERSION", now)
}

func testClusterOperator(version string, progressingLastTransition metav1.Time) *configv1.ClusterOperator {
	return &configv1.ClusterOperator{
		ObjectMeta: metav1.ObjectMeta{
			Name: constants.CloudCredClusterOperatorName,
		},
		Status: configv1.ClusterOperatorStatus{
			Versions: []configv1.OperandVersion{
				{
					Name:    "operator",
					Version: version,
				},
			},
			Conditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:               configv1.OperatorProgressing,
					Status:             configv1.ConditionFalse,
					LastTransitionTime: progressingLastTransition,
				},
			},
		},
	}
}

// conditionEqual compares every field except LastTransitionTime.
func conditionEqual(a, b configv1.ClusterOperatorStatusCondition) bool {
	if a.Type == b.Type &&
		a.Status == b.Status &&
		a.Reason == b.Reason &&
		a.Message == b.Message {
		return true
	}
	return false
}

type miniHandler struct {
	name           string
	conditions     []configv1.ClusterOperatorStatusCondition
	relatedObjects []configv1.ObjectReference
}

func newHandler(name string, conditions []configv1.ClusterOperatorStatusCondition) Handler {
	return &miniHandler{
		name:       name,
		conditions: conditions,
	}
}

func (h *miniHandler) GetConditions(log.FieldLogger) ([]configv1.ClusterOperatorStatusCondition, error) {
	return h.conditions, nil
}

func (h *miniHandler) GetRelatedObjects(log.FieldLogger) ([]configv1.ObjectReference, error) {
	return h.relatedObjects, nil
}

func (h *miniHandler) Name() string {
	return h.name
}

func testHandler() Handler {
	return nil
}
