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
	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
)

// ================================================================
// Available condition
// ================================================================

func TestAvailable(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	t.Run("coexists with Degraded=True", func(t *testing.T) {
		// Spec: "A component may be Available even if its degraded."
		basicCO := testBasicClusterOperator()
		operatorConfig := testOperatorConfig("")
		cv := testClusterVersion(false)

		clearHandlers()
		AddHandler("test-degraded", newHandler("test-degraded", []configv1.ClusterOperatorStatusCondition{
			{
				Type:    configv1.OperatorDegraded,
				Status:  configv1.ConditionTrue,
				Reason:  "SomeDegradedReason",
				Message: "something is degraded",
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
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)

		available, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorAvailable)
		require.NotNil(t, available)
		assert.Equal(t, configv1.ConditionTrue, available.Status,
			"Available should default to True even when Degraded is True")

		degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionTrue, degraded.Status,
			"Degraded should be True as set by handler")
	})

	t.Run("Progressing=True does not cause Degraded within timeout", func(t *testing.T) {
		// Spec: "A component may be Progressing but not Degraded because the
		// transition from one state to another does not persist over a long enough
		// period to report Degraded."
		tenMinutesAgo := metav1.Time{Time: time.Now().Add(-10 * time.Minute)}

		existingCO := &configv1.ClusterOperator{
			ObjectMeta: metav1.ObjectMeta{
				Name: constants.CloudCredClusterOperatorName,
			},
			Status: configv1.ClusterOperatorStatus{
				Versions: []configv1.OperandVersion{
					{Name: "operator", Version: "ANYVERSION"},
				},
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{
						Type:               configv1.OperatorProgressing,
						Status:             configv1.ConditionTrue,
						Reason:             "Reconciling",
						LastTransitionTime: tenMinutesAgo,
					},
				},
			},
		}

		operatorConfig := testOperatorConfig("")
		cv := testClusterVersion(false)

		clearHandlers()
		AddHandler("test-progressing", newHandler("test-progressing", []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorProgressing, Status: configv1.ConditionTrue, Reason: "Reconciling"},
		}))
		defer clearHandlers()

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(existingCO).
			WithRuntimeObjects(existingCO, operatorConfig, cv).Build()

		t.Setenv("RELEASE_VERSION", "ANYVERSION")

		rs := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", "teststatus"),
			platform: configv1.AWSPlatformType,
		}
		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)

		// Progressing should be True
		progCond, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		require.NotNil(t, progCond)
		assert.Equal(t, configv1.ConditionTrue, progCond.Status)

		// Available should be True (default)
		available, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorAvailable)
		require.NotNil(t, available)
		assert.Equal(t, configv1.ConditionTrue, available.Status,
			"Available should remain True while Progressing — component is still functional")

		// Degraded should be False — progressing alone does not cause Degraded
		degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionFalse, degraded.Status,
			"Progressing alone should not cause Degraded within the 20-minute window")
	})

	t.Run("Available=True when operator disabled", func(t *testing.T) {
		clearHandlers()
		defer clearHandlers()

		basicCO := testBasicClusterOperator()
		operatorConfig := testOperatorConfig(operatorv1.CloudCredentialsModeManual)
		cv := testClusterVersion(false)

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
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)

		available, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorAvailable)
		require.NotNil(t, available)
		assert.Equal(t, configv1.ConditionTrue, available.Status,
			"Available should remain True when operator is disabled")
		assert.Equal(t, reasonOperatorDisabled, available.Reason)
		assert.Equal(t, msgOperatorDisabled, available.Message)
	})
}

// ================================================================
// Progressing condition
// ================================================================

func TestProgressing(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	twentyHoursAgo := metav1.Time{
		Time: time.Now().Add(-20 * time.Hour),
	}

	t.Run("version change sets Progressing=True with VersionChanged reason", func(t *testing.T) {
		existingCO := testClusterOperator("4.0.0-5", twentyHoursAgo)
		operatorConfig := testOperatorConfig("")
		cv := testClusterVersion(false)
		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(existingCO).
			WithRuntimeObjects(existingCO, operatorConfig, cv).Build()

		t.Setenv("RELEASE_VERSION", "4.0.0-10")

		rs := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", "teststatus"),
			platform: configv1.AWSPlatformType,
		}
		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)

		foundVersion := false
		for _, version := range co.Status.Versions {
			if version.Name == "operator" {
				foundVersion = true
				assert.Equal(t, "4.0.0-10", version.Version)
			}
		}
		assert.True(t, foundVersion, "didn't find an entry named 'operator' in the version list")

		progCond, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		require.NotNil(t, progCond)
		assert.True(t, progCond.LastTransitionTime.Time.After(twentyHoursAgo.Time))
		assert.Equal(t, configv1.ConditionTrue, progCond.Status, "Progressing condition should be True when version changes")
		assert.Equal(t, reasonVersionChanged, progCond.Reason, "Progressing condition should have VersionChanged reason")
		assert.Equal(t, "Operator version is updating", progCond.Message, "Progressing condition should have expected message")
	})

	t.Run("version unchanged keeps Progressing=False", func(t *testing.T) {
		existingCO := testClusterOperator("4.0.0-5", twentyHoursAgo)
		operatorConfig := testOperatorConfig("")
		cv := testClusterVersion(false)
		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(existingCO).
			WithRuntimeObjects(existingCO, operatorConfig, cv).Build()

		t.Setenv("RELEASE_VERSION", "4.0.0-5")

		rs := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", "teststatus"),
			platform: configv1.AWSPlatformType,
		}
		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)

		progCond, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		require.NotNil(t, progCond)
		assert.Equal(t, configv1.ConditionFalse, progCond.Status,
			"Progressing should be False when version is unchanged")
		// Compare at second precision: metav1.Time serializes to RFC3339 (no
		// sub-second component), so times that round-trip through the fake client
		// lose nanoseconds, making Time.Equal inappropriate here.
		assert.Equal(t, twentyHoursAgo.Time.Unix(), progCond.LastTransitionTime.Time.Unix(),
			"LastTransitionTime should be preserved when version is unchanged")
	})

	t.Run("VersionChanged clears on next reconcile when no handler reports progress", func(t *testing.T) {
		existingCO := testClusterOperator("4.0.0-1", metav1.Time{Time: time.Now().Add(-1 * time.Hour)})
		operatorConfig := testOperatorConfig("")
		cv := testClusterVersion(false)
		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(existingCO).
			WithRuntimeObjects(existingCO, operatorConfig, cv).Build()

		t.Setenv("RELEASE_VERSION", "4.0.0-2")

		rs := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", "teststatus"),
			platform: configv1.AWSPlatformType,
		}

		// First reconcile: version changes
		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)
		progCond, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		require.NotNil(t, progCond)
		assert.Equal(t, configv1.ConditionTrue, progCond.Status)
		assert.Equal(t, reasonVersionChanged, progCond.Reason)

		// Second reconcile: version matches, no handler progressing — clears signal
		_, err = rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co = getClusterOperator(fakeClient)
		require.NotNil(t, co)
		progCond, _ = findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		require.NotNil(t, progCond)
		assert.Equal(t, configv1.ConditionFalse, progCond.Status,
			"Progressing should clear when no handler reports progress after version change")
	})

	t.Run("handler takes over Progressing from VersionChanged", func(t *testing.T) {
		existingCO := testClusterOperator("4.0.0-1", metav1.Time{Time: time.Now().Add(-1 * time.Hour)})
		operatorConfig := testOperatorConfig("")
		cv := testClusterVersion(false)
		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(existingCO).
			WithRuntimeObjects(existingCO, operatorConfig, cv).Build()

		t.Setenv("RELEASE_VERSION", "4.0.0-2")

		clearHandlers()
		AddHandler("test-progressing", newHandler("test-progressing", []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorProgressing, Status: configv1.ConditionTrue, Reason: "Reconciling"},
		}))
		defer clearHandlers()

		rs := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", "teststatus"),
			platform: configv1.AWSPlatformType,
		}

		// First reconcile — version change detected
		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		// Second reconcile — handler takes over with its own reason
		_, err = rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		progCond, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		assert.Equal(t, configv1.ConditionTrue, progCond.Status)
		assert.Equal(t, "Reconciling", progCond.Reason,
			"handler's reason should take over from VersionChanged")
	})

	t.Run("LastTransitionTime not reset when already progressing", func(t *testing.T) {
		tenMinutesAgo := metav1.Time{Time: time.Now().Add(-10 * time.Minute)}
		existingCO := &configv1.ClusterOperator{
			ObjectMeta: metav1.ObjectMeta{
				Name: constants.CloudCredClusterOperatorName,
			},
			Status: configv1.ClusterOperatorStatus{
				Versions: []configv1.OperandVersion{
					{Name: "operator", Version: "4.0.0-1"},
				},
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{
						Type:               configv1.OperatorProgressing,
						Status:             configv1.ConditionTrue,
						Reason:             "Reconciling",
						LastTransitionTime: tenMinutesAgo,
					},
				},
			},
		}
		operatorConfig := testOperatorConfig("")

		clearHandlers()
		AddHandler("test-progressing", newHandler("test-progressing", []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorProgressing, Status: configv1.ConditionTrue, Reason: "Reconciling"},
		}))
		defer clearHandlers()

		cv := testClusterVersion(false)
		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(existingCO).
			WithRuntimeObjects(existingCO, operatorConfig, cv).Build()

		t.Setenv("RELEASE_VERSION", "4.0.0-2")

		rs := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", "teststatus"),
			platform: configv1.AWSPlatformType,
		}
		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)

		progCond, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		require.NotNil(t, progCond)
		assert.Equal(t, configv1.ConditionTrue, progCond.Status)
		assert.Equal(t, tenMinutesAgo.Time.Unix(), progCond.LastTransitionTime.Time.Unix(),
			"LastTransitionTime should not be reset when already Progressing=True")
	})

	t.Run("three-reconcile: VersionChanged clears and stays cleared", func(t *testing.T) {
		existingCO := testClusterOperator("4.0.0-1", metav1.Time{Time: time.Now().Add(-1 * time.Hour)})
		operatorConfig := testOperatorConfig("")
		cv := testClusterVersion(false)

		clearHandlers()
		defer clearHandlers()

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(existingCO).
			WithRuntimeObjects(existingCO, operatorConfig, cv).Build()

		t.Setenv("RELEASE_VERSION", "4.0.0-2")

		rs := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", "teststatus"),
			platform: configv1.AWSPlatformType,
		}

		// First reconcile: version changes
		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)
		progCond, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		require.NotNil(t, progCond)
		assert.Equal(t, configv1.ConditionTrue, progCond.Status)
		assert.Equal(t, reasonVersionChanged, progCond.Reason)

		// Second reconcile: no handler, version matches — clears signal
		_, err = rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co = getClusterOperator(fakeClient)
		require.NotNil(t, co)
		progCond, _ = findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		require.NotNil(t, progCond)
		assert.Equal(t, configv1.ConditionFalse, progCond.Status,
			"Progressing should clear on second reconcile")

		// Third reconcile: stays cleared
		_, err = rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co = getClusterOperator(fakeClient)
		require.NotNil(t, co)
		progCond, _ = findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		require.NotNil(t, progCond)
		assert.Equal(t, configv1.ConditionFalse, progCond.Status,
			"Progressing should remain cleared on third reconcile")
	})

	t.Run("second version change while VersionChanged is active", func(t *testing.T) {
		existingCO := testClusterOperator("4.0.0-1", metav1.Time{Time: time.Now().Add(-1 * time.Hour)})
		operatorConfig := testOperatorConfig("")
		cv := testClusterVersion(false)

		clearHandlers()
		defer clearHandlers()

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(existingCO).
			WithRuntimeObjects(existingCO, operatorConfig, cv).Build()

		// First reconcile: version changes to 4.0.0-2
		t.Setenv("RELEASE_VERSION", "4.0.0-2")

		rs := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", "teststatus"),
			platform: configv1.AWSPlatformType,
		}
		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)
		progCond, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		require.NotNil(t, progCond)
		assert.Equal(t, configv1.ConditionTrue, progCond.Status)
		assert.Equal(t, reasonVersionChanged, progCond.Reason)
		firstTransitionTime := progCond.LastTransitionTime

		// Second reconcile: version changes again to 4.0.0-3
		t.Setenv("RELEASE_VERSION", "4.0.0-3")

		_, err = rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co = getClusterOperator(fakeClient)
		require.NotNil(t, co)
		progCond, _ = findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		require.NotNil(t, progCond)
		assert.Equal(t, configv1.ConditionTrue, progCond.Status,
			"Progressing should stay True after second version change")
		assert.Equal(t, reasonVersionChanged, progCond.Reason)
		// LastTransitionTime should NOT be reset because it was already True
		assert.Equal(t, firstTransitionTime.Time.Unix(), progCond.LastTransitionTime.Time.Unix(),
			"LastTransitionTime should NOT be reset on second version change while already Progressing=True")
	})
}

// ================================================================
// Degraded condition
// ================================================================

func TestDegraded(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	// ---- ProgressingTooLong table-driven cases ----

	progressingTooLongTests := []struct {
		name                       string
		progressingSince           time.Duration
		handlerSetsProgressing     bool
		handlerSetsDegraded        bool
		existingDegraded           bool
		existingDegradedTransition metav1.Time
		expectDegraded             bool
		expectDegradedReason       string
		expectTransitionPreserved  bool
	}{
		{
			name:                   "within 20min window: Progressing=True, Degraded=False",
			progressingSince:       10 * time.Minute,
			handlerSetsProgressing: true,
			expectDegraded:         false,
		},
		{
			name:                   "progressing for 25 minutes does not set Degraded",
			progressingSince:       25 * time.Minute,
			handlerSetsProgressing: true,
			expectDegraded:         false,
		},
		{
			name:                   "not degraded when not progressing even after 25 minutes",
			progressingSince:       25 * time.Minute,
			handlerSetsProgressing: false,
			expectDegraded:         false,
		},
		{
			name:                   "handler Degraded reason preserved over ProgressingTooLong",
			progressingSince:       25 * time.Minute,
			handlerSetsProgressing: true,
			handlerSetsDegraded:    true,
			expectDegraded:         true,
			expectDegradedReason:   "HandlerDegradedReason",
		},
		{
			name:                   "previously Degraded clears when no handler reports degraded",
			progressingSince:       25 * time.Minute,
			handlerSetsProgressing: true,
			existingDegraded:       true,
			existingDegradedTransition: metav1.Time{
				Time: time.Now().Add(-10 * time.Minute),
			},
			expectDegraded: false,
		},
	}

	for _, test := range progressingTooLongTests {
		t.Run(test.name, func(t *testing.T) {
			progressingTransition := metav1.Time{
				Time: time.Now().Add(-test.progressingSince),
			}

			existingConditions := []configv1.ClusterOperatorStatusCondition{
				{
					Type:               configv1.OperatorProgressing,
					Status:             configv1.ConditionTrue,
					Reason:             "Reconciling",
					LastTransitionTime: progressingTransition,
				},
			}
			if test.existingDegraded {
				existingConditions = append(existingConditions, configv1.ClusterOperatorStatusCondition{
					Type:               configv1.OperatorDegraded,
					Status:             configv1.ConditionTrue,
					Reason:             "SomePriorDegradedReason",
					LastTransitionTime: test.existingDegradedTransition,
				})
			}

			existingCO := &configv1.ClusterOperator{
				ObjectMeta: metav1.ObjectMeta{
					Name: constants.CloudCredClusterOperatorName,
				},
				Status: configv1.ClusterOperatorStatus{
					Versions: []configv1.OperandVersion{
						{Name: "operator", Version: "ANYVERSION"},
					},
					Conditions: existingConditions,
				},
			}

			operatorConfig := testOperatorConfig("")
			objects := []runtime.Object{existingCO, operatorConfig}
			objects = append(objects, testClusterVersion(false))

			clearHandlers()
			if test.handlerSetsProgressing {
				AddHandler("test-progressing", newHandler("test-progressing", []configv1.ClusterOperatorStatusCondition{
					{
						Type:   configv1.OperatorProgressing,
						Status: configv1.ConditionTrue,
						Reason: "Reconciling",
					},
				}))
			}
			if test.handlerSetsDegraded {
				AddHandler("test-degraded", newHandler("test-degraded", []configv1.ClusterOperatorStatusCondition{
					{
						Type:    configv1.OperatorDegraded,
						Status:  configv1.ConditionTrue,
						Reason:  "HandlerDegradedReason",
						Message: "handler set this degraded condition",
					},
				}))
			}
			defer clearHandlers()

			fakeClient := fake.NewClientBuilder().
				WithStatusSubresource(existingCO).
				WithRuntimeObjects(objects...).Build()

			t.Setenv("RELEASE_VERSION", "ANYVERSION")

			rs := &ReconcileStatus{
				Client:   fakeClient,
				Logger:   log.WithField("controller", "teststatus"),
				platform: configv1.AWSPlatformType,
			}
			_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
			require.NoError(t, err)

			co := getClusterOperator(fakeClient)
			require.NotNil(t, co)

			// For the "within window" case, also verify Progressing is True
			if test.handlerSetsProgressing && !test.expectDegraded {
				progCond, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
				require.NotNil(t, progCond)
				assert.Equal(t, configv1.ConditionTrue, progCond.Status,
					"Progressing should be True while handler reports it")
			}

			degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
			if test.expectDegraded {
				require.NotNil(t, degraded, "expected Degraded condition to be set")
				assert.Equal(t, configv1.ConditionTrue, degraded.Status)
				assert.Equal(t, test.expectDegradedReason, degraded.Reason)
				if test.expectTransitionPreserved {
					assert.Equal(t, test.existingDegradedTransition.Time.Unix(), degraded.LastTransitionTime.Time.Unix(),
						"Degraded LastTransitionTime should be preserved when already Degraded=True")
				}
			} else {
				if degraded != nil {
					assert.Equal(t, configv1.ConditionFalse, degraded.Status,
						"expected Degraded=False but got %s with reason %s", degraded.Status, degraded.Reason)
				}
			}
		})
	}

	// ---- Boundary and edge cases ----

	boundaryTests := []struct {
		name             string
		progressingSince time.Duration
		zeroTransition   bool
		expectDegraded   bool
	}{
		{
			// Use 19m59s: the code checks > 20m, so 19m59s should NOT trigger.
			name:             "boundary: just under 20 minutes - NOT degraded",
			progressingSince: 19*time.Minute + 59*time.Second,
			expectDegraded:   false,
		},
		{
			name:             "boundary: 20 minutes + 1 second - NOT degraded",
			progressingSince: 20*time.Minute + 1*time.Second,
			expectDegraded:   false,
		},
		{
			name:           "zero LastTransitionTime prevents timeout",
			zeroTransition: true,
			expectDegraded: false,
		},
	}

	for _, test := range boundaryTests {
		t.Run(test.name, func(t *testing.T) {
			var progressingTransition metav1.Time
			if test.zeroTransition {
				progressingTransition = metav1.Time{}
			} else {
				progressingTransition = metav1.Time{
					Time: time.Now().Add(-test.progressingSince),
				}
			}

			existingCO := &configv1.ClusterOperator{
				ObjectMeta: metav1.ObjectMeta{
					Name: constants.CloudCredClusterOperatorName,
				},
				Status: configv1.ClusterOperatorStatus{
					Versions: []configv1.OperandVersion{
						{Name: "operator", Version: "ANYVERSION"},
					},
					Conditions: []configv1.ClusterOperatorStatusCondition{
						{
							Type:               configv1.OperatorProgressing,
							Status:             configv1.ConditionTrue,
							Reason:             "Reconciling",
							LastTransitionTime: progressingTransition,
						},
					},
				},
			}

			operatorConfig := testOperatorConfig("")
			cv := testClusterVersion(false)

			clearHandlers()
			AddHandler("test-progressing", newHandler("test-progressing", []configv1.ClusterOperatorStatusCondition{
				{
					Type:   configv1.OperatorProgressing,
					Status: configv1.ConditionTrue,
					Reason: "Reconciling",
				},
			}))
			defer clearHandlers()

			fakeClient := fake.NewClientBuilder().
				WithStatusSubresource(existingCO).
				WithRuntimeObjects(existingCO, operatorConfig, cv).Build()

			t.Setenv("RELEASE_VERSION", "ANYVERSION")

			rs := &ReconcileStatus{
				Client:   fakeClient,
				Logger:   log.WithField("controller", "teststatus"),
				platform: configv1.AWSPlatformType,
			}
			_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
			require.NoError(t, err)

			co := getClusterOperator(fakeClient)
			require.NotNil(t, co)

			degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
			if degraded != nil {
				assert.Equal(t, configv1.ConditionFalse, degraded.Status,
					"expected Degraded=False but got %s with reason %s", degraded.Status, degraded.Reason)
			}
		})
	}

	// ---- Individual subtests ----

	t.Run("long Progressing does not set Degraded", func(t *testing.T) {
		progressingTransition := metav1.Time{
			Time: time.Now().Add(-25 * time.Minute),
		}

		existingCO := &configv1.ClusterOperator{
			ObjectMeta: metav1.ObjectMeta{
				Name: constants.CloudCredClusterOperatorName,
			},
			Status: configv1.ClusterOperatorStatus{
				Versions: []configv1.OperandVersion{
					{Name: "operator", Version: "ANYVERSION"},
				},
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{
						Type:               configv1.OperatorProgressing,
						Status:             configv1.ConditionTrue,
						Reason:             "Reconciling",
						LastTransitionTime: progressingTransition,
					},
				},
			},
		}

		operatorConfig := testOperatorConfig("")
		cv := testClusterVersion(false)

		clearHandlers()
		AddHandler("test-progressing", newHandler("test-progressing", []configv1.ClusterOperatorStatusCondition{
			{
				Type:   configv1.OperatorProgressing,
				Status: configv1.ConditionTrue,
				Reason: "Reconciling",
			},
		}))
		defer clearHandlers()

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(existingCO).
			WithRuntimeObjects(existingCO, operatorConfig, cv).Build()

		t.Setenv("RELEASE_VERSION", "ANYVERSION")

		rs := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", "teststatus"),
			platform: configv1.AWSPlatformType,
		}
		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)

		degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		if degraded != nil {
			assert.Equal(t, configv1.ConditionFalse, degraded.Status,
				"Degraded should be False — ProgressingTooLong mechanism has been removed")
		}
	})

	t.Run("Sticky VersionChanged clears when no handler reports progress", func(t *testing.T) {
		// If a version change produced no handler-level progress after one
		// reconcile cycle, the synthetic VersionChanged signal should clear
		// rather than persisting until ProgressingTooLong fires.
		twentyFiveMinutesAgo := metav1.Time{
			Time: time.Now().Add(-25 * time.Minute),
		}

		existingCO := &configv1.ClusterOperator{
			ObjectMeta: metav1.ObjectMeta{
				Name: constants.CloudCredClusterOperatorName,
			},
			Status: configv1.ClusterOperatorStatus{
				Versions: []configv1.OperandVersion{
					{Name: "operator", Version: "ANYVERSION"},
				},
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{
						Type:               configv1.OperatorProgressing,
						Status:             configv1.ConditionTrue,
						Reason:             reasonVersionChanged,
						LastTransitionTime: twentyFiveMinutesAgo,
					},
				},
			},
		}

		operatorConfig := testOperatorConfig("")
		cv := testClusterVersion(false)

		clearHandlers()
		defer clearHandlers()

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(existingCO).
			WithRuntimeObjects(existingCO, operatorConfig, cv).Build()

		t.Setenv("RELEASE_VERSION", "ANYVERSION")

		rs := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", "teststatus"),
			platform: configv1.AWSPlatformType,
		}
		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)

		// VersionChanged should have cleared since no handler reported progress.
		progCond, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		require.NotNil(t, progCond)
		assert.Equal(t, configv1.ConditionFalse, progCond.Status)

		// Degraded should not fire — the version change was a no-op.
		degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionFalse, degraded.Status)
	})

	t.Run("handler takes over from VersionChanged but no Degraded without handler degraded signal", func(t *testing.T) {
		// Even if a handler reports Progressing=True after a version change
		// and 25 minutes have elapsed, Degraded should NOT fire without a
		// handler explicitly reporting Degraded.
		twentyFiveMinutesAgo := metav1.Time{
			Time: time.Now().Add(-25 * time.Minute),
		}

		existingCO := &configv1.ClusterOperator{
			ObjectMeta: metav1.ObjectMeta{
				Name: constants.CloudCredClusterOperatorName,
			},
			Status: configv1.ClusterOperatorStatus{
				Versions: []configv1.OperandVersion{
					{Name: "operator", Version: "ANYVERSION"},
				},
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{
						Type:               configv1.OperatorProgressing,
						Status:             configv1.ConditionTrue,
						Reason:             reasonVersionChanged,
						LastTransitionTime: twentyFiveMinutesAgo,
					},
				},
			},
		}

		operatorConfig := testOperatorConfig("")
		cv := testClusterVersion(false)

		clearHandlers()
		// A handler is actively reporting progress.
		AddHandler("test-progressing", newHandler("test-progressing", []configv1.ClusterOperatorStatusCondition{
			{
				Type:   configv1.OperatorProgressing,
				Status: configv1.ConditionTrue,
				Reason: "Reconciling",
			},
		}))
		defer clearHandlers()

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(existingCO).
			WithRuntimeObjects(existingCO, operatorConfig, cv).Build()

		t.Setenv("RELEASE_VERSION", "ANYVERSION")

		rs := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", "teststatus"),
			platform: configv1.AWSPlatformType,
		}
		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)

		// Handler took over — Progressing stays True with handler's reason.
		progCond, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		require.NotNil(t, progCond)
		assert.Equal(t, configv1.ConditionTrue, progCond.Status)
		assert.Equal(t, "Reconciling", progCond.Reason)

		// Degraded should NOT fire — ProgressingTooLong mechanism is removed.
		degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		if degraded != nil {
			assert.Equal(t, configv1.ConditionFalse, degraded.Status,
				"Degraded should be False — no handler reported degraded")
		}
	})

	t.Run("LastTransitionTime preserved on reason change", func(t *testing.T) {
		basicCO := testBasicClusterOperator()
		operatorConfig := testOperatorConfig("")
		cv := testClusterVersion(false)

		clearHandlers()
		AddHandler("test-degraded", newHandler("test-degraded", []configv1.ClusterOperatorStatusCondition{
			{
				Type:    configv1.OperatorDegraded,
				Status:  configv1.ConditionTrue,
				Reason:  "ReasonA",
				Message: "first reason",
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

		// First reconcile: Degraded=True with ReasonA
		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)
		degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionTrue, degraded.Status)
		assert.Equal(t, "ReasonA", degraded.Reason)
		firstTransitionTime := degraded.LastTransitionTime

		// Change handler to report ReasonB
		clearHandlers()
		AddHandler("test-degraded", newHandler("test-degraded", []configv1.ClusterOperatorStatusCondition{
			{
				Type:    configv1.OperatorDegraded,
				Status:  configv1.ConditionTrue,
				Reason:  "ReasonB",
				Message: "second reason",
			},
		}))

		// Second reconcile: Degraded=True with ReasonB
		_, err = rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co = getClusterOperator(fakeClient)
		require.NotNil(t, co)
		degraded, _ = findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionTrue, degraded.Status)
		assert.Equal(t, "ReasonB", degraded.Reason)
		assert.Equal(t, firstTransitionTime.Time.Unix(), degraded.LastTransitionTime.Time.Unix(),
			"LastTransitionTime should be preserved when status stays True but reason changes")
	})

	t.Run("transition times correct on True-False-True cycle", func(t *testing.T) {
		// Spec: "a component should not oscillate in and out of Degraded state"
		// Verify that transition times are tracked correctly if it does happen.
		basicCO := testBasicClusterOperator()
		operatorConfig := testOperatorConfig("")
		cv := testClusterVersion(false)

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(basicCO).
			WithRuntimeObjects(basicCO, operatorConfig, cv).Build()

		t.Setenv("RELEASE_VERSION", "ANYVERSION")

		rs := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", "teststatus"),
			platform: configv1.AWSPlatformType,
		}

		// Reconcile 1: handler reports Degraded=True
		clearHandlers()
		AddHandler("test-degraded", newHandler("test-degraded", []configv1.ClusterOperatorStatusCondition{
			{
				Type:    configv1.OperatorDegraded,
				Status:  configv1.ConditionTrue,
				Reason:  "Broken",
				Message: "something broke",
			},
		}))

		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)
		degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionTrue, degraded.Status)

		// Reconcile 2: handler reports Degraded=False (transient recovery)
		clearHandlers()

		_, err = rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co = getClusterOperator(fakeClient)
		require.NotNil(t, co)
		degraded, _ = findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionFalse, degraded.Status,
			"Degraded should be False after transient recovery")

		// Reconcile 3: handler reports Degraded=True again
		AddHandler("test-degraded", newHandler("test-degraded", []configv1.ClusterOperatorStatusCondition{
			{
				Type:    configv1.OperatorDegraded,
				Status:  configv1.ConditionTrue,
				Reason:  "Broken",
				Message: "something broke again",
			},
		}))
		defer clearHandlers()

		_, err = rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co = getClusterOperator(fakeClient)
		require.NotNil(t, co)
		degraded, _ = findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionTrue, degraded.Status)

		// The final LastTransitionTime should reflect the most recent False→True
		// transition, not the original.
		assert.True(t, time.Since(degraded.LastTransitionTime.Time) < 5*time.Second,
			"LastTransitionTime should be fresh after False->True transition, got %v",
			degraded.LastTransitionTime.Time)
	})
}

// ================================================================
// Upgradeable condition
// ================================================================

func TestUpgradeable(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	t.Run("defaults to True with reason AsExpected when no handler sets it", func(t *testing.T) {
		basicCO := testBasicClusterOperator()
		operatorConfig := testOperatorConfig("")
		cv := testClusterVersion(false)

		clearHandlers()
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
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)

		upgradeable, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorUpgradeable)
		require.NotNil(t, upgradeable)
		assert.Equal(t, configv1.ConditionTrue, upgradeable.Status)
		assert.Equal(t, "AsExpected", upgradeable.Reason)
	})

	t.Run("handler sets Upgradeable=False with non-empty message", func(t *testing.T) {
		basicCO := testBasicClusterOperator()
		operatorConfig := testOperatorConfig("")
		cv := testClusterVersion(false)

		clearHandlers()
		AddHandler("test-upgradeable", newHandler("test-upgradeable", []configv1.ClusterOperatorStatusCondition{
			{
				Type:    configv1.OperatorUpgradeable,
				Status:  configv1.ConditionFalse,
				Reason:  "NotReady",
				Message: "upgrade is blocked due to pending changes",
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
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)

		upgradeable, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorUpgradeable)
		require.NotNil(t, upgradeable)
		assert.Equal(t, configv1.ConditionFalse, upgradeable.Status)
		assert.NotEmpty(t, upgradeable.Message, "Upgradeable=False should have a non-empty message")
	})
}
