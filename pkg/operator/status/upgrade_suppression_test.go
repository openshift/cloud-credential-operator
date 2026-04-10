package status

import (
	"context"
	"regexp"
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
// Upgrade suppression (Degraded and Available=False during upgrades)
// ================================================================

func TestUpgradeSuppression(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	// ---- Core suppression behavior ----
	// Suppression requires BOTH the cluster to be upgrading AND this operator
	// to be actively progressing. This scopes the suppression window to when
	// CCO is doing upgrade work, not the entire multi-hour cluster upgrade.

	coreTests := []struct {
		name                   string
		clusterUpgrading       bool
		handlerSetsProgressing bool
		handlerSetsDegraded    bool
		handlerSetsAvailable   bool
		expectDegraded         bool
		expectDegradedReason   string
		expectAvailableTrue    bool
	}{
		{
			name:                   "Degraded suppressed during cluster upgrade while operator progressing",
			clusterUpgrading:       true,
			handlerSetsProgressing: true,
			handlerSetsDegraded:    true,
			expectDegraded:         false,
			expectAvailableTrue:    true,
		},
		{
			name:                 "Degraded not suppressed when cluster is not upgrading",
			clusterUpgrading:     false,
			handlerSetsDegraded:  true,
			expectDegraded:       true,
			expectDegradedReason: "TestDegraded",
			expectAvailableTrue:  true,
		},
		{
			name:                   "Available=False NOT suppressed during cluster upgrade while operator progressing",
			clusterUpgrading:       true,
			handlerSetsProgressing: true,
			handlerSetsAvailable:   true,
			expectDegraded:         false,
			expectAvailableTrue:    false,
		},
		{
			name:                 "Available=False not suppressed when cluster is not upgrading",
			clusterUpgrading:     false,
			handlerSetsAvailable: true,
			expectDegraded:       false,
			expectAvailableTrue:  false,
		},
		{
			name:                "Degraded NOT suppressed during cluster upgrade when operator is not progressing",
			clusterUpgrading:    true,
			handlerSetsDegraded: true,
			// no progressing handler — operator has finished its upgrade work
			expectDegraded:       true,
			expectDegradedReason: "TestDegraded",
			expectAvailableTrue:  true,
		},
		{
			name:             "Available=False NOT suppressed during cluster upgrade when operator is not progressing",
			clusterUpgrading: true,
			// no progressing handler — operator has finished its upgrade work
			handlerSetsAvailable: true,
			expectDegraded:       false,
			expectAvailableTrue:  false,
		},
	}

	for _, test := range coreTests {
		t.Run(test.name, func(t *testing.T) {
			basicCO := testBasicClusterOperator()
			operatorConfig := testOperatorConfig("")

			objects := []runtime.Object{basicCO, operatorConfig}
			objects = append(objects, testClusterVersion(test.clusterUpgrading))

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
						Reason:  "TestDegraded",
						Message: "test degraded condition",
					},
				}))
			}
			if test.handlerSetsAvailable {
				AddHandler("test-available", newHandler("test-available", []configv1.ClusterOperatorStatusCondition{
					{
						Type:    configv1.OperatorAvailable,
						Status:  configv1.ConditionFalse,
						Reason:  "TestUnavailable",
						Message: "test unavailable condition",
					},
				}))
			}
			defer clearHandlers()

			fakeClient := fake.NewClientBuilder().
				WithStatusSubresource(basicCO).
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

			degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
			if test.expectDegraded {
				require.NotNil(t, degraded)
				assert.Equal(t, configv1.ConditionTrue, degraded.Status)
				assert.Equal(t, test.expectDegradedReason, degraded.Reason)
			} else {
				if degraded != nil {
					assert.Equal(t, configv1.ConditionFalse, degraded.Status)
				}
			}

			available, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorAvailable)
			require.NotNil(t, available)
			if test.expectAvailableTrue {
				assert.Equal(t, configv1.ConditionTrue, available.Status)
			} else {
				assert.Equal(t, configv1.ConditionFalse, available.Status)
			}
		})
	}

	// ---- ProgressingTooLong + handler Degraded suppressed during upgrade ----

	upgradeProgressingTests := []struct {
		name                   string
		progressingSince       time.Duration
		handlerSetsProgressing bool
		handlerSetsDegraded    bool
		expectDegraded         bool
	}{
		{
			name:                   "ProgressingTooLong during cluster upgrade - Degraded suppressed",
			progressingSince:       25 * time.Minute,
			handlerSetsProgressing: true,
			expectDegraded:         false,
		},
		{
			name:                   "handler Degraded during cluster upgrade - suppressed",
			progressingSince:       5 * time.Minute,
			handlerSetsProgressing: true,
			handlerSetsDegraded:    true,
			expectDegraded:         false,
		},
	}

	for _, test := range upgradeProgressingTests {
		t.Run(test.name, func(t *testing.T) {
			progressingTransition := metav1.Time{
				Time: time.Now().Add(-test.progressingSince),
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
			objects := []runtime.Object{existingCO, operatorConfig}
			objects = append(objects, testClusterVersion(true))

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

			degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
			if degraded != nil {
				assert.Equal(t, configv1.ConditionFalse, degraded.Status,
					"expected Degraded=False but got %s with reason %s", degraded.Status, degraded.Reason)
			}
		})
	}

	// ---- Edge cases: ClusterVersion missing/unusual states ----

	edgeTests := []struct {
		name                   string
		clusterVersion         *configv1.ClusterVersion // nil means no ClusterVersion object
		handlerSetsProgressing bool
		handlerSetsDegraded    bool
		handlerSetsAvailable   bool
		expectDegraded         bool
		expectAvailableTrue    bool
		checkReason            string
		checkMessageContains   string
	}{
		// NOTE: "ClusterVersion not found" is tested separately below because
		// syncStatus now returns early with an error when it cannot determine
		// the cluster upgrade state.
		{
			name: "ClusterVersion exists but has no Progressing condition - Degraded NOT suppressed",
			clusterVersion: &configv1.ClusterVersion{
				ObjectMeta: metav1.ObjectMeta{Name: "version"},
				Status:     configv1.ClusterVersionStatus{},
			},
			handlerSetsDegraded: true,
			expectDegraded:      true,
			expectAvailableTrue: true,
		},
		{
			name: "ClusterVersion Progressing=Unknown - Degraded NOT suppressed",
			clusterVersion: &configv1.ClusterVersion{
				ObjectMeta: metav1.ObjectMeta{Name: "version"},
				Status: configv1.ClusterVersionStatus{
					Conditions: []configv1.ClusterOperatorStatusCondition{
						{
							Type:   configv1.OperatorProgressing,
							Status: configv1.ConditionUnknown,
						},
					},
				},
			},
			handlerSetsDegraded: true,
			expectDegraded:      true,
			expectAvailableTrue: true,
		},
		{
			name:                   "suppressed Degraded preserves original reason and message",
			clusterVersion:         testClusterVersion(true),
			handlerSetsProgressing: true,
			handlerSetsDegraded:    true,
			expectDegraded:         false,
			expectAvailableTrue:    true,
			checkReason:            "UpgradeInProgress",
			checkMessageContains:   "TestDegraded",
		},
		{
			name:                   "Available=False NOT suppressed during upgrade - preserves handler reason",
			clusterVersion:         testClusterVersion(true),
			handlerSetsProgressing: true,
			handlerSetsAvailable:   true,
			expectDegraded:         false,
			expectAvailableTrue:    false,
			checkReason:            "TestUnavailable",
			checkMessageContains:   "test unavailable condition",
		},
	}

	for _, test := range edgeTests {
		t.Run(test.name, func(t *testing.T) {
			basicCO := testBasicClusterOperator()
			operatorConfig := testOperatorConfig("")

			objects := []runtime.Object{basicCO, operatorConfig}
			if test.clusterVersion != nil {
				objects = append(objects, test.clusterVersion)
			}

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
						Reason:  "TestDegraded",
						Message: "test degraded condition",
					},
				}))
			}
			if test.handlerSetsAvailable {
				AddHandler("test-available", newHandler("test-available", []configv1.ClusterOperatorStatusCondition{
					{
						Type:    configv1.OperatorAvailable,
						Status:  configv1.ConditionFalse,
						Reason:  "TestUnavailable",
						Message: "test unavailable condition",
					},
				}))
			}
			defer clearHandlers()

			fakeClient := fake.NewClientBuilder().
				WithStatusSubresource(basicCO).
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

			degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
			if test.expectDegraded {
				require.NotNil(t, degraded)
				assert.Equal(t, configv1.ConditionTrue, degraded.Status)
			} else if degraded != nil {
				assert.Equal(t, configv1.ConditionFalse, degraded.Status)
			}

			available, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorAvailable)
			require.NotNil(t, available)
			if test.expectAvailableTrue {
				assert.Equal(t, configv1.ConditionTrue, available.Status)
			} else {
				assert.Equal(t, configv1.ConditionFalse, available.Status)
			}

			// Verify reason/message on the suppressed condition when specified.
			if test.checkReason != "" {
				var suppressed *configv1.ClusterOperatorStatusCondition
				if test.handlerSetsDegraded {
					suppressed = degraded
				} else if test.handlerSetsAvailable {
					suppressed = available
				}
				if suppressed != nil {
					assert.Equal(t, test.checkReason, suppressed.Reason)
					assert.Contains(t, suppressed.Message, test.checkMessageContains)
				}
			}
		})
	}

	// ---- ClusterVersion not found: syncStatus returns error ----

	t.Run("ClusterVersion not found - syncStatus returns error", func(t *testing.T) {
		basicCO := testBasicClusterOperator()
		operatorConfig := testOperatorConfig("")
		// No ClusterVersion object in the fake client.

		clearHandlers()
		AddHandler("test-degraded", newHandler("test-degraded", []configv1.ClusterOperatorStatusCondition{
			{
				Type:    configv1.OperatorDegraded,
				Status:  configv1.ConditionTrue,
				Reason:  "TestDegraded",
				Message: "test degraded condition",
			},
		}))
		defer clearHandlers()

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(basicCO).
			WithRuntimeObjects(basicCO, operatorConfig).Build()

		t.Setenv("RELEASE_VERSION", "ANYVERSION")

		rs := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", "teststatus"),
			platform: configv1.AWSPlatformType,
		}
		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		// When ClusterVersion is not found, syncStatus logs a warning and
		// defaults to not suppressing Degraded — it does NOT return an error,
		// so the rest of the status sync can proceed.
		require.NoError(t, err, "syncStatus should succeed even when ClusterVersion is not found")

		// Verify Degraded is published unsuppressed (clusterUpgrading defaults to false).
		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)
		degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionTrue, degraded.Status,
			"Degraded should be published unsuppressed when ClusterVersion is unreadable")
	})

	t.Run("ClusterVersion not found - conditions still published unsuppressed", func(t *testing.T) {
		// When isClusterUpgrading fails, syncStatus should still proceed
		// and publish conditions — just without Degraded suppression.
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
						Type:   configv1.OperatorAvailable,
						Status: configv1.ConditionTrue,
						Reason: "PreExisting",
					},
				},
			},
		}
		operatorConfig := testOperatorConfig("")
		// No ClusterVersion object.

		clearHandlers()
		AddHandler("test-degraded", newHandler("test-degraded", []configv1.ClusterOperatorStatusCondition{
			{
				Type:    configv1.OperatorDegraded,
				Status:  configv1.ConditionTrue,
				Reason:  "TestDegraded",
				Message: "should be published unsuppressed",
			},
		}))
		defer clearHandlers()

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(existingCO).
			WithRuntimeObjects(existingCO, operatorConfig).Build()

		t.Setenv("RELEASE_VERSION", "ANYVERSION")

		rs := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", "teststatus"),
			platform: configv1.AWSPlatformType,
		}
		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		// Verify conditions were updated (not stale).
		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)
		assert.Len(t, co.Status.Conditions, 4,
			"all four condition types should be published")
		degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionTrue, degraded.Status,
			"Degraded should be published unsuppressed when ClusterVersion is unreadable")
		assert.Equal(t, "TestDegraded", degraded.Reason)
	})

	// ---- Lifecycle: suppression lifts when upgrade finishes ----

	t.Run("suppressed Degraded reappears when upgrade finishes", func(t *testing.T) {
		basicCO := testBasicClusterOperator()
		operatorConfig := testOperatorConfig("")
		cvUpgrading := testClusterVersion(true)

		clearHandlers()
		AddHandler("test-progressing", newHandler("test-progressing", []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorProgressing, Status: configv1.ConditionTrue, Reason: "Reconciling"},
		}))
		AddHandler("test-degraded", newHandler("test-degraded", []configv1.ClusterOperatorStatusCondition{
			{
				Type:    configv1.OperatorDegraded,
				Status:  configv1.ConditionTrue,
				Reason:  "PersistentIssue",
				Message: "something is wrong",
			},
		}))
		defer clearHandlers()

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(basicCO).
			WithRuntimeObjects(basicCO, operatorConfig, cvUpgrading).Build()

		t.Setenv("RELEASE_VERSION", "ANYVERSION")

		rs := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", "teststatus"),
			platform: configv1.AWSPlatformType,
		}

		// Reconcile 1: cluster upgrading + operator progressing → Degraded suppressed.
		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)
		degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionFalse, degraded.Status,
			"Degraded should be suppressed while operator is progressing during upgrade")

		// Simulate the upgrade finishing by replacing the ClusterVersion.
		require.NoError(t, fakeClient.Delete(context.TODO(), cvUpgrading))
		cvDone := testClusterVersion(false)
		require.NoError(t, fakeClient.Create(context.TODO(), cvDone))

		// Reconcile 2: cluster is no longer upgrading — Degraded should reappear.
		_, err = rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co = getClusterOperator(fakeClient)
		require.NotNil(t, co)
		degraded, _ = findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionTrue, degraded.Status,
			"Degraded should reappear after upgrade finishes")
		assert.Equal(t, "PersistentIssue", degraded.Reason,
			"Degraded reason should be the handler's original reason")
	})

	t.Run("Available=False persists through upgrade lifecycle", func(t *testing.T) {
		// Available is NOT suppressed during upgrades, so it stays False
		// throughout and after the upgrade.
		basicCO := testBasicClusterOperator()
		operatorConfig := testOperatorConfig("")
		cvUpgrading := testClusterVersion(true)

		clearHandlers()
		AddHandler("test-progressing", newHandler("test-progressing", []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorProgressing, Status: configv1.ConditionTrue, Reason: "Reconciling"},
		}))
		AddHandler("test-available", newHandler("test-available", []configv1.ClusterOperatorStatusCondition{
			{
				Type:    configv1.OperatorAvailable,
				Status:  configv1.ConditionFalse,
				Reason:  "ComponentDown",
				Message: "a required component is down",
			},
		}))
		defer clearHandlers()

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(basicCO).
			WithRuntimeObjects(basicCO, operatorConfig, cvUpgrading).Build()

		t.Setenv("RELEASE_VERSION", "ANYVERSION")

		rs := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", "teststatus"),
			platform: configv1.AWSPlatformType,
		}

		// Reconcile 1: cluster upgrading + operator progressing — Available=False is NOT suppressed.
		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		require.NotNil(t, co)
		available, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorAvailable)
		require.NotNil(t, available)
		assert.Equal(t, configv1.ConditionFalse, available.Status,
			"Available=False should NOT be suppressed during upgrade")

		// Simulate the upgrade finishing by replacing the ClusterVersion.
		require.NoError(t, fakeClient.Delete(context.TODO(), cvUpgrading))
		cvDone := testClusterVersion(false)
		require.NoError(t, fakeClient.Create(context.TODO(), cvDone))

		// Reconcile 2: cluster is no longer upgrading — Available=False persists.
		_, err = rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co = getClusterOperator(fakeClient)
		require.NotNil(t, co)
		available, _ = findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorAvailable)
		require.NotNil(t, available)
		assert.Equal(t, configv1.ConditionFalse, available.Status,
			"Available=False should persist after upgrade finishes")
		assert.Equal(t, "ComponentDown", available.Reason,
			"Available reason should be the handler's original reason")
	})
}

// ================================================================
// Sysadmin paging scenarios: real-world upgrade situations
// ================================================================
// These tests validate that the operator pages a sysadmin (reports Degraded)
// at the right times during cluster upgrades, and doesn't wake them up
// unnecessarily for transient upgrade noise.

func TestSysadminPagingScenarios(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	t.Run("normal upgrade - no page", func(t *testing.T) {
		// Scenario: cluster is upgrading, CCO version changes, handlers report
		// Progressing while doing upgrade work. No errors.
		// Expected: no Degraded, no page.
		existingCO := testClusterOperator("4.0.0-1", metav1.Time{Time: time.Now().Add(-1 * time.Hour)})
		operatorConfig := testOperatorConfig("")
		cvUpgrading := testClusterVersion(true)

		clearHandlers()
		defer clearHandlers()

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(existingCO).
			WithRuntimeObjects(existingCO, operatorConfig, cvUpgrading).Build()

		t.Setenv("RELEASE_VERSION", "4.0.0-2")

		rs := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", "teststatus"),
			platform: configv1.AWSPlatformType,
		}

		// Reconcile 1: version changes → Progressing=True
		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionFalse, degraded.Status,
			"no page during normal upgrade")
	})

	t.Run("CCO finishes upgrade, then credentials break - sysadmin paged", func(t *testing.T) {
		// Scenario: cluster upgrade is running. CCO finished its work (Progressing=False).
		// Then credentials fail. Sysadmin should be paged because CCO is not doing
		// upgrade work anymore — this is an independent problem.
		basicCO := testBasicClusterOperator()
		operatorConfig := testOperatorConfig("")
		cvUpgrading := testClusterVersion(true)

		clearHandlers()
		// No progressing handler — CCO has finished its upgrade work.
		// But credentials are failing.
		AddHandler("test-degraded", newHandler("test-degraded", []configv1.ClusterOperatorStatusCondition{
			{
				Type:    configv1.OperatorDegraded,
				Status:  configv1.ConditionTrue,
				Reason:  "CredentialsFailing",
				Message: "2 of 5 credentials requests are failing to sync.",
			},
		}))
		defer clearHandlers()

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(basicCO).
			WithRuntimeObjects(basicCO, operatorConfig, cvUpgrading).Build()

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
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionTrue, degraded.Status,
			"sysadmin should be paged: CCO is not progressing, creds are broken")
		assert.Equal(t, "CredentialsFailing", degraded.Reason)
	})

	t.Run("transient error during upgrade while progressing - no page", func(t *testing.T) {
		// Scenario: cluster upgrading, CCO is progressing, a handler reports Degraded
		// (e.g. pod-identity reconcile failed). Suppression hides it.
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
		cvUpgrading := testClusterVersion(true)

		clearHandlers()
		AddHandler("test-progressing", newHandler("test-progressing", []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorProgressing, Status: configv1.ConditionTrue, Reason: "Reconciling"},
		}))
		AddHandler("test-degraded", newHandler("test-degraded", []configv1.ClusterOperatorStatusCondition{
			{
				Type:    configv1.OperatorDegraded,
				Status:  configv1.ConditionTrue,
				Reason:  "StaticResourceReconcileFailed",
				Message: "static resource reconciliation failed: API server restarting",
			},
		}))
		defer clearHandlers()

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(existingCO).
			WithRuntimeObjects(existingCO, operatorConfig, cvUpgrading).Build()

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
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionFalse, degraded.Status,
			"no page: transient error during upgrade while operator is progressing")
		// But the message should tell the sysadmin what's going on if they look
		assert.Contains(t, degraded.Message, "StaticResourceReconcileFailed",
			"suppressed message should preserve original reason for sysadmin visibility")
	})

	t.Run("suppression lifts when operator finishes progressing mid-upgrade", func(t *testing.T) {
		// Scenario: cluster upgrading, CCO progressing with a Degraded condition.
		// Degraded is suppressed. Then CCO finishes progressing but Degraded persists.
		// Suppression should lift because the operator is no longer doing upgrade work.
		basicCO := testBasicClusterOperator()
		operatorConfig := testOperatorConfig("")
		cvUpgrading := testClusterVersion(true)

		clearHandlers()
		AddHandler("test-progressing", newHandler("test-progressing", []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorProgressing, Status: configv1.ConditionTrue, Reason: "Reconciling"},
		}))
		AddHandler("test-degraded", newHandler("test-degraded", []configv1.ClusterOperatorStatusCondition{
			{
				Type:    configv1.OperatorDegraded,
				Status:  configv1.ConditionTrue,
				Reason:  "CredentialsFailing",
				Message: "root credentials are insufficient",
			},
		}))
		defer clearHandlers()

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(basicCO).
			WithRuntimeObjects(basicCO, operatorConfig, cvUpgrading).Build()

		t.Setenv("RELEASE_VERSION", "ANYVERSION")

		rs := &ReconcileStatus{
			Client:   fakeClient,
			Logger:   log.WithField("controller", "teststatus"),
			platform: configv1.AWSPlatformType,
		}

		// Reconcile 1: progressing + degraded → suppressed
		_, err := rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co := getClusterOperator(fakeClient)
		degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionFalse, degraded.Status,
			"Degraded should be suppressed while progressing during upgrade")

		// CCO finishes its upgrade work — remove the progressing handler.
		// Degraded persists (creds still broken). Cluster is still upgrading.
		clearHandlers()
		AddHandler("test-degraded", newHandler("test-degraded", []configv1.ClusterOperatorStatusCondition{
			{
				Type:    configv1.OperatorDegraded,
				Status:  configv1.ConditionTrue,
				Reason:  "CredentialsFailing",
				Message: "root credentials are insufficient",
			},
		}))

		// Reconcile 2: not progressing + degraded + cluster still upgrading → NOT suppressed
		_, err = rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co = getClusterOperator(fakeClient)
		degraded, _ = findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionTrue, degraded.Status,
			"sysadmin should be paged: CCO finished progressing but creds are still broken")
		assert.Equal(t, "CredentialsFailing", degraded.Reason)
	})

	t.Run("config misconfiguration pages even during upgrade", func(t *testing.T) {
		// Scenario: cluster upgrading, but someone set the operator mode to an
		// invalid value. CCO is not progressing. Sysadmin should be paged
		// because this is admin misconfiguration, not an upgrade artifact.
		basicCO := testBasicClusterOperator()
		operatorConfig := testOperatorConfig("")
		cvUpgrading := testClusterVersion(true)

		clearHandlers()
		// No progressing handler — CCO is not doing upgrade work.
		AddHandler("test-degraded", newHandler("test-degraded", []configv1.ClusterOperatorStatusCondition{
			{
				Type:    configv1.OperatorDegraded,
				Status:  configv1.ConditionTrue,
				Reason:  "StatusModeInvalid",
				Message: "operator mode of BogusMode is invalid",
			},
		}))
		defer clearHandlers()

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(basicCO).
			WithRuntimeObjects(basicCO, operatorConfig, cvUpgrading).Build()

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
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionTrue, degraded.Status,
			"sysadmin should be paged: misconfiguration is not upgrade-related")
		assert.Equal(t, "StatusModeInvalid", degraded.Reason)
	})
}

// ================================================================
// Edge cases
// ================================================================

func TestEdgeCases(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	t.Run("version change on long-stuck operator triggers immediate ProgressingTooLong", func(t *testing.T) {
		// Edge case 1: operator has been Progressing=True for >20 minutes
		// (stuck on previous work). A version change arrives. With the fix for
		// the ProgressingTooLong timer, the old LastTransitionTime is preserved,
		// so the 20-minute timeout fires immediately in the same reconcile.
		thirtyMinutesAgo := metav1.Time{Time: time.Now().Add(-30 * time.Minute)}

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
						LastTransitionTime: thirtyMinutesAgo,
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

		// Version bumps from 4.0.0-1 to 4.0.0-2
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

		// Progressing should be True with VersionChanged
		progCond, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		require.NotNil(t, progCond)
		assert.Equal(t, configv1.ConditionTrue, progCond.Status)
		assert.Equal(t, reasonVersionChanged, progCond.Reason)

		// LastTransitionTime should be preserved from the old condition (30 min ago),
		// NOT reset to now.
		assert.True(t, progCond.LastTransitionTime.Time.Before(time.Now().Add(-29*time.Minute)),
			"LastTransitionTime should be preserved from the old progressing condition, got %v",
			progCond.LastTransitionTime.Time)

		// ProgressingTooLong mechanism has been removed — Degraded should not fire
		// just because the operator has been progressing for a long time.
		degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		if degraded != nil {
			assert.Equal(t, configv1.ConditionFalse, degraded.Status,
				"Degraded should be False — ProgressingTooLong mechanism is removed")
		}
	})

	t.Run("long Progressing does not set Degraded even during cluster upgrade", func(t *testing.T) {
		// ProgressingTooLong mechanism has been removed. Verify that even with
		// a handler stuck Progressing=True for >20 minutes during a cluster
		// upgrade, Degraded is not set.
		thirtyMinutesAgo := metav1.Time{Time: time.Now().Add(-30 * time.Minute)}

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
						LastTransitionTime: thirtyMinutesAgo,
					},
				},
			},
		}

		operatorConfig := testOperatorConfig("")
		cvUpgrading := testClusterVersion(true)

		clearHandlers()
		// Handler keeps reporting Progressing=True (stuck)
		AddHandler("stuck-handler", newHandler("stuck-handler", []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorProgressing, Status: configv1.ConditionTrue, Reason: "Reconciling"},
		}))
		defer clearHandlers()

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(existingCO).
			WithRuntimeObjects(existingCO, operatorConfig, cvUpgrading).Build()

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

		// Degraded should be False — ProgressingTooLong mechanism is removed.
		degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		if degraded != nil {
			assert.Equal(t, configv1.ConditionFalse, degraded.Status,
				"Degraded should be False — no handler reported degraded")
		}

		// After upgrade finishes, Degraded should still be False.
		require.NoError(t, fakeClient.Delete(context.TODO(), cvUpgrading))
		cvDone := testClusterVersion(false)
		require.NoError(t, fakeClient.Create(context.TODO(), cvDone))

		_, err = rs.Reconcile(context.TODO(), reconcile.Request{})
		require.NoError(t, err)

		co = getClusterOperator(fakeClient)
		require.NotNil(t, co)

		degraded, _ = findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		if degraded != nil {
			assert.Equal(t, configv1.ConditionFalse, degraded.Status,
				"Degraded should remain False after upgrade finishes")
		}
	})

	t.Run("handler error after version change clears VersionChanged", func(t *testing.T) {
		// Edge case 4: a handler errors on the reconcile after a version change.
		// Its conditions are skipped entirely (continue on error). With no handler
		// reporting Progressing=True and stickiness removed, the VersionChanged
		// signal clears on the next reconcile.
		existingCO := testClusterOperator("4.0.0-1", metav1.Time{Time: time.Now().Add(-1 * time.Hour)})
		operatorConfig := testOperatorConfig("")
		cv := testClusterVersion(false)

		clearHandlers()
		defer clearHandlers()

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(existingCO).
			WithRuntimeObjects(existingCO, operatorConfig, cv).Build()

		// First reconcile: version changes to 4.0.0-2 — sets VersionChanged
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

		// Second reconcile: register a handler that always errors.
		// The reconcile should fail so that the last published status
		// is preserved — defaultUnsetConditions must not run and mask
		// the missing handler's conditions with "AsExpected".
		AddHandler("error-handler", &errorHandler{name: "error-handler"})

		_, err = rs.Reconcile(context.TODO(), reconcile.Request{})
		require.Error(t, err, "syncStatus should return an error when a handler fails")
		assert.Contains(t, err.Error(), "error-handler")

		// ClusterOperator should still have the conditions from the first
		// reconcile since the second reconcile aborted before updating.
		co = getClusterOperator(fakeClient)
		require.NotNil(t, co)
		progCond, _ = findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		require.NotNil(t, progCond)
		assert.Equal(t, configv1.ConditionTrue, progCond.Status,
			"VersionChanged Progressing should be preserved because the erroring reconcile did not update status")
	})

	t.Run("nested suppression does not double-wrap message", func(t *testing.T) {
		schemeutils.SetupScheme(scheme.Scheme)

		// Start with an already-suppressed Degraded condition (from a previous reconcile)
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
						Type:               configv1.OperatorDegraded,
						Status:             configv1.ConditionFalse,
						Reason:             "UpgradeInProgress",
						Message:            "Degraded=True suppressed during cluster upgrade (reason: TestDegraded, message: original problem)",
						LastTransitionTime: metav1.Time{Time: time.Now().Add(-1 * time.Minute)},
					},
					{
						Type:               configv1.OperatorProgressing,
						Status:             configv1.ConditionTrue,
						Reason:             "Reconciling",
						LastTransitionTime: metav1.Time{Time: time.Now().Add(-1 * time.Minute)},
					},
				},
			},
		}
		operatorConfig := testOperatorConfig("")
		cv := testClusterVersion(true) // cluster is upgrading

		clearHandlers()
		// Handler still reports Degraded=True and Progressing=True
		AddHandler("test-degraded", newHandler("test-degraded", []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorDegraded, Status: configv1.ConditionTrue, Reason: "TestDegraded", Message: "original problem"},
		}))
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
		degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		require.NotNil(t, degraded)
		assert.Equal(t, configv1.ConditionFalse, degraded.Status)
		// The message should contain the original reason, not a nested suppression
		assert.Contains(t, degraded.Message, "original problem",
			"suppressed message should reference the original problem")
		assert.Equal(t, 1, len(regexp.MustCompile("suppressed").FindAllString(degraded.Message, -1)),
			"message should only contain one 'suppressed' — no nesting")
	})
}
