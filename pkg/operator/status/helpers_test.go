package status

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
)

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
					Reason:             "AsExpected",
					Message:            "All is well",
					LastTransitionTime: progressingLastTransition,
				},
			},
		},
	}
}

func testClusterVersion(upgrading bool) *configv1.ClusterVersion {
	progressingStatus := configv1.ConditionFalse
	if upgrading {
		progressingStatus = configv1.ConditionTrue
	}
	return &configv1.ClusterVersion{
		ObjectMeta: metav1.ObjectMeta{
			Name: "version",
		},
		Status: configv1.ClusterVersionStatus{
			Conditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:   configv1.OperatorProgressing,
					Status: progressingStatus,
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

// errorHandler is a Handler that always returns an error from GetConditions.
type errorHandler struct {
	name string
}

func (h *errorHandler) GetConditions(log.FieldLogger) ([]configv1.ClusterOperatorStatusCondition, error) {
	return nil, fmt.Errorf("simulated handler error")
}

func (h *errorHandler) GetRelatedObjects(log.FieldLogger) ([]configv1.ObjectReference, error) {
	return nil, nil
}

func (h *errorHandler) Name() string {
	return h.name
}
