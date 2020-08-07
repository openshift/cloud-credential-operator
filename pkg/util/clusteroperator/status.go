package clusteroperator

import (
	configv1 "github.com/openshift/api/config/v1"
	log "github.com/sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	msgConfigConflict = "Conflict between legacy configmap and operator config"
)

/*
// ClearHandlers so that test cases don't endlessly add handlers
func ClearHandlers() {
	statusHandlers = []StatusHandler{}
}
*/

// SetStatusCondition returns the result of setting the specified condition in
// the given slice of conditions.
func SetStatusCondition(oldConditions []configv1.ClusterOperatorStatusCondition, condition *configv1.ClusterOperatorStatusCondition) []configv1.ClusterOperatorStatusCondition {
	condition.LastTransitionTime = metav1.Now()

	log.Debug("new condition: %v", condition)
	newConditions := []configv1.ClusterOperatorStatusCondition{}

	found := false
	for _, c := range oldConditions {
		if condition.Type == c.Type {
			if condition.Status == c.Status &&
				condition.Reason == c.Reason &&
				condition.Message == c.Message {
				log.Debug("condition unchanged")
				return oldConditions
			}

			log.Debug("condition changed")
			found = true
			newConditions = append(newConditions, *condition)
		} else {
			log.Debug("preserving another condition: %v", c)
			newConditions = append(newConditions, c)
		}
	}
	if !found {
		log.Debug("condition is new")
		newConditions = append(newConditions, *condition)
	}

	return newConditions
}

// ConditionsEqual returns true if and only if the provided slices of conditions
// (ignoring LastTransitionTime) are equal.
func ConditionsEqual(oldConditions, newConditions []configv1.ClusterOperatorStatusCondition) bool {
	if len(newConditions) != len(oldConditions) {
		return false
	}

	for _, conditionA := range oldConditions {
		foundMatchingCondition := false

		for _, conditionB := range newConditions {
			// Compare every field except LastTransitionTime.
			if conditionA.Type == conditionB.Type &&
				conditionA.Status == conditionB.Status &&
				conditionA.Reason == conditionB.Reason &&
				conditionA.Message == conditionB.Message {
				foundMatchingCondition = true
				break
			}
		}

		if !foundMatchingCondition {
			return false
		}
	}

	return true
}
