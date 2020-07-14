package clusteroperator

import (
<<<<<<< HEAD
	configv1 "github.com/openshift/api/config/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SetStatusCondition returns the result of setting the specified condition in
// the given slice of conditions.
func SetStatusCondition(oldConditions []configv1.ClusterOperatorStatusCondition, condition *configv1.ClusterOperatorStatusCondition) []configv1.ClusterOperatorStatusCondition {
	condition.LastTransitionTime = metav1.Now()
=======
	"context"
	"fmt"
	"os"
	"reflect"

	log "github.com/sirupsen/logrus"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

const (
	cloudCredClusterOperator = "cloud-credential"
	reasonOperatorDisabled   = "OperatorDisabledByAdmin"
	msgOperatorDisabled      = "Credential minting is disabled by cluster admin"
	msgConfigConflict        = "Conflict between legacy configmap and operator config"
)

// StatusHandler produces conditions and related objects to be reflected
// in the cloud-credential-operator ClusterOperatorStatus
type StatusHandler interface {
	GetConditions(logger log.FieldLogger) ([]configv1.ClusterOperatorStatusCondition, error)
	GetRelatedObjects(logger log.FieldLogger) ([]configv1.ObjectReference, error)
	Name() string
}

var (
	statusHandlers = []StatusHandler{}
)

// ClearHandlers so that test cases don't endlessly add handlers
func ClearHandlers() {
	statusHandlers = []StatusHandler{}
}

// AddStatusHandler registers a StatusHandler that will be called whenever
// an update to the ClusterOperator status is requested
func AddStatusHandler(handler StatusHandler) {
	statusHandlers = append(statusHandlers, handler)
}

// SyncStatus syncs the ClusterOperator status by calling all registered
// status handlers for conditions and related objects
func SyncStatus(client client.Client, logger log.FieldLogger) error {
	logger.Info("syncing cluster operator status")

	co := &configv1.ClusterOperator{ObjectMeta: metav1.ObjectMeta{Name: cloudCredClusterOperator}}
	err := client.Get(context.TODO(), types.NamespacedName{Name: co.Name}, co)
	isNotFound := errors.IsNotFound(err)
	if err != nil && !isNotFound {
		return fmt.Errorf("failed to get clusteroperator %s: %v", co.Name, err)
	}

	oldConditions := co.Status.Conditions
	oldVersions := co.Status.Versions
	oldRelatedObjects := co.Status.RelatedObjects

	// We rebuild the conditions from scratch each time.
	// Handlers return abnormal (non-default) conditions they wish to set.
	// if the controller is functioning normally, it should return an empty slice of conditions.
	conditions := []configv1.ClusterOperatorStatusCondition{}
	relatedObjects := []configv1.ObjectReference{}
	for _, handler := range statusHandlers {
		handlerConditions, err := handler.GetConditions(logger)
		if err != nil {
			logger.Errorf("failed to get conditions from handler %s", handler.Name())
			continue
		}
		conditions = mergeConditions(conditions, handlerConditions, logger, handler.Name())
		handlerRelatedObjects, err := handler.GetRelatedObjects(logger)
		if err != nil {
			logger.Errorf("failed to get related objects from handler %s", handler.Name())
			continue
		}
		relatedObjects = append(relatedObjects, handlerRelatedObjects...)
	}

	// sets defaults for condition not set by any handler
	conditions = defaultUnsetConditions(conditions)

	// at this point we know all condition types exist in conditions

	co.Status.Conditions = conditions
	co.Status.RelatedObjects = relatedObjects
	co.Status.Versions = computeClusterOperatorVersions()

	// check if the operator is disabled and reflect that in the Available condition
	mode, _, err := utils.GetOperatorConfiguration(client, logger)
	if err != nil {
		return fmt.Errorf("error checking if operator is disabled: %v", err)
	}
	if mode == operatorv1.CloudCredentialsModeManual {
		available, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorAvailable)
		if available.Status == configv1.ConditionTrue {
			available.Reason = reasonOperatorDisabled
			available.Message = msgOperatorDisabled
		}
	}
>>>>>>> 840ad99a... use CCO config object

	newConditions := []configv1.ClusterOperatorStatusCondition{}

<<<<<<< HEAD
	found := false
	for _, c := range oldConditions {
		if condition.Type == c.Type {
			if condition.Status == c.Status &&
				condition.Reason == c.Reason &&
				condition.Message == c.Message {
				return oldConditions
			}
=======
	// Check if version changed, if so force a progressing last transition update:
	if !reflect.DeepEqual(oldVersions, co.Status.Versions) {
		logger.WithFields(log.Fields{
			"old": oldVersions,
			"new": co.Status.Versions,
		}).Info("version has changed, updating progressing condition lastTransitionTime")
		progressing, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		// We know this should be there.
		progressing.LastTransitionTime = metav1.Now()
	}
>>>>>>> 840ad99a... use CCO config object

			found = true
			newConditions = append(newConditions, *condition)
		} else {
			newConditions = append(newConditions, c)
		}
	}
	if !found {
		newConditions = append(newConditions, *condition)
	}

	return newConditions
}

<<<<<<< HEAD
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
=======
func mergeConditions(existing []configv1.ClusterOperatorStatusCondition, new []configv1.ClusterOperatorStatusCondition, logger log.FieldLogger, handlerName string) []configv1.ClusterOperatorStatusCondition {
	for _, newCondition := range new {
		existingCondition, index := findClusterOperatorCondition(existing, newCondition.Type)
		if existingCondition == nil {
			existing = append(existing, newCondition)
		} else {
			logger.Infof("condition already set for type %s by a previous handler, the new condition from handler %s will be accepted: %v", newCondition.Type, handlerName, newCondition)
			existing[index] = newCondition
		}
	}
	return existing
}

func defaultUnsetConditions(existing []configv1.ClusterOperatorStatusCondition) []configv1.ClusterOperatorStatusCondition {
	var conditions []configv1.ClusterOperatorStatusCondition
	for _, conditionType := range []configv1.ClusterStatusConditionType{
		configv1.OperatorAvailable,
		configv1.OperatorDegraded,
		configv1.OperatorProgressing,
		configv1.OperatorUpgradeable,
	} {
		existingCondition, _ := findClusterOperatorCondition(existing, conditionType)
		if existingCondition != nil {
			conditions = append(conditions, *existingCondition)
		} else {
			// No handler set this condition type, set to defaults
			defaultCondition := configv1.ClusterOperatorStatusCondition{
				Type: conditionType,
			}
			switch conditionType {
			case configv1.OperatorAvailable:
				defaultCondition.Status = configv1.ConditionTrue
			case configv1.OperatorDegraded:
				defaultCondition.Status = configv1.ConditionFalse
			case configv1.OperatorProgressing:
				defaultCondition.Status = configv1.ConditionFalse
			case configv1.OperatorUpgradeable:
				defaultCondition.Status = configv1.ConditionTrue
>>>>>>> 840ad99a... use CCO config object
			}
		}
<<<<<<< HEAD

		if !foundMatchingCondition {
			return false
=======
	}
	return conditions
}

func computeClusterOperatorVersions() []configv1.OperandVersion {
	currentVersion := os.Getenv("RELEASE_VERSION")
	versions := []configv1.OperandVersion{
		{
			Name:    "operator",
			Version: currentVersion,
		},
	}
	return versions
}

// findClusterOperatorCondition iterates all conditions on a ClusterOperator looking for the
// specified condition type. If none exists nil will be returned.
func findClusterOperatorCondition(conditions []configv1.ClusterOperatorStatusCondition, conditionType configv1.ClusterStatusConditionType) (*configv1.ClusterOperatorStatusCondition, int) {
	for i, condition := range conditions {
		if condition.Type == conditionType {
			return &conditions[i], i
		}
	}
	return nil, 0
}

func setLastTransitionTime(oldConditions []configv1.ClusterOperatorStatusCondition, newConditions []configv1.ClusterOperatorStatusCondition) {
	for i := range newConditions {
		newCondition := &newConditions[i]
		oldCondition, _ := findClusterOperatorCondition(oldConditions, newCondition.Type)
		if oldCondition == nil || !ConditionEqual(*oldCondition, *newCondition) {
			newCondition.LastTransitionTime = metav1.Now()
		} else {
			newCondition.LastTransitionTime = oldCondition.LastTransitionTime
>>>>>>> 840ad99a... use CCO config object
		}
	}

	return true
}
