package clusteroperator

import (
	"context"
	"fmt"
	"os"
	"reflect"

	log "github.com/sirupsen/logrus"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	cloudCredClusterOperator = "cloud-credential"
	reasonOperatorDisabled   = "OperatorDisabledByAdmin"
	msgOperatorDisabled      = "Credential minting is disabled by cluster admin"
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
	operatorIsDisabled, err := utils.IsOperatorDisabled(client, logger)
	if err != nil {
		return fmt.Errorf("error checking if operator is disabled: %v", err)
	}
	if operatorIsDisabled {
		available := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorAvailable)
		if available.Status == configv1.ConditionTrue {
			available.Reason = reasonOperatorDisabled
			available.Message = msgOperatorDisabled
		}
	}

	// Update transition time for any condition that has changed
	setLastTransitionTime(oldConditions, co.Status.Conditions)

	// Check if version changed, if so force a progressing last transition update:
	if !reflect.DeepEqual(oldVersions, co.Status.Versions) {
		logger.WithFields(log.Fields{
			"old": oldVersions,
			"new": co.Status.Versions,
		}).Info("version has changed, updating progressing condition lastTransitionTime")
		progressing := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		// We know this should be there.
		progressing.LastTransitionTime = metav1.Now()
	}

	// ClusterOperator should already exist (from the manifests payload), but recreate it if needed
	if isNotFound {
		if err := client.Create(context.TODO(), co); err != nil {
			return fmt.Errorf("failed to create clusteroperator %s: %v", co.Name, err)
		}
		logger.Info("created clusteroperator")
		return nil
	}

	// Update status fields if needed
	if !reflect.DeepEqual(oldConditions, co.Status.Conditions) ||
		!reflect.DeepEqual(oldVersions, co.Status.Versions) ||
		!reflect.DeepEqual(oldRelatedObjects, co.Status.RelatedObjects) {

		err = client.Status().Update(context.TODO(), co)
		if err != nil {
			return fmt.Errorf("failed to update clusteroperator %s: %v", co.Name, err)
		}
		logger.Info("cluster operator status updated")
	}

	return nil
}

func mergeConditions(existing []configv1.ClusterOperatorStatusCondition, new []configv1.ClusterOperatorStatusCondition, logger log.FieldLogger, handlerName string) []configv1.ClusterOperatorStatusCondition {
	conditions := []configv1.ClusterOperatorStatusCondition{}
	for _, newCondition := range new {
		existingCondition := findClusterOperatorCondition(existing, newCondition.Type)
		if existingCondition == nil {
			conditions = append(conditions, newCondition)
		} else {
			logger.Infof("condition already set for type %s by a previous handler, the following condition from handler %s will be dropped: %v", newCondition.Type, handlerName, newCondition)
		}
	}
	return conditions
}

func defaultUnsetConditions(existing []configv1.ClusterOperatorStatusCondition) []configv1.ClusterOperatorStatusCondition {
	var conditions []configv1.ClusterOperatorStatusCondition
	for _, conditionType := range []configv1.ClusterStatusConditionType{
		configv1.OperatorAvailable,
		configv1.OperatorDegraded,
		configv1.OperatorProgressing,
		configv1.OperatorUpgradeable,
	} {
		existingCondition := findClusterOperatorCondition(existing, conditionType)
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
			}
			conditions = append(conditions, defaultCondition)
		}
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
func findClusterOperatorCondition(conditions []configv1.ClusterOperatorStatusCondition, conditionType configv1.ClusterStatusConditionType) *configv1.ClusterOperatorStatusCondition {
	for i, condition := range conditions {
		if condition.Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}

func setLastTransitionTime(oldConditions []configv1.ClusterOperatorStatusCondition, newConditions []configv1.ClusterOperatorStatusCondition) {
	for i := range newConditions {
		newCondition := &newConditions[i]
		oldCondition := findClusterOperatorCondition(oldConditions, newCondition.Type)
		if oldCondition == nil || !ConditionEqual(*oldCondition, *newCondition) {
			newCondition.LastTransitionTime = metav1.Now()
		} else {
			newCondition.LastTransitionTime = oldCondition.LastTransitionTime
		}
	}
}

func ConditionEqual(a, b configv1.ClusterOperatorStatusCondition) bool {
	// Compare every field except LastTransitionTime.
	if a.Type == b.Type &&
		a.Status == b.Status &&
		a.Reason == b.Reason &&
		a.Message == b.Message {
		return true
	}
	return false
}
