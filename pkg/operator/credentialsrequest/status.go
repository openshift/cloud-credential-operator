package credentialsrequest

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"sort"
	"time"

	log "github.com/sirupsen/logrus"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	constants "github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/actuator"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
	"github.com/openshift/cloud-credential-operator/pkg/util/clusteroperator"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	cloudCredClusterOperator        = "cloud-credential"
	cloudCredOperatorNamespace      = "openshift-cloud-credential-operator"
	reasonCredentialsFailing        = "CredentialsFailing"
	reasonOperatorStateError        = "OperatorStateError"
	reasonNoCredentialsFailing      = "NoCredentialsFailing"
	reasonReconciling               = "Reconciling"
	reasonReconcilingComplete       = "ReconcilingComplete"
	reasonCredentialsNotProvisioned = "CredentialsNotProvisioned"
	reasonOperatorDisabled          = "OperatorDisabledByAdmin"
)

// syncOperatorStatus computes the operator's current status and
// creates or updates the ClusterOperator resource for the operator accordingly.
func (r *ReconcileCredentialsRequest) syncOperatorStatus() error {
	logger := log.WithField("controller", "credreq_status")
	logger.Debug("syncing cluster operator status")
	co := &configv1.ClusterOperator{ObjectMeta: metav1.ObjectMeta{Name: cloudCredClusterOperator}}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: co.Name}, co)
	isNotFound := errors.IsNotFound(err)
	if err != nil && !isNotFound {
		return fmt.Errorf("failed to get clusteroperator %s: %v", co.Name, err)
	}

	_, credRequests, operatorMode, configConflict, err := r.getOperatorState(logger)
	if err != nil {
		return fmt.Errorf("failed to get operator state: %v", err)
	}

	oldConditions := co.Status.Conditions
	oldVersions := co.Status.Versions
	oldRelatedObjects := co.Status.RelatedObjects
	co.Status.Conditions = computeStatusConditions(r.Actuator, oldConditions, credRequests, r.platformType,
		operatorMode, configConflict, logger)
	co.Status.Versions = computeClusterOperatorVersions()
	co.Status.RelatedObjects = buildExpectedRelatedObjects(credRequests)

	// ClusterOperator should already exist (from the manifests payload), but recreate it if needed
	if isNotFound {
		if err := r.Client.Create(context.TODO(), co); err != nil {
			return fmt.Errorf("failed to create clusteroperator %s: %v", co.Name, err)
		}
		logger.Info("created clusteroperator")
	}

	// Check if version changed, if so force a progressing last transition update:
	if !reflect.DeepEqual(oldVersions, co.Status.Versions) {
		logger.WithFields(log.Fields{
			"old": oldVersions,
			"new": co.Status.Versions,
		}).Info("version has changed, updating progressing condition lastTransitionTime")
		progressing := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		// We know this should be there.
		progressing.LastTransitionTime = metav1.Time{Time: time.Now()}
	}

	// Update status fields if needed
	if !clusteroperator.ConditionsEqual(oldConditions, co.Status.Conditions) ||
		!reflect.DeepEqual(oldVersions, co.Status.Versions) ||
		!reflect.DeepEqual(oldRelatedObjects, co.Status.RelatedObjects) {
		log.Infof("full obj: %v", co.Status.Conditions)

		err = r.Client.Status().Update(context.TODO(), co)
		if err != nil {
			return fmt.Errorf("failed to update clusteroperator %s: %v", co.Name, err)
		}
		logger.Debug("cluster operator status updated")
	}

	return nil
}

// getOperatorState gets and returns the resources necessary to compute the
// operator's current state.
func (r *ReconcileCredentialsRequest) getOperatorState(logger log.FieldLogger) (*corev1.Namespace, []minterv1.CredentialsRequest,
	operatorv1.CloudCredentialsMode, bool, error) {

	ns := &corev1.Namespace{}
	if err := r.Client.Get(context.TODO(), types.NamespacedName{Name: minterv1.CloudCredOperatorNamespace}, ns); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil, "", false, nil
		}

		return nil, nil, "", false, fmt.Errorf(
			"error getting Namespace %s: %v", minterv1.CloudCredOperatorNamespace, err)
	}

	// NOTE: we're only looking at cred requests in our namespace, which is where we expect the
	// central list to live. Other credentials requests in other namespaces will not affect status,
	// but they will still work fine.
	credRequestList := &minterv1.CredentialsRequestList{}
	err := r.Client.List(context.TODO(), credRequestList, client.InNamespace(minterv1.CloudCredOperatorNamespace))
	if err != nil {
		return nil, nil, "", false, fmt.Errorf(
			"failed to list CredentialsRequests: %v", err)
	}

	mode, configConflict, err := utils.GetOperatorConfiguration(r.Client, logger)
	if err != nil {
		return nil, nil, "", false, fmt.Errorf("error checking if operator is disabled: %v", err)
	}

	return ns, credRequestList.Items, mode, configConflict, nil
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

// computeStatusConditions computes the operator's current state.
func computeStatusConditions(
	actuator actuator.Actuator,
	conditions []configv1.ClusterOperatorStatusCondition,
	credRequests []minterv1.CredentialsRequest,
	clusterCloudPlatform configv1.PlatformType,
	mode operatorv1.CloudCredentialsMode,
	configConflict bool,
	logger log.FieldLogger) []configv1.ClusterOperatorStatusCondition {

	failingCredRequests := 0

	validCredRequests := []minterv1.CredentialsRequest{}
	// Filter out credRequests that are for different clouds
	for i, cr := range credRequests {
		infraMatches, err := crInfraMatches(&cr, clusterCloudPlatform)
		if err != nil {
			// couldn't decode the providerspec (bad spec data?)
			logger.WithField("credentialsRequest", cr.Name).WithError(err).Warning("ignoring for status condition because could not decode provider spec")
			continue
		}
		if !infraMatches {
			continue
		}
		validCredRequests = append(validCredRequests, credRequests[i])
	}

	for _, cr := range validCredRequests {
		// Check for provision failure conditions:
		foundFailure := false
		for _, t := range constants.FailureConditionTypes {
			failureCond := utils.FindCredentialsRequestCondition(cr.Status.Conditions, t)
			if failureCond != nil && failureCond.Status == corev1.ConditionTrue {
				foundFailure = true
				break
			}
		}

		if foundFailure {
			failingCredRequests = failingCredRequests + 1
		}

	}

	// Degraded should be true if we are encountering errors. We consider any credentials request
	// with either provision or deprovision failure conditions true, to be a degraded condition.
	degradedCondition := &configv1.ClusterOperatorStatusCondition{
		Type:   configv1.OperatorDegraded,
		Status: configv1.ConditionFalse,
	}

	// shouldn't happen with the server-side enforcement of the CRDs enum specification
	if !utils.IsValidMode(mode) {
		degradedCondition.Status = configv1.ConditionTrue
		degradedCondition.Reason = constants.StatusModeInvalid
		degradedCondition.Message = fmt.Sprintf("operator mode of %s is invalid", mode)
	} else if configConflict {
		degradedCondition.Status = configv1.ConditionTrue
		degradedCondition.Reason = constants.StatusModeMismatch
		degradedCondition.Message = fmt.Sprintf("legacy configmap disabled setting conflicts with operator config mode of %s",
			mode)
	} else if mode == operatorv1.CloudCredentialsModeManual {
		degradedCondition.Status = configv1.ConditionFalse
		degradedCondition.Reason = reasonOperatorDisabled
	} else {
		if failingCredRequests > 0 {
			degradedCondition.Status = configv1.ConditionTrue
			degradedCondition.Reason = reasonCredentialsFailing
			degradedCondition.Message = fmt.Sprintf(
				"%d of %d credentials requests are failing to sync.",
				failingCredRequests, len(validCredRequests))
		} else {
			degradedCondition.Status = configv1.ConditionFalse
			degradedCondition.Reason = reasonNoCredentialsFailing
			degradedCondition.Message = "No credentials requests reporting errors."

		}
	}
	conditions = clusteroperator.SetStatusCondition(conditions,
		degradedCondition)

	// Progressing should be true if the operator is making changes to the operand. In this case
	// we will set true if any CredentialsRequests are not provisioned, or have failure conditions,
	// as this indicates the controllers have work they are trying to do.
	progressingCondition := &configv1.ClusterOperatorStatusCondition{
		Type:   configv1.OperatorProgressing,
		Status: configv1.ConditionUnknown,
	}

	if mode == operatorv1.CloudCredentialsModeManual {
		progressingCondition.Status = configv1.ConditionFalse
		progressingCondition.Reason = reasonOperatorDisabled
	} else {
		credRequestsNotProvisioned := 0
		logger.Debugf("%d cred requests", len(validCredRequests))

		for _, cr := range validCredRequests {
			if !cr.Status.Provisioned {
				credRequestsNotProvisioned = credRequestsNotProvisioned + 1
			}
		}
		if credRequestsNotProvisioned > 0 || failingCredRequests > 0 {
			progressingCondition.Status = configv1.ConditionTrue
			progressingCondition.Reason = reasonReconciling
			progressingCondition.Message = fmt.Sprintf(
				"%d of %d credentials requests provisioned, %d reporting errors.",
				len(validCredRequests)-credRequestsNotProvisioned, len(validCredRequests), failingCredRequests)
		} else {
			progressingCondition.Status = configv1.ConditionFalse
			progressingCondition.Reason = reasonReconcilingComplete
			progressingCondition.Message = fmt.Sprintf(
				"%d of %d credentials requests provisioned and reconciled.",
				len(validCredRequests), len(validCredRequests))
		}
	}
	conditions = clusteroperator.SetStatusCondition(conditions,
		progressingCondition)

	// Available should be true if we've made our API available.
	// (note: definition has fluctuated a lot) Our CO definition in release manifest will set to
	// unknown, we will set to true indicating we're up and running.
	// TODO: is there a better way to determine if we've made our API available? We wouldn't
	// get this far in syncing on a CredentialsRequest if it wasn't available. Would probably need a separate controller syncing on some other type to formally check.
	availableCondition := &configv1.ClusterOperatorStatusCondition{
		Status: configv1.ConditionTrue,
		Type:   configv1.OperatorAvailable,
	}
	if mode == operatorv1.CloudCredentialsModeManual {
		availableCondition.Reason = reasonOperatorDisabled
	}
	conditions = clusteroperator.SetStatusCondition(conditions,
		availableCondition)

	upgradeableCondition := actuator.Upgradeable(mode)
	conditions = clusteroperator.SetStatusCondition(conditions,
		upgradeableCondition)

	// Log all conditions we set:
	for _, c := range conditions {
		logger.WithFields(log.Fields{
			"type":    c.Type,
			"status":  c.Status,
			"reason":  c.Reason,
			"message": c.Message,
		}).Debug("set ClusterOperator condition")
	}

	return conditions
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

// buildExpectedRelatedObjects returns the list of expected related objects, used
// by the oc must-gather command to fetch resource yaml for debugging purposes.
// Keeping this up to date across versions via the code seems like the safest option.
func buildExpectedRelatedObjects(credRequests []minterv1.CredentialsRequest) []configv1.ObjectReference {
	related := []configv1.ObjectReference{
		{
			Resource: "namespaces",
			Name:     cloudCredOperatorNamespace,
		},
	}
	for _, cr := range credRequests {
		related = append(related, configv1.ObjectReference{
			Group:     minterv1.SchemeGroupVersion.Group,
			Resource:  "CredentialsRequest",
			Namespace: cr.Namespace,
			Name:      cr.Name,
		})
	}
	related = append(related, configv1.ObjectReference{
		Group:    operatorv1.GroupName,
		Resource: "CloudCredentials",
		Name:     constants.CloudCredOperatorConfig,
	})
	sort.SliceStable(related, func(i, j int) bool {
		if related[i].Namespace < related[j].Namespace {
			return true
		}
		if related[i].Namespace > related[j].Namespace {
			return false
		}
		return related[i].Name < related[j].Name
	})

	return related
}
