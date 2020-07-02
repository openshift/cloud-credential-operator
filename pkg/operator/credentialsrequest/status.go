package credentialsrequest

import (
	"context"
	"fmt"
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	configv1 "github.com/openshift/api/config/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
	"github.com/openshift/cloud-credential-operator/pkg/util/clusteroperator"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	cloudCredClusterOperator           = "cloud-credential"
	cloudCredOperatorNamespace         = "openshift-cloud-credential-operator"
	reasonCredentialsFailing           = "CredentialsFailing"
	reasonReconciling                  = "Reconciling"
	reasonCredentialsRootSecretMissing = "CredentialsRootSecretMissing"
)

// syncOperatorStatus computes the operator's current status and
// creates or updates the ClusterOperator resource for the operator accordingly.
func (r *ReconcileCredentialsRequest) syncOperatorStatus() error {
	logger := log.WithField("controller", "credreq_status")
	return clusteroperator.SyncStatus(r.Client, logger)
}

var _ clusteroperator.StatusHandler = &ReconcileCredentialsRequest{}

func (r *ReconcileCredentialsRequest) GetConditions(logger log.FieldLogger) ([]configv1.ClusterOperatorStatusCondition, error) {
	_, credRequests, operatorIsDisabled, err := r.getOperatorState(logger)
	if err != nil {
		return []configv1.ClusterOperatorStatusCondition{}, fmt.Errorf("failed to get operator state: %v", err)
	}
	parentSecretExists, err := r.parentSecretExists()
	if err != nil {
		return []configv1.ClusterOperatorStatusCondition{}, errors.Wrap(err, "error checking if parent secret exists")
	}
	return computeStatusConditions(credRequests, r.platformType, operatorIsDisabled, parentSecretExists, r.Actuator.GetCredentialsRootSecretLocation(), logger), nil
}

func (r *ReconcileCredentialsRequest) GetRelatedObjects(logger log.FieldLogger) ([]configv1.ObjectReference, error) {
	_, credRequests, _, err := r.getOperatorState(logger)
	if err != nil {
		return []configv1.ObjectReference{}, fmt.Errorf("failed to get operator state: %v", err)
	}
	return buildExpectedRelatedObjects(credRequests), nil
}

func (r *ReconcileCredentialsRequest) Name() string {
	return controllerName
}

func (r *ReconcileCredentialsRequest) parentSecretExists() (bool, error) {
	parentSecret := &corev1.Secret{}
	if err := r.Client.Get(context.TODO(), r.Actuator.GetCredentialsRootSecretLocation(), parentSecret); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// getOperatorState gets and returns the resources necessary to compute the
// operator's current state.
func (r *ReconcileCredentialsRequest) getOperatorState(logger log.FieldLogger) (*corev1.Namespace, []minterv1.CredentialsRequest, bool, error) {

	ns := &corev1.Namespace{}
	if err := r.Client.Get(context.TODO(), types.NamespacedName{Name: minterv1.CloudCredOperatorNamespace}, ns); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil, false, nil
		}

		return nil, nil, false, fmt.Errorf(
			"error getting Namespace %s: %v", minterv1.CloudCredOperatorNamespace, err)
	}

	// NOTE: we're only looking at cred requests in our namespace, which is where we expect the
	// central list to live. Other credentials requests in other namespaces will not affect status,
	// but they will still work fine.
	credRequestList := &minterv1.CredentialsRequestList{}
	err := r.Client.List(context.TODO(), credRequestList, client.InNamespace(minterv1.CloudCredOperatorNamespace))
	if err != nil {
		return nil, nil, false, fmt.Errorf(
			"failed to list CredentialsRequests: %v", err)
	}

	operatorIsDisabled, err := utils.IsOperatorDisabled(r.Client, logger)
	if err != nil {
		return nil, nil, false, fmt.Errorf("error checking if operator is disabled: %v", err)
	}

	return ns, credRequestList.Items, operatorIsDisabled, nil
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
	credRequests []minterv1.CredentialsRequest,
	clusterCloudPlatform configv1.PlatformType,
	operatorIsDisabled bool, parentCredExists bool, parentCredLocation types.NamespacedName,
	logger log.FieldLogger) []configv1.ClusterOperatorStatusCondition {

	var conditions []configv1.ClusterOperatorStatusCondition
	if operatorIsDisabled {
		return conditions
	}

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
		for _, t := range minterv1.FailureConditionTypes {
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

	if failingCredRequests > 0 {
		var degradedCondition configv1.ClusterOperatorStatusCondition
		degradedCondition.Type = configv1.OperatorDegraded
		degradedCondition.Status = configv1.ConditionTrue
		degradedCondition.Reason = reasonCredentialsFailing
		degradedCondition.Message = fmt.Sprintf(
			"%d of %d credentials requests are failing to sync.",
			failingCredRequests, len(validCredRequests))
		conditions = append(conditions, degradedCondition)
	}

	// Progressing should be true if the operator is making changes to the operand. In this case
	// we will set true if any CredentialsRequests are not provisioned, or have failure conditions,
	// as this indicates the controllers have work they are trying to do.
	credRequestsNotProvisioned := 0
	logger.Debugf("%d cred requests", len(validCredRequests))

	for _, cr := range validCredRequests {
		if !cr.Status.Provisioned {
			credRequestsNotProvisioned = credRequestsNotProvisioned + 1
		}
	}
	if credRequestsNotProvisioned > 0 || failingCredRequests > 0 {
		var progressingCondition configv1.ClusterOperatorStatusCondition
		progressingCondition.Type = configv1.OperatorProgressing
		progressingCondition.Status = configv1.ConditionTrue
		progressingCondition.Reason = reasonReconciling
		progressingCondition.Message = fmt.Sprintf(
			"%d of %d credentials requests provisioned, %d reporting errors.",
			len(validCredRequests)-credRequestsNotProvisioned, len(validCredRequests), failingCredRequests)
		conditions = append(conditions, progressingCondition)
	}

	// If the operator is not disabled, and we do not have a parent cred in kube-system, we are not
	// upgradable. Admin cred removal is a valid mode to run in but it should be restored before
	// you can upgrade.
	if !operatorIsDisabled && !parentCredExists {
		var upgradeableCondition configv1.ClusterOperatorStatusCondition
		upgradeableCondition.Type = configv1.OperatorUpgradeable
		upgradeableCondition.Status = configv1.ConditionFalse
		upgradeableCondition.Reason = reasonCredentialsRootSecretMissing
		upgradeableCondition.Message = fmt.Sprintf("Parent credential secret %s/%s must be restored prior to upgrade",
			parentCredLocation.Namespace, parentCredLocation.Name)
		conditions = append(conditions, upgradeableCondition)
	}

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
	return related
}
