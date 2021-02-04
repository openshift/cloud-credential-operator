package credentialsrequest

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/actuator"
	"github.com/openshift/cloud-credential-operator/pkg/operator/status"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

const (
	reasonCredentialsFailing = "CredentialsFailing"
	reasonReconciling        = "Reconciling"
	reasonStaleCredentials   = "StaleCredentials"
)

var _ status.Handler = &ReconcileCredentialsRequest{}

func (r *ReconcileCredentialsRequest) GetConditions(logger log.FieldLogger) ([]configv1.ClusterOperatorStatusCondition, error) {
	_, credRequests, mode, err := r.getOperatorState(logger)
	if err != nil {
		return []configv1.ClusterOperatorStatusCondition{}, fmt.Errorf("failed to get operator state: %v", err)
	}
	return computeStatusConditions(
		r.Actuator,
		mode,
		credRequests,
		r.platformType,
		logger), nil
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

// getOperatorState gets and returns the resources necessary to compute the
// operator's current state.
func (r *ReconcileCredentialsRequest) getOperatorState(logger log.FieldLogger) (*corev1.Namespace, []minterv1.CredentialsRequest, operatorv1.CloudCredentialsMode, error) {

	ns := &corev1.Namespace{}
	if err := r.Client.Get(context.TODO(), types.NamespacedName{Name: minterv1.CloudCredOperatorNamespace}, ns); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil, operatorv1.CloudCredentialsModeDefault, nil
		}

		return nil, nil, operatorv1.CloudCredentialsModeDefault, fmt.Errorf(
			"error getting Namespace %s: %v", minterv1.CloudCredOperatorNamespace, err)
	}

	// NOTE: we're only looking at cred requests in our namespace, which is where we expect the
	// central list to live. Other credentials requests in other namespaces will not affect status,
	// but they will still work fine.
	credRequestList := &minterv1.CredentialsRequestList{}
	err := r.Client.List(context.TODO(), credRequestList, client.InNamespace(minterv1.CloudCredOperatorNamespace))
	if err != nil {
		return nil, nil, operatorv1.CloudCredentialsModeDefault, fmt.Errorf(
			"failed to list CredentialsRequests: %v", err)
	}

	mode, _, err := utils.GetOperatorConfiguration(r.Client, logger)
	if err != nil {
		return nil, nil, mode, fmt.Errorf("error checking if operator is disabled: %v", err)
	}

	return ns, credRequestList.Items, mode, nil
}

// computeStatusConditions computes the operator's current state.
func computeStatusConditions(
	actuator actuator.Actuator,
	mode operatorv1.CloudCredentialsMode,
	credRequests []minterv1.CredentialsRequest,
	clusterCloudPlatform configv1.PlatformType,
	logger log.FieldLogger) []configv1.ClusterOperatorStatusCondition {
	operatorIsDisabled := mode == operatorv1.CloudCredentialsModeManual

	var conditions []configv1.ClusterOperatorStatusCondition

	// Only set non-default conditions
	upgradeableCondition := actuator.Upgradeable(mode)
	log.WithField("condition", upgradeableCondition).Debug("calculated upgradeable condition")
	if upgradeableCondition != nil {
		conditions = append(conditions, *upgradeableCondition)
	}

	failingCredRequests := 0
	staleCredRequests := 0

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

		// Check for stale credential request condition
		staleCond := utils.FindCredentialsRequestCondition(cr.Status.Conditions, minterv1.StaleCredentials)
		if staleCond != nil && staleCond.Status == corev1.ConditionTrue {
			staleCredRequests = staleCredRequests + 1
		}
	}

	if operatorIsDisabled {
		if staleCredRequests > 0 {
			var degradedCondition configv1.ClusterOperatorStatusCondition
			degradedCondition.Type = configv1.OperatorDegraded
			degradedCondition.Status = configv1.ConditionTrue
			degradedCondition.Reason = reasonStaleCredentials
			degradedCondition.Message = fmt.Sprintf(
				"%d of %d credentials requests are stale and should be deleted.",
				staleCredRequests, len(validCredRequests))
			conditions = append(conditions, degradedCondition)
		}
		return conditions
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

// buildExpectedRelatedObjects returns the list of expected related objects, used
// by the oc must-gather command to fetch resource yaml for debugging purposes.
// Keeping this up to date across versions via the code seems like the safest option.
func buildExpectedRelatedObjects(credRequests []minterv1.CredentialsRequest) []configv1.ObjectReference {
	related := []configv1.ObjectReference{
		{
			Resource: "namespaces",
			Name:     minterv1.CloudCredOperatorNamespace,
		},
	}
	for _, cr := range credRequests {
		related = append(related, configv1.ObjectReference{
			Group:     minterv1.SchemeGroupVersion.Group,
			Resource:  "credentialsrequests",
			Namespace: cr.Namespace,
			Name:      cr.Name,
		})
	}
	return related
}
