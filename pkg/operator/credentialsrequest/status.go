package credentialsrequest

import (
	"context"
	"fmt"
	"time"

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

	// degradedGracePeriod is the minimum time a CredentialsRequest failure
	// condition must persist before counting toward Degraded. Per the spec,
	// Degraded represents a condition that persists "over a period of time" —
	// transient failures during reconciliation should not immediately surface.
	degradedGracePeriod = 5 * time.Minute
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

	// Spec: Progressing means actively moving from one steady state to another,
	// not reconciling a previously known state. A generation mismatch indicates
	// the CR spec has changed and the reconciler has not yet synced it.
	//
	// Resource version checks (root credential secret, Infrastructure) are
	// intentionally NOT used here for Progressing detection:
	// - Root credential rotation: the credreq controller watches the root
	//   secret and re-syncs all CRs immediately via CreateOrUpdateOnCredsExist.
	//   The sync completes in milliseconds (passthrough) to seconds (mint),
	//   so the transient RV mismatch is almost never visible to the status
	//   controller's 5-minute reconcile loop.
	// - Infrastructure RV: changes for many reasons unrelated to CCO (proxy,
	//   platform status, topology) and would cause noisy false Progressing.
	credRequestsProgressing := 0
	credRequestsProvisioned := 0
	logger.Debugf("%d cred requests", len(validCredRequests))

	for _, cr := range validCredRequests {
		if cr.Generation != cr.Status.LastSyncGeneration {
			credRequestsProgressing++
		}
		if cr.Status.Provisioned {
			credRequestsProvisioned++
		}
		for _, t := range minterv1.FailureConditionTypes {
			failureCond := utils.FindCredentialsRequestCondition(cr.Status.Conditions, t)
			if failureCond != nil && failureCond.Status == corev1.ConditionTrue {
				// Spec: Degraded represents a persistent condition, not a transient
				// error. Only count as failing after the grace period has elapsed.
				if time.Since(failureCond.LastTransitionTime.Time) > degradedGracePeriod {
					failingCredRequests++
					break
				}
				// Continue checking other failure types if this one is still
				// within the grace period.
			}
		}
	}

	// Spec: Degraded means the component does not match its desired state over a
	// period of time. Failing credentials requests indicate a persistent lower
	// quality of service. Suppression during cluster upgrades is handled centrally
	// in syncStatus via the ClusterVersion Progressing condition.
	if failingCredRequests > 0 {
		conditions = append(conditions, configv1.ClusterOperatorStatusCondition{
			Type:   configv1.OperatorDegraded,
			Status: configv1.ConditionTrue,
			Reason: reasonCredentialsFailing,
			Message: fmt.Sprintf(
				"%d of %d credentials requests are failing to sync.",
				failingCredRequests, len(validCredRequests)),
		})
	}

	// Progressing should be true if the operator is making changes to the
	// operand. Report true when any CredentialsRequests are not yet provisioned
	// (credRequestsNotProvisioned > 0) or when controllers are actively
	// reconciling a generation mismatch (credRequestsProgressing > 0).
	credRequestsNotProvisioned := len(validCredRequests) - credRequestsProvisioned
	if credRequestsNotProvisioned > 0 || credRequestsProgressing > 0 {
		conditions = append(conditions, configv1.ClusterOperatorStatusCondition{
			Type:   configv1.OperatorProgressing,
			Status: configv1.ConditionTrue,
			Reason: reasonReconciling,
			Message: fmt.Sprintf(
				"%d of %d credentials requests provisioned, %d reporting errors.",
				credRequestsProvisioned, len(validCredRequests), failingCredRequests),
		})
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
