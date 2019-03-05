package credentialsrequest

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	configv1 "github.com/openshift/api/config/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/controller/utils"
	"github.com/openshift/cloud-credential-operator/pkg/util/clusteroperator"
	operatorversion "github.com/openshift/cloud-credential-operator/version"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	cloudCredOperatorNamespace      = "openshift-cloud-credential-operator"
	reasonCredentialsFailing        = "CredentialsFailing"
	reasonNoCredentialsFailing      = "NoCredentialsFailing"
	reasonReconciling               = "Reconciling"
	reasonReconcilingComplete       = "ReconcilingComplete"
	reasonCredentialsNotProvisioned = "CredentialsNotProvisioned"
)

// syncOperatorStatus computes the operator's current status and
// creates or updates the ClusterOperator resource for the operator accordingly.
func (r *ReconcileCredentialsRequest) syncOperatorStatus() error {
	log.Debug("syncing cluster operator status")
	co := &configv1.ClusterOperator{ObjectMeta: metav1.ObjectMeta{Name: cloudCredOperatorNamespace}}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: co.Name}, co)
	isNotFound := errors.IsNotFound(err)
	if err != nil && !isNotFound {
		return fmt.Errorf("failed to get clusteroperator %s: %v", co.Name, err)
	}

	_, credRequests, err := r.getOperatorState()
	if err != nil {
		return fmt.Errorf("failed to get operator state: %v", err)
	}

	oldConditions := co.Status.Conditions
	co.Status.Conditions = computeStatusConditions(oldConditions, credRequests)

	if isNotFound {
		co.Status.Version = operatorversion.Version
		if err := r.Client.Create(context.TODO(), co); err != nil {
			return fmt.Errorf("failed to create clusteroperator %s: %v", co.Name, err)
		}
		log.Info("created clusteroperator")
	} else {
		if !clusteroperator.ConditionsEqual(oldConditions, co.Status.Conditions) {
			err = r.Client.Status().Update(context.TODO(), co)
			if err != nil {
				return fmt.Errorf("failed to update clusteroperator %s: %v", co.Name, err)
			}
			log.Debug("cluster operator status updated")
		}
	}
	return nil
}

// getOperatorState gets and returns the resources necessary to compute the
// operator's current state.
func (r *ReconcileCredentialsRequest) getOperatorState() (*corev1.Namespace, []minterv1.CredentialsRequest, error) {

	ns := &corev1.Namespace{}
	if err := r.Client.Get(context.TODO(), types.NamespacedName{Name: cloudCredOperatorNamespace}, ns); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil, nil
		}

		return nil, nil, fmt.Errorf(
			"error getting Namespace %s: %v", cloudCredOperatorNamespace, err)
	}

	// NOTE: we're only looking at cred requests in our namespace, which is where we expect the
	// central list to live. Other credentials requests in other namespaces will not affect status,
	// but they will still work fine.
	credRequestList := &minterv1.CredentialsRequestList{}
	err := r.Client.List(context.TODO(), &client.ListOptions{Namespace: cloudCredOperatorNamespace}, credRequestList)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"failed to list CredentialsRequests: %v", err)
	}

	return ns, credRequestList.Items, nil
}

// computeStatusConditions computes the operator's current state.
func computeStatusConditions(conditions []configv1.ClusterOperatorStatusCondition, credRequests []minterv1.CredentialsRequest) []configv1.ClusterOperatorStatusCondition {

	// Failing should be true if we are encountering errors. We consider any credentials request
	// with either provision or deprovision failure conditions true, to be failing.
	failingCondition := &configv1.ClusterOperatorStatusCondition{
		Type:   configv1.OperatorFailing,
		Status: configv1.ConditionFalse,
	}

	// If any of these conditions are present and true, we consider it a failing credential:
	failureConditionTypes := []minterv1.CredentialsRequestConditionType{
		minterv1.InsufficientCloudCredentials,
		minterv1.MissingTargetNamespace,
		minterv1.CredentialsProvisionFailure,
		minterv1.CredentialsDeprovisionFailure,
	}
	failingCredRequests := 0

	for _, cr := range credRequests {
		// Check for provision failure conditions:
		foundFailure := false
		for _, t := range failureConditionTypes {
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
		failingCondition.Status = configv1.ConditionTrue
		failingCondition.Reason = reasonCredentialsFailing
		failingCondition.Message = fmt.Sprintf(
			"%d of %d credentials requests are failing to sync.",
			failingCredRequests, len(credRequests))
	} else {
		failingCondition.Status = configv1.ConditionFalse
		failingCondition.Reason = reasonNoCredentialsFailing
		failingCondition.Message = "No credentials requests reporting errors."

	}
	conditions = clusteroperator.SetStatusCondition(conditions,
		failingCondition)

	// Progressing should be true if the operator is making changes to the operand. In this case
	// we will set true if any CredentialsRequests are not provisioned, or have failure conditions,
	// as this indicates the controllers have work they are trying to do.
	progressingCondition := &configv1.ClusterOperatorStatusCondition{
		Type:   configv1.OperatorProgressing,
		Status: configv1.ConditionUnknown,
	}
	credRequestsNotProvisioned := 0
	log.Debugf("%d cred requests", len(credRequests))

	for _, cr := range credRequests {
		if !cr.Status.Provisioned {
			credRequestsNotProvisioned = credRequestsNotProvisioned + 1
		}
	}
	if credRequestsNotProvisioned > 0 || failingCredRequests > 0 {
		progressingCondition.Status = configv1.ConditionTrue
		progressingCondition.Reason = reasonReconciling
		progressingCondition.Message = fmt.Sprintf(
			"%d of %d credentials requests provisioned, %d reporting errors.",
			len(credRequests)-credRequestsNotProvisioned, len(credRequests), failingCredRequests)
	} else {
		progressingCondition.Status = configv1.ConditionFalse
		progressingCondition.Reason = reasonReconcilingComplete
		progressingCondition.Message = "All credentials reconciled."
		progressingCondition.Message = fmt.Sprintf(
			"%d of %d credentials requests provisioned and reconciled.",
			len(credRequests), len(credRequests))
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
	conditions = clusteroperator.SetStatusCondition(conditions,
		availableCondition)

	// Log all conditions we set:
	for _, c := range conditions {
		log.WithFields(log.Fields{
			"type":    c.Type,
			"status":  c.Status,
			"reason":  c.Reason,
			"message": c.Message,
		}).Debug("set ClusterOperator condition")
	}

	return conditions
}
