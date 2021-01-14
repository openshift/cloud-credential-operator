package cleanup

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	operatorv1 "github.com/openshift/api/operator/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest"
	"github.com/openshift/cloud-credential-operator/pkg/operator/metrics"
	"github.com/openshift/cloud-credential-operator/pkg/operator/status"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

const (
	controllerName       = "cleanup"
	defaultRequeuePeriod = time.Minute * 5
)

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	r := &ReconcileStaleCredentialsRequest{
		ReconcileCredentialsRequest: credentialsrequest.ReconcileCredentialsRequest{
			Client: mgr.GetClient(),
		},
	}
	status.AddHandler(controllerName, &r.ReconcileCredentialsRequest)
	return r
}

// Add creates a new Cleanup Controller and adds it to the Manager.
func Add(mgr manager.Manager, kubeConfig string) error {
	r := newReconciler(mgr)

	// Create a new controller
	c, err := controller.New(controllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// trigger a sync only in case of an event for a stale credential request
	stateCredentialRequestPredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			return isStaleCredentialsRequest(e.MetaNew.GetNamespace(), e.MetaNew.GetName())
		},
		CreateFunc: func(e event.CreateEvent) bool {
			return isStaleCredentialsRequest(e.Meta.GetNamespace(), e.Meta.GetName())
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return isStaleCredentialsRequest(e.Meta.GetNamespace(), e.Meta.GetName())
		},
	}

	// Watch for changes to CredentialsRequest and reconcile only the stale one
	err = c.Watch(
		&source.Kind{Type: &minterv1.CredentialsRequest{}},
		&handler.EnqueueRequestForObject{},
		stateCredentialRequestPredicate)
	if err != nil {
		return err
	}

	return nil
}

func isStaleCredentialsRequest(namespace, credentialRequestName string) bool {
	cr := types.NamespacedName{Name: credentialRequestName, Namespace: namespace}

	if contains(constants.StaleCredentialsRequests, cr) {
		log.WithField("cr", credentialRequestName).WithField("namespace", namespace).Info("observed stale credential request event")
		return true
	}

	return false
}

// contains checks if a given credential request is present in a slice of stale credential requests
func contains(credentialRequests []types.NamespacedName, credentialRequest types.NamespacedName) bool {
	for _, cr := range credentialRequests {
		if cr == credentialRequest {
			return true
		}
	}
	return false
}

var _ reconcile.Reconciler = &ReconcileStaleCredentialsRequest{}

// ReconcileStaleCredentialsRequest reconciles a stale CredentialsRequest object
type ReconcileStaleCredentialsRequest struct {
	ReconcileCredentialsRequest credentialsrequest.ReconcileCredentialsRequest
}

// Reconcile marks the stale CredentialsRequest object for deletion
func (r *ReconcileStaleCredentialsRequest) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	start := time.Now()

	logger := log.WithFields(log.Fields{
		"controller": controllerName,
		"cr":         fmt.Sprintf("%s/%s", request.NamespacedName.Namespace, request.NamespacedName.Name),
	})

	defer func() {
		dur := time.Since(start)
		metrics.MetricControllerReconcileTime.WithLabelValues(controllerName).Observe(dur.Seconds())
	}()

	mode, conflict, err := utils.GetOperatorConfiguration(r.ReconcileCredentialsRequest.Client, logger)
	if err != nil {
		logger.WithError(err).Error("error checking if operator is disabled")
		return reconcile.Result{}, err
	} else if conflict {
		logger.Error("configuration conflict betwen legacy configmap and operator config")
		return reconcile.Result{}, fmt.Errorf("configuration conflict")
	}

	logger.Info("syncing stale credentials request")
	cr := &minterv1.CredentialsRequest{}
	err = r.ReconcileCredentialsRequest.Get(context.TODO(), request.NamespacedName, cr)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Debug("credentials request no longer exists")
			return reconcile.Result{}, nil
		}
		logger.WithError(err).Error("error getting credentials request, requeuing")
		return reconcile.Result{}, err
	}
	logger = logger.WithFields(log.Fields{
		"secret": fmt.Sprintf("%s/%s", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name),
	})

	origCR := cr
	cr = cr.DeepCopy()

	if mode == operatorv1.CloudCredentialsModeManual {
		logger.Warnf("operator set to disabled / manual mode, user needs to delete stale credentials")

		msg := fmt.Sprintf("CredentialsRequest is no longer required. Delete CR, Secret containing credentials, and associated platform/cloud resources")
		reason := "CredentialsNoLongerRequired"
		updateCheck := utils.UpdateConditionIfReasonOrMessageChange
		status := corev1.ConditionTrue

		cr.Status.Conditions = utils.SetCredentialsRequestCondition(cr.Status.Conditions, minterv1.StaleCredentials,
			status, reason, msg, updateCheck)

		err := r.ReconcileCredentialsRequest.UpdateStatus(origCR, cr, logger)
		if err != nil {
			logger.WithError(err).Error("failed to update conditions")
		}

		return reconcile.Result{}, err
	}

	// Delete stale credentials request
	if cr.DeletionTimestamp == nil {
		err = r.ReconcileCredentialsRequest.Client.Delete(context.TODO(), cr)
	}

	return reconcile.Result{
		RequeueAfter: defaultRequeuePeriod,
	}, err
}
