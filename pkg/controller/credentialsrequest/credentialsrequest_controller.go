/*
Copyright 2018 The OpenShift Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package credentialsrequest

import (
	"context"
	"reflect"

	log "github.com/sirupsen/logrus"

	ccv1 "github.com/openshift/cloud-creds/pkg/apis/cloudcreds/v1beta1"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// Add creates a new CredentialsRequest Controller and adds it to the Manager with default RBAC. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
// USER ACTION REQUIRED: update cmd/manager/main.go to call this cloudcreds.Add(mgr) to install this Controller
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileCredentialsRequest{Client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("credentialsrequest-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to CredentialsRequest
	err = c.Watch(&source.Kind{Type: &ccv1.CredentialsRequest{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileCredentialsRequest{}

// ReconcileCredentialsRequest reconciles a CredentialsRequest object
type ReconcileCredentialsRequest struct {
	client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a CredentialsRequest object and makes changes based on the state read
// and what is in the CredentialsRequest.Spec
// Automatically generate RBAC rules to allow the Controller to read and write Deployments
// +kubebuilder:rbac:groups=cloudcreds.openshift.io,resources=credentialsrequests,verbs=get;list;watch;create;update;patch;delete
func (r *ReconcileCredentialsRequest) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	logger := log.WithFields(
		log.Fields{
			"controller": "credentialsrequest",
			"name":       request.NamespacedName.Name,
			"namespace":  request.NamespacedName.Namespace,
		})
	logger.Info("syncing credentials request")
	cr := &ccv1.CredentialsRequest{}
	err := r.Get(context.TODO(), request.NamespacedName, cr)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Debug("credentials request no longer exists")
			return reconcile.Result{}, nil
		}
		logger.WithError(err).Error("error getting credentials request, requeuing")
		return reconcile.Result{}, err
	}
	logger.Info("%v", cr.Spec)
	// Maintain a copy, but work on a copy of the credentials request:
	origCR := cr
	cr = cr.DeepCopy()

	if !HasFinalizer(cr, ccv1.FinalizerDeprovision) {
		if cr.DeletionTimestamp == nil {
			// Ensure the finalizer is set on any not-deleted requests:
			logger.Info("adding deprovision finalizer")
			err = r.addDeprovisionFinalizer(cr)
			return reconcile.Result{}, err
		} else {
			// If deleted and finalizer is also gone, we can return, nothing for us to do.
			logger.Info("credentials request deleted and finalizer no longer present, nothing to do")
			return reconcile.Result{}, nil
		}
	}

	if cr.Spec.AWS != nil {
		err := r.reconcileAWS(cr, logger)
		if err != nil {
			logger.WithError(err).Error("error reconciling AWS credentials")
			return reconcile.Result{}, err
		}
	} else {
		logger.Warn("no platform defined")
		return reconcile.Result{}, nil
	}

	err = r.updateStatus(origCR, cr, logger)
	if err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileCredentialsRequest) updateStatus(origCR, newCR *ccv1.CredentialsRequest, logger log.FieldLogger) error {
	logger.Debug("updating credentials request status")

	// Update cluster deployment status if changed:
	if !reflect.DeepEqual(newCR.Status, origCR.Status) {
		logger.Infof("status has changed, updating")
		logger.Debugf("orig: %v", origCR.Status.AWS)
		logger.Debugf("new : %v", *newCR.Status.AWS)
		err := r.Status().Update(context.TODO(), newCR)
		if err != nil {
			logger.WithError(err).Error("error updating credentials request")
			return err
		}
	} else {
		logger.Debugf("status unchanged")
	}

	return nil
}

func (r *ReconcileCredentialsRequest) addDeprovisionFinalizer(cr *ccv1.CredentialsRequest) error {
	cr = cr.DeepCopy()
	AddFinalizer(cr, ccv1.FinalizerDeprovision)
	return r.Update(context.TODO(), cr)
}

func (r *ReconcileCredentialsRequest) removeDeprovisionFinalizer(cr *ccv1.CredentialsRequest) error {
	cr = cr.DeepCopy()
	DeleteFinalizer(cr, ccv1.FinalizerDeprovision)
	return r.Update(context.TODO(), cr)
}

// HasFinalizer returns true if the given object has the given finalizer
func HasFinalizer(object metav1.Object, finalizer string) bool {
	for _, f := range object.GetFinalizers() {
		if f == finalizer {
			return true
		}
	}
	return false
}

// AddFinalizer adds a finalizer to the given object
func AddFinalizer(object metav1.Object, finalizer string) {
	finalizers := sets.NewString(object.GetFinalizers()...)
	finalizers.Insert(finalizer)
	object.SetFinalizers(finalizers.List())
}

// DeleteFinalizer removes a finalizer from the given object
func DeleteFinalizer(object metav1.Object, finalizer string) {
	finalizers := sets.NewString(object.GetFinalizers()...)
	finalizers.Delete(finalizer)
	object.SetFinalizers(finalizers.List())
}
