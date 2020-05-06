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
	"fmt"
	"reflect"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/actuator"
	"github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/internalcontroller"
	"github.com/openshift/cloud-credential-operator/pkg/operator/metrics"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"

	configv1 "github.com/openshift/api/config/v1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	controllerName = "credreq"

	namespaceMissing = "NamespaceMissing"
	namespaceExists  = "NamespaceExists"

	cloudCredsInsufficient = "CloudCredsInsufficient"
	cloudCredsSufficient   = "CloudCredsSufficient"

	credentialsProvisionFailure = "CredentialsProvisionFailure"
	credentialsProvisionSuccess = "CredentialsProvisionSuccess"

	cloudCredDeprovisionFailure = "CloudCredDeprovisionFailure"
	cloudCredDeprovisionSuccess = "CloudCredDeprovisionSuccess"

	credentialsRequestInfraMismatch          = "InfrastructureMismatch"
	credentialsRequestUnsupportedStorageType = "UnsupportedStorageType"
	credentialsRequestInvalidStorageRef      = "InvalidStorageRef"
	credentialsRequestInvalidStorageType     = "InvalidStorageType"
)

// AddWithActuator creates a new CredentialsRequest Controller and adds it to the Manager with
// default RBAC. The Manager will set fields on the Controller and Start it when
// the Manager is Started.
func AddWithActuator(mgr manager.Manager, actuator actuator.Actuator, platType configv1.PlatformType) error {
	return add(mgr, newReconciler(mgr, actuator, platType))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, actuator actuator.Actuator, platType configv1.PlatformType) reconcile.Reconciler {
	return &ReconcileCredentialsRequest{
		Client:       mgr.GetClient(),
		Actuator:     actuator,
		platformType: platType,
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Inject dependencies into Reconciler
	if err := mgr.SetFields(r); err != nil {
		return err
	}

	name := "credentialsrequest_controller"

	// Custom rateLimiter that sets minimum backoff to 2 seconds
	rateLimiter := workqueue.NewMaxOfRateLimiter(
		workqueue.NewItemExponentialFailureRateLimiter(2*time.Second, 1000*time.Second),
		&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
	)

	// Create controller with dependencies set
	c := &internalcontroller.Controller{
		Do:                      r,
		Cache:                   mgr.GetCache(),
		Config:                  mgr.GetConfig(),
		Scheme:                  mgr.GetScheme(),
		Client:                  mgr.GetClient(),
		Recorder:                mgr.GetEventRecorderFor(name),
		Queue:                   workqueue.NewNamedRateLimitingQueue(rateLimiter, name),
		MaxConcurrentReconciles: 1,
		Name:                    name,
	}

	if err := mgr.Add(c); err != nil {
		return err
	}

	// Watch for changes to CredentialsRequest
	// TODO: we should limit the namespaces where we watch, we want all requests in one namespace so anyone with admin on a namespace cannot create
	// a request for any credentials they want.
	err := c.Watch(&source.Kind{Type: &minterv1.CredentialsRequest{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// Define a mapping for secrets to the credentials requests that created them. (if applicable)
	// We use an annotation on secrets that refers back to their owning credentials request because
	// the normal owner reference is not namespaced, and we want to support credentials requests being
	// in a centralized namespace, but writing secrets into component namespaces.
	mapFn := handler.ToRequestsFunc(
		func(a handler.MapObject) []reconcile.Request {
			// Predicate below should ensure this map function is not called if the
			// secret does not have our label:
			namespace, name, err := cache.SplitMetaNamespaceKey(a.Meta.GetAnnotations()[minterv1.AnnotationCredentialsRequest])
			if err != nil {
				log.WithField("labels", a.Meta.GetAnnotations()).WithError(err).Error("error splitting namespace key for label")
				// WARNING: No way to return an error here...
				return []reconcile.Request{}
			}

			log.WithField("cr", fmt.Sprintf("%s/%s", namespace, name)).Debug("parsed annotation")

			return []reconcile.Request{
				{NamespacedName: types.NamespacedName{
					Name:      name,
					Namespace: namespace,
				}},
			}
		})

	// These functions are used to determine if a event for the given object should trigger a sync:
	p := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			// The object doesn't contain our label, so we have nothing to reconcile.
			if _, ok := e.MetaOld.GetAnnotations()[minterv1.AnnotationCredentialsRequest]; !ok {
				return false
			}
			return true
		},
		CreateFunc: func(e event.CreateEvent) bool {
			if _, ok := e.Meta.GetAnnotations()[minterv1.AnnotationCredentialsRequest]; !ok {
				return false
			}
			return true
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			if _, ok := e.Meta.GetAnnotations()[minterv1.AnnotationCredentialsRequest]; !ok {
				return false
			}
			return true
		},
	}

	// Watch Secrets and reconcile if we see one with our label.
	err = c.Watch(
		&source.Kind{Type: &corev1.Secret{}},
		&handler.EnqueueRequestsFromMapFunc{
			ToRequests: mapFn,
		},
		p)
	if err != nil {
		return err
	}

	// Monitor namespace creation, and check out list of credentials requests for any destined
	// for that new namespace. This allows us to be up and running for other components that don't
	// yet exist, but will.
	namespaceMapFn := handler.ToRequestsFunc(
		func(a handler.MapObject) []reconcile.Request {

			// Iterate all CredentialsRequests to determine if we have any that target
			// this new namespace. We are not anticipating huge numbers of CredentailsRequests,
			// nor namespace creations.
			newNamespace := a.Meta.GetName()
			log.WithField("namespace", newNamespace).Debug("checking for credentials requests targeting namespace")
			crs := &minterv1.CredentialsRequestList{}
			mgr.GetClient().List(context.TODO(), crs)
			requests := []reconcile.Request{}
			for _, cr := range crs.Items {
				if cr.Status.Provisioned ||
					cr.Spec.Storage.Type != minterv1.SecretStorageType ||
					cr.Spec.Storage.Secret.Namespace != newNamespace {
					continue
				}
				log.WithFields(log.Fields{
					"namespace": newNamespace,
					"cr":        fmt.Sprintf("%s/%s", cr.Spec.Storage.Secret.Namespace, cr.Spec.Storage.Secret.Name),
				}).Info("found credentials request for namespace")
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      cr.Name,
						Namespace: cr.Namespace,
					},
				})
			}
			return requests
		})

	namespacePred := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			// WARNING: on restart, the controller sees all namespaces as creates even if they
			// are pre-existing
			return true
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return false
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return false
		},
	}

	err = c.Watch(
		&source.Kind{Type: &corev1.Namespace{}},
		&handler.EnqueueRequestsFromMapFunc{
			ToRequests: namespaceMapFn,
		},
		namespacePred)
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileCredentialsRequest{}

// ReconcileCredentialsRequest reconciles a CredentialsRequest object
type ReconcileCredentialsRequest struct {
	client.Client
	Actuator     actuator.Actuator
	platformType configv1.PlatformType
}

// Reconcile reads that state of the cluster for a CredentialsRequest object and
// makes changes based on the state read and what is in the CredentialsRequest.Spec
// Automatically generate RBAC rules to allow the Controller to read and write required types.
// +kubebuilder:rbac:groups=cloudcredential.openshift.io,resources=credentialsrequests;credentialsrequests/status;credentialsrequests/finalizers,verbs=get;list;watch;create;update;patch;delete
// Configmaps required for leader election:
// +kubebuilder:rbac:groups=core,resources=secrets;configmaps;events,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.openshift.io,resources=clusterversions,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.openshift.io,resources=infrastructures;dnses,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.openshift.io,resources=clusteroperators;clusteroperators/status,verbs=create;get;update;list;watch
func (r *ReconcileCredentialsRequest) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	start := time.Now()

	logger := log.WithFields(log.Fields{
		"controller": controllerName,
		"cr":         fmt.Sprintf("%s/%s", request.NamespacedName.Namespace, request.NamespacedName.Name),
	})

	// Ensure we always sync operator status after reconciling, even if an error occurred.
	// TODO: Should this be another controller?
	defer func() {
		err := r.syncOperatorStatus()
		if err != nil {
			logger.WithError(err).Error("failed to sync operator status")
		}
		dur := time.Since(start)
		metrics.MetricControllerReconcileTime.WithLabelValues(controllerName).Observe(dur.Seconds())
	}()

	operatorIsDisabled, err := utils.IsOperatorDisabled(r.Client, logger)
	if err != nil {
		logger.WithError(err).Error("error checking if operator is disabled")
		return reconcile.Result{}, err
	} else if operatorIsDisabled {
		logger.Infof("operator disabled in %s ConfigMap", minterv1.CloudCredOperatorConfigMap)
		return reconcile.Result{}, err
	}

	logger.Info("syncing credentials request")
	cr := &minterv1.CredentialsRequest{}
	err = r.Get(context.TODO(), request.NamespacedName, cr)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Debug("credentials request no longer exists")
			return reconcile.Result{}, nil
		}
		logger.WithError(err).Error("error getting credentials request, requeuing")
		return reconcile.Result{}, err
	}

	// Maintain a copy, but work on a copy of the credentials request:
	origCR := cr
	cr = cr.DeepCopy()

	// Copy deprecated secretRef to the new storage field for internal processing
	if cr.Spec.Storage.Type == "" {
		cr.Spec.Storage.Type = minterv1.SecretStorageType
		cr.Spec.Storage.Secret = &minterv1.SecretStorage{
			Namespace: cr.Spec.SecretRef.Namespace,
			Name:      cr.Spec.SecretRef.Name,
		}
	}

	storageType := cr.Spec.Storage.Type

	if storageType != minterv1.SecretStorageType && storageType != minterv1.ServiceAccountStorageType {
		setInvalidStorageType(cr, r.platformType)
		err := r.updateStatus(origCR, cr, logger)
		if err != nil {
			logger.WithError(err).Error("failed to update conditions")
		}
		return reconcile.Result{}, err
	}

	// CRs must contain a reference for their storage type (union)
	if (storageType == minterv1.SecretStorageType && cr.Spec.Storage.Secret == nil) ||
		(storageType == minterv1.ServiceAccountStorageType && cr.Spec.Storage.ServiceAccount == nil) {
		setInvalidStorageRef(cr, r.platformType)
		err := r.updateStatus(origCR, cr, logger)
		if err != nil {
			logger.WithError(err).Error("failed to update conditions")
		}
		return reconcile.Result{}, err
	}

	var namespace, name string
	if storageType == minterv1.SecretStorageType {
		namespace = cr.Spec.Storage.Secret.Namespace
		name = cr.Spec.Storage.Secret.Name

	} else if storageType == minterv1.ServiceAccountStorageType {
		namespace = cr.Spec.Storage.ServiceAccount.Namespace
		name = cr.Spec.Storage.ServiceAccount.Name
	}
	logger = logger.WithFields(log.Fields{
		"storage": fmt.Sprintf("%s %s/%s", storageType, namespace, name),
	})

	// Ignore CR if it's for a different cloud/infra
	infraMatch, err := crInfraMatches(cr, r.platformType)
	if err != nil {
		logger.WithError(err).Error("failed to determine cloud platform type")
		return reconcile.Result{}, err
	}
	if !infraMatch {
		logger.Debug("ignoring cr as it is for a different cloud")
		setIgnoredCondition(cr, r.platformType)
		err := r.updateStatus(origCR, cr, logger)
		if err != nil {
			logger.WithError(err).Error("failed to update conditions")
		}
		return reconcile.Result{}, err
	}

	// CRs for platforms other than AWS require secret storage type
	if r.platformType != configv1.AWSPlatformType && storageType != minterv1.SecretStorageType {
		setUnsupportedStorageType(cr, r.platformType)
		err := r.updateStatus(origCR, cr, logger)
		if err != nil {
			logger.WithError(err).Error("failed to update conditions")
		}
		return reconcile.Result{}, err
	}

	// Handle deletion and the deprovision finalizer:
	if cr.DeletionTimestamp != nil {
		if HasFinalizer(cr, minterv1.FinalizerDeprovision) {
			err = r.Actuator.Delete(context.TODO(), cr)
			if err != nil {
				logger.WithError(err).Error("actuator error deleting credentials exist")

				setCredentialsDeprovisionFailureCondition(cr, true, err)
				if err := r.updateStatus(origCR, cr, logger); err != nil {
					logger.WithError(err).Error("failed to update condition")
					return reconcile.Result{}, err
				}
				return reconcile.Result{}, err
			} else {
				setCredentialsDeprovisionFailureCondition(cr, false, nil)
				if err := r.updateStatus(origCR, cr, logger); err != nil {
					// Just a warning, since on deprovision we're just tearing down
					// the CredentialsRequest object anyway
					logger.Warnf("unable to update condition: %v", err)
				}
			}

			if storageType == minterv1.SecretStorageType {
				// Delete the target secret if it exists
				secretRef := cr.Spec.Storage.Secret
				targetSecret := &corev1.Secret{}
				err := r.Client.Get(context.TODO(), types.NamespacedName{Namespace: secretRef.Namespace, Name: secretRef.Name}, targetSecret)
				sLog := logger.WithFields(log.Fields{
					"targetSecret": fmt.Sprintf("%s/%s", secretRef.Namespace, secretRef.Name),
				})
				if err != nil {
					if errors.IsNotFound(err) {
						sLog.Debug("target secret does not exist")
					} else {
						sLog.WithError(err).Error("unexpected error getting target secret to delete")
						return reconcile.Result{}, err
					}
				} else {
					err := r.Client.Delete(context.TODO(), targetSecret)
					if err != nil {
						sLog.WithError(err).Error("error deleting target secret")
						return reconcile.Result{}, err
					} else {
						sLog.Info("target secret deleted successfully")
					}
				}
			} else if storageType == minterv1.ServiceAccountStorageType {
				// TODO: remove annotation from service account
				// TODO: should we annotation service accounts we create (vs just annotate) and clean them up?
			}

			logger.Info("actuator deletion complete, removing finalizer")
			err = r.removeDeprovisionFinalizer(cr)
			if err != nil {
				logger.WithError(err).Error("error removing deprovision finalizer")
				return reconcile.Result{}, err
			}
			return reconcile.Result{}, nil
		} else {
			logger.Info("credentials request deleted and finalizer no longer present, nothing to do")
			return reconcile.Result{}, nil
		}
	} else {
		if !HasFinalizer(cr, minterv1.FinalizerDeprovision) {
			// Ensure the finalizer is set on any not-deleted requests:
			logger.Infof("adding finalizer: %s", minterv1.FinalizerDeprovision)
			err = r.addDeprovisionFinalizer(cr)
			if err != nil {
				logger.WithError(err).Error("error adding finalizer")
			}
			return reconcile.Result{}, err
		}
	}

	// Ensure the target namespace exists for the secret, if not, there's no point
	// continuing:
	targetNS := &corev1.Namespace{}
	err = r.Get(context.TODO(), types.NamespacedName{Name: namespace}, targetNS)
	if err != nil {
		if errors.IsNotFound(err) {
			// TODO: technically we should deprovision if a credential was in this ns, but it
			// was then deleted.
			logger.Warn("storage  namespace does not yet exist")
			setMissingTargetNamespaceCondition(cr, true)
			if err := r.updateStatus(origCR, cr, logger); err != nil {
				logger.WithError(err).Error("error updating condition")
				return reconcile.Result{}, err
			}
			// We will re-sync immediately when the namespace is created.
			return reconcile.Result{}, nil
		}
		logger.WithError(err).Error("unexpected error looking up namespace")
		return reconcile.Result{}, err
	}

	logger.Debug("found storage  namespace")
	setMissingTargetNamespaceCondition(cr, false)

	// Check if the secret/serviceaccount the credRequest wants created already exists
	exists := true
	if storageType == minterv1.SecretStorageType {
		crSecret := &corev1.Secret{}
		secretKey := types.NamespacedName{
			Namespace: cr.Spec.Storage.Secret.Namespace,
			Name:      cr.Spec.Storage.Secret.Name,
		}
		if err := r.Get(context.TODO(), secretKey, crSecret); err != nil {
			if errors.IsNotFound(err) {
				exists = false
			} else {
				logger.WithError(err).Error("could not query whether secret already exists")
				return reconcile.Result{}, err
			}
		}
	} else if storageType == minterv1.ServiceAccountStorageType {
		crServiceAccount := &corev1.ServiceAccount{}
		serviceAccountKey := types.NamespacedName{
			Namespace: cr.Spec.Storage.ServiceAccount.Namespace,
			Name:      cr.Spec.Storage.ServiceAccount.Name,
		}
		if err := r.Get(context.TODO(), serviceAccountKey, crServiceAccount); err != nil {
			if errors.IsNotFound(err) {
				exists = false
			} else {
				logger.WithError(err).Error("could not query whether serviceaccount already exists")
				return reconcile.Result{}, err
			}
		}
	}

	isStale := cr.Generation != cr.Status.LastSyncGeneration
	hasRecentlySynced := cr.Status.LastSyncTimestamp != nil && cr.Status.LastSyncTimestamp.Add(time.Hour*1).After(time.Now())
	hasActiveFailureConditions := checkForFailureConditions(cr)

	if !isStale && hasRecentlySynced && exists && !hasActiveFailureConditions && cr.Status.Provisioned {
		logger.Debug("lastsyncgeneration is current and lastsynctimestamp was less than an hour ago, so no need to sync")
		return reconcile.Result{}, nil
	}

	credsExists, err := r.Actuator.Exists(context.TODO(), cr)
	if err != nil {
		logger.Errorf("error checking whether credentials already exists: %v", err)
		return reconcile.Result{}, err
	}

	var syncErr error
	if !credsExists {
		syncErr = r.Actuator.Create(context.TODO(), cr)
	} else {
		syncErr = r.Actuator.Update(context.TODO(), cr)
	}
	if syncErr != nil {
		logger.Errorf("error syncing credentials: %v", syncErr)
		// TODO: set condition if previously satisfied credrequest can now
		// not be satisfied (but keeping provisioned==True).
		cr.Status.Provisioned = false

		switch t := syncErr.(type) {
		case actuator.ActuatorStatus:
			logger.Errorf("errored with condition: %v", t.Reason())
			r.updateActuatorConditions(cr, t.Reason(), syncErr)
		default:
			logger.Errorf("unexpected error while syncing credentialsrequest: %v", syncErr)
			return reconcile.Result{}, syncErr
		}

	} else {
		// it worked so clear any actuator conditions if they exist
		r.updateActuatorConditions(cr, "", nil)

		cr.Status.Provisioned = true
		cr.Status.LastSyncTimestamp = &metav1.Time{
			Time: time.Now(),
		}
		cr.Status.LastSyncGeneration = origCR.Generation
	}

	err = r.updateStatus(origCR, cr, logger)
	if err != nil {
		logger.Errorf("error updating status: %v", err)
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, syncErr
}

func (r *ReconcileCredentialsRequest) updateActuatorConditions(cr *minterv1.CredentialsRequest, reason minterv1.CredentialsRequestConditionType, conditionError error) {

	if reason == minterv1.CredentialsProvisionFailure {
		setFailedToProvisionCredentialsRequest(cr, true, conditionError)
	} else {
		// If this is not our error, ensure the condition is cleared.
		setFailedToProvisionCredentialsRequest(cr, false, nil)
	}

	if reason == minterv1.InsufficientCloudCredentials {
		setInsufficientCredsCondition(cr, true)
	} else {
		// If this is not our error, ensure the condition is cleared.
		setInsufficientCredsCondition(cr, false)
	}

	return
}

func setMissingTargetNamespaceCondition(cr *minterv1.CredentialsRequest, missing bool) {
	var (
		msg, reason string
		status      corev1.ConditionStatus
		updateCheck utils.UpdateConditionCheck
	)
	var namespace string
	if cr.Spec.Storage.Type == minterv1.SecretStorageType {
		namespace = cr.Spec.Storage.Secret.Namespace
	} else if cr.Spec.Storage.Type == minterv1.ServiceAccountStorageType {
		namespace = cr.Spec.Storage.ServiceAccount.Namespace
	}
	if missing {
		msg = fmt.Sprintf("target namespace %v not found", namespace)
		status = corev1.ConditionTrue
		reason = namespaceMissing
		updateCheck = utils.UpdateConditionIfReasonOrMessageChange
	} else {
		msg = fmt.Sprintf("target namespace %v found", namespace)
		status = corev1.ConditionFalse
		reason = namespaceExists
		updateCheck = utils.UpdateConditionNever
	}
	cr.Status.Conditions = utils.SetCredentialsRequestCondition(cr.Status.Conditions, minterv1.MissingTargetNamespace,
		status, reason, msg, updateCheck)
}

func setInsufficientCredsCondition(cr *minterv1.CredentialsRequest, insufficient bool) {
	var (
		msg, reason string
		status      corev1.ConditionStatus
		updateCheck utils.UpdateConditionCheck
	)
	if insufficient {
		msg = fmt.Sprintf("cloud creds are insufficient to satisfy CredentialsRequest")
		status = corev1.ConditionTrue
		reason = cloudCredsInsufficient
		updateCheck = utils.UpdateConditionIfReasonOrMessageChange
	} else {
		msg = fmt.Sprintf("cloud credentials sufficient for minting or passthrough")
		status = corev1.ConditionFalse
		reason = cloudCredsSufficient
		updateCheck = utils.UpdateConditionNever
	}
	cr.Status.Conditions = utils.SetCredentialsRequestCondition(cr.Status.Conditions, minterv1.InsufficientCloudCredentials,
		status, reason, msg, updateCheck)
}

func setFailedToProvisionCredentialsRequest(cr *minterv1.CredentialsRequest, failed bool, err error) {
	var (
		msg, reason string
		status      corev1.ConditionStatus
		updateCheck utils.UpdateConditionCheck
	)
	if failed {
		msg = fmt.Sprintf("failed to grant creds: %v", err)
		status = corev1.ConditionTrue
		reason = credentialsProvisionFailure
		updateCheck = utils.UpdateConditionIfReasonOrMessageChange
	} else {
		msg = fmt.Sprintf("successfully granted credentials request")
		status = corev1.ConditionFalse
		reason = credentialsProvisionSuccess
		updateCheck = utils.UpdateConditionNever
	}
	cr.Status.Conditions = utils.SetCredentialsRequestCondition(cr.Status.Conditions, minterv1.CredentialsProvisionFailure,
		status, reason, msg, updateCheck)
}

func setCredentialsDeprovisionFailureCondition(cr *minterv1.CredentialsRequest, failed bool, err error) {
	var (
		msg, reason string
		status      corev1.ConditionStatus
		updateCheck utils.UpdateConditionCheck
	)
	if failed {
		msg = fmt.Sprintf("failed to deprovision resource: %v", err)
		status = corev1.ConditionTrue
		reason = cloudCredDeprovisionFailure
		updateCheck = utils.UpdateConditionIfReasonOrMessageChange
	} else {
		msg = fmt.Sprintf("deprovisioned cloud credential resource(s)")
		status = corev1.ConditionFalse
		reason = cloudCredDeprovisionSuccess
		updateCheck = utils.UpdateConditionNever
	}
	cr.Status.Conditions = utils.SetCredentialsRequestCondition(cr.Status.Conditions, minterv1.CredentialsDeprovisionFailure,
		status, reason, msg, updateCheck)
}

func setIgnoredCondition(cr *minterv1.CredentialsRequest, clusterPlatform configv1.PlatformType) {
	// Only supporting the ability to set the condition
	msg := fmt.Sprintf("CredentialsRequest is not for platform %s", clusterPlatform)
	reason := credentialsRequestInfraMismatch
	updateCheck := utils.UpdateConditionIfReasonOrMessageChange
	status := corev1.ConditionTrue

	cr.Status.Conditions = utils.SetCredentialsRequestCondition(cr.Status.Conditions, minterv1.Ignored,
		status, reason, msg, updateCheck)

	// Also clear any other conditions since we are ignoring this cred request,
	// and we don't want to be in a degraded state b/c of cred requests that we're ignoring.
	for _, cond := range constants.FailureConditionTypes {
		cr.Status.Conditions = utils.SetCredentialsRequestCondition(cr.Status.Conditions, cond,
			corev1.ConditionFalse, reason, msg, updateCheck)
	}
}

func setInvalidStorageType(cr *minterv1.CredentialsRequest, clusterPlatform configv1.PlatformType) {
	msg := fmt.Sprintf("CredentialsRequest has invalid storage type %s", cr.Spec.Storage.Type)
	reason := credentialsRequestInvalidStorageType
	updateCheck := utils.UpdateConditionIfReasonOrMessageChange
	status := corev1.ConditionTrue

	cr.Status.Conditions = utils.SetCredentialsRequestCondition(cr.Status.Conditions, minterv1.Ignored,
		status, reason, msg, updateCheck)
}

func setUnsupportedStorageType(cr *minterv1.CredentialsRequest, clusterPlatform configv1.PlatformType) {
	msg := fmt.Sprintf("CredentialsRequest with storage type %s is not suppported for platform %s", cr.Spec.Storage.Type, clusterPlatform)
	reason := credentialsRequestUnsupportedStorageType
	updateCheck := utils.UpdateConditionIfReasonOrMessageChange
	status := corev1.ConditionTrue

	cr.Status.Conditions = utils.SetCredentialsRequestCondition(cr.Status.Conditions, minterv1.Ignored,
		status, reason, msg, updateCheck)
}

func setInvalidStorageRef(cr *minterv1.CredentialsRequest, clusterPlatform configv1.PlatformType) {
	msg := fmt.Sprintf("CredentialsRequest requires a storage reference for type %s", cr.Spec.Storage.Type)
	reason := credentialsRequestInvalidStorageRef
	updateCheck := utils.UpdateConditionIfReasonOrMessageChange
	status := corev1.ConditionTrue

	cr.Status.Conditions = utils.SetCredentialsRequestCondition(cr.Status.Conditions, minterv1.Ignored,
		status, reason, msg, updateCheck)
}

func (r *ReconcileCredentialsRequest) updateStatus(origCR, newCR *minterv1.CredentialsRequest, logger log.FieldLogger) error {
	logger.Debug("updating credentials request status")

	// Update cluster deployment status if changed:
	if !reflect.DeepEqual(newCR.Status, origCR.Status) {
		logger.Infof("status has changed, updating")
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

func (r *ReconcileCredentialsRequest) addDeprovisionFinalizer(cr *minterv1.CredentialsRequest) error {
	AddFinalizer(cr, minterv1.FinalizerDeprovision)
	return r.Update(context.TODO(), cr)
}

func (r *ReconcileCredentialsRequest) removeDeprovisionFinalizer(cr *minterv1.CredentialsRequest) error {
	DeleteFinalizer(cr, minterv1.FinalizerDeprovision)
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

func crInfraMatches(cr *minterv1.CredentialsRequest, clusterCloudPlatform configv1.PlatformType) (bool, error) {
	cloudType, err := utils.GetCredentialsRequestCloudType(cr.Spec.ProviderSpec)
	if err != nil {
		return true, fmt.Errorf("error determining cloud type for CredentialsRequest: %v", err)
	}

	switch clusterCloudPlatform {
	case configv1.AWSPlatformType:
		return cloudType == reflect.TypeOf(minterv1.AWSProviderSpec{}).Name(), nil
	case configv1.AzurePlatformType:
		return cloudType == reflect.TypeOf(minterv1.AzureProviderSpec{}).Name(), nil
	case configv1.GCPPlatformType:
		return cloudType == reflect.TypeOf(minterv1.GCPProviderSpec{}).Name(), nil
	case configv1.OpenStackPlatformType:
		return cloudType == reflect.TypeOf(minterv1.OpenStackProviderSpec{}).Name(), nil
	case configv1.OvirtPlatformType:
		return cloudType == reflect.TypeOf(minterv1.OvirtProviderSpec{}).Name(), nil
	case configv1.VSpherePlatformType:
		return cloudType == reflect.TypeOf(minterv1.VSphereProviderSpec{}).Name(), nil
	default:
		return false, fmt.Errorf("unsupported platorm type: %v", clusterCloudPlatform)
	}
}

func checkForFailureConditions(cr *minterv1.CredentialsRequest) bool {
	for _, t := range constants.FailureConditionTypes {
		failureCond := utils.FindCredentialsRequestCondition(cr.Status.Conditions, t)
		if failureCond != nil && failureCond.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}
