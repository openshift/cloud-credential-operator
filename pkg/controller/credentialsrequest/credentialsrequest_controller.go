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

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1beta1"
	"github.com/openshift/cloud-credential-operator/pkg/controller/credentialsrequest/actuator"
	"github.com/openshift/cloud-credential-operator/pkg/controller/internalcontroller"
	"github.com/openshift/cloud-credential-operator/pkg/controller/secretannotator"
	"github.com/openshift/cloud-credential-operator/pkg/controller/utils"

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
	namespaceMissing = "NamespaceMissing"
	namespaceExists  = "NamespaceExists"

	cloudCredsInsufficient = "CloudCredsInsufficient"
	cloudCredsSufficient   = "CloudCredsSufficient"

	credentialsProvisionFailure = "CredentialsProvisionFailure"
	credentialsProvisionSuccess = "CredentialsProvisionSuccess"

	cloudCredDeprovisionFailure = "CloudCredDeprovisionFailure"
	cloudCredDeprovisionSuccess = "CloudCredDeprovisionSuccess"
)

// AddWithActuator creates a new CredentialsRequest Controller and adds it to the Manager with
// default RBAC. The Manager will set fields on the Controller and Start it when
// the Manager is Started.
func AddWithActuator(mgr manager.Manager, actuator actuator.Actuator) error {
	return add(mgr, newReconciler(mgr, actuator))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, actuator actuator.Actuator) reconcile.Reconciler {
	return &ReconcileCredentialsRequest{
		Client:   mgr.GetClient(),
		Actuator: actuator,
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Inject dependencies into Reconciler
	if err := mgr.SetFields(r); err != nil {
		return err
	}

	name := "credentialsrequest-controller"

	// Custom rateLimiter that sets minimum backoff to 2 seconds
	rateLimiter := workqueue.NewMaxOfRateLimiter(
		workqueue.NewItemExponentialFailureRateLimiter(2*time.Second, 1000*time.Second),
		&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
	)

	// Create controller with dependencies set
	c := &internalcontroller.Controller{
		Do:       r,
		Cache:    mgr.GetCache(),
		Config:   mgr.GetConfig(),
		Scheme:   mgr.GetScheme(),
		Client:   mgr.GetClient(),
		Recorder: mgr.GetRecorder(name),
		Queue:    workqueue.NewNamedRateLimitingQueue(rateLimiter, name),
		MaxConcurrentReconciles: 1,
		Name: name,
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
			mgr.GetClient().List(context.TODO(), &client.ListOptions{}, crs)
			requests := []reconcile.Request{}
			for _, cr := range crs.Items {
				if !cr.Status.Provisioned && cr.Spec.SecretRef.Namespace == newNamespace {
					log.WithFields(log.Fields{
						"namespace": newNamespace,
						"cr":        fmt.Sprintf("%s/%s", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name),
					}).Info("found credentials request for namespace")
					requests = append(requests, reconcile.Request{
						NamespacedName: types.NamespacedName{
							Name:      cr.Name,
							Namespace: cr.Namespace,
						},
					})
				}
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
	Actuator actuator.Actuator
}

// Reconcile reads that state of the cluster for a CredentialsRequest object and
// makes changes based on the state read and what is in the CredentialsRequest.Spec
// Automatically generate RBAC rules to allow the Controller to read and write required types.
// +kubebuilder:rbac:groups=cloudcredential.openshift.io,resources=credentialsrequests;credentialsrequests/status;credentialsrequests/finalizers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// TODO: temporary, used for cluster-config-v1, no way to limit by namespace+name today.
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.openshift.io,resources=clusterversions,verbs=get;list;watch
func (r *ReconcileCredentialsRequest) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	logger := log.WithFields(log.Fields{
		"controller": "credreq",
		"cr":         fmt.Sprintf("%s/%s", request.NamespacedName.Namespace, request.NamespacedName.Name),
	})

	logger.Info("syncing credentials request")
	cr := &minterv1.CredentialsRequest{}
	err := r.Get(context.TODO(), request.NamespacedName, cr)
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
	// Maintain a copy, but work on a copy of the credentials request:
	origCR := cr
	cr = cr.DeepCopy()

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

			// Delete the target secret if it exists:
			targetSecret := &corev1.Secret{}
			err := r.Client.Get(context.TODO(), types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, targetSecret)
			sLog := logger.WithFields(log.Fields{
				"targetSecret": fmt.Sprintf("%s/%s", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name),
			})
			if err != nil {
				if errors.IsNotFound(err) {
					sLog.Debug("target secret does not exist")
				}
				sLog.WithError(err).Error("unexpected error getting target secret to delete")
				return reconcile.Result{}, err
			} else {
				err := r.Client.Delete(context.TODO(), targetSecret)
				if err != nil {
					sLog.WithError(err).Error("error deleting target secret")
					return reconcile.Result{}, err
				} else {
					sLog.Info("target secret deleted successfully")
				}
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
	err = r.Get(context.TODO(), types.NamespacedName{Name: cr.Spec.SecretRef.Namespace}, targetNS)
	if err != nil {
		if errors.IsNotFound(err) {
			// TODO: technically we should deprovision if a credential was in this ns, but it
			// was then deleted.
			logger.Warn("secret namespace does not yet exist")
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
	} else {
		logger.Debug("found secret namespace")
		setMissingTargetNamespaceCondition(cr, false)
	}

	// Now figure out whether we need to create new creds/secrets to satisfy the CredentialsRequest

	updateNeeded, err := r.Actuator.NeedsUpdate(context.TODO(), cr)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("error determining whether updated creds are needed: %v", err)
	}
	if !updateNeeded {
		logger.Debug("creds already satisfy the CredentialsRequest")
		cr.Status.Provisioned = true
	} else {

		cloudCredSecret := &corev1.Secret{}
		if err := r.Get(context.Background(), types.NamespacedName{Name: secretannotator.CloudCredSecretName, Namespace: secretannotator.CloudCredSecretNamespace}, cloudCredSecret); err != nil {
			logger.WithError(err).Error("unable to fetch cloud cred secret")
			return reconcile.Result{}, err
		}

		if !properlyAnnotatedSecret(cloudCredSecret) {
			logger.WithField("secret", fmt.Sprintf("%s/%s", secretannotator.CloudCredSecretNamespace, secretannotator.CloudCredSecretName)).Info("cloud cred secret not yet annotated")
			return reconcile.Result{}, fmt.Errorf("waiting for cloud cred secret annotation before proceeding")
		}

		if cloudCredSecret.Annotations[secretannotator.AnnotationKey] == secretannotator.MintAnnotation {
			err = r.mintCredsWithActuator(cr, logger)
			if err != nil {
				logger.WithError(err).Errorf("error while minting credentials")
				setFailedToProvisionCredentialsRequest(cr, true, err)
				if err := r.updateStatus(origCR, cr, logger); err != nil {
					logger.WithError(err).Error("failed to update condition")
					return reconcile.Result{}, err
				}
				return reconcile.Result{}, err
			}
		} else if cloudCredSecret.Annotations[secretannotator.AnnotationKey] == secretannotator.PassthroughAnnotation {
			cr, err = r.usePassthroughCreds(cr, cloudCredSecret, logger)
			if err != nil {
				logger.WithError(err).Errorf("error while trying to use creds as passthrough")
				setFailedToProvisionCredentialsRequest(cr, true, err)
				if err := r.updateStatus(origCR, cr, logger); err != nil {
					logger.WithError(err).Error("failed to update condition")
				}
				return reconcile.Result{}, err
			}
		} else if cloudCredSecret.Annotations[secretannotator.AnnotationKey] == secretannotator.InsufficientAnnotation {
			// update status on credentialsrequest to indicate we can't satisfy the request
			logger.Debug("insufficient creds for passthrough or minting")
			setInsufficientCredsCondition(cr, true)
			if err := r.updateStatus(origCR, cr, logger); err != nil {
				logger.WithError(err).Error("failed to update status")
				return reconcile.Result{}, err
			}
			// Returning error, will retry with the expectation that someone will notice
			// the bad condition(s) and fix
			return reconcile.Result{}, fmt.Errorf("insufficient creds to satisfy CredentialsRequest: %v", cr.Name)
		}

		setInsufficientCredsCondition(cr, false)
		setFailedToProvisionCredentialsRequest(cr, false, nil)
	}

	err = r.updateStatus(origCR, cr, logger)
	if err != nil {
		return reconcile.Result{}, err
	}

	// Ensure we have the controller reference set on the managed secret if it exists:
	// TODO: we could refactor a bit so this is set when it's created, but it's done in sync.go which currently doesn't know about the full CR.
	secret := &corev1.Secret{}
	err = r.Client.Get(context.TODO(), types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, secret)
	if err != nil {
		logger.WithError(err).Error("error looking up secret")
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileCredentialsRequest) usePassthroughCreds(cr *minterv1.CredentialsRequest, cloudCredSecret *corev1.Secret, logger log.FieldLogger) (*minterv1.CredentialsRequest, error) {
	secretAlreadyExists := true
	existingSecret := &corev1.Secret{}
	err := r.Get(context.Background(), types.NamespacedName{Name: cr.Spec.SecretRef.Name, Namespace: cr.Spec.SecretRef.Namespace}, existingSecret)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Debug("existing secret not found. will create one.")
			secretAlreadyExists = false
		} else {
			logger.WithError(err).Error("error checking if the secret satisfying the credentialsrequest already exists")
			return nil, err
		}
	}

	if secretAlreadyExists {
		logger.Debug("Update if necessary")

		if updateExistingSecret(existingSecret, cloudCredSecret) {
			logger.Debugf("updating existing secret")

			err = r.Update(context.Background(), existingSecret)
			if err != nil {
				logger.WithError(err).Error("error updating existing secret")
				return nil, err
			}
		}
	} else {
		logger.Debug("Creating a secret")

		newSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cr.Spec.SecretRef.Name,
				Namespace: cr.Spec.SecretRef.Namespace,
				Annotations: map[string]string{
					minterv1.AnnotationCredentialsRequest: fmt.Sprintf("%s/%s", cr.Namespace, cr.Name),
				},
			},
			Data: map[string][]byte{
				secretannotator.AwsAccessKeyName:       cloudCredSecret.Data[secretannotator.AwsAccessKeyName],
				secretannotator.AwsSecretAccessKeyName: cloudCredSecret.Data[secretannotator.AwsSecretAccessKeyName],
			},
		}

		// create secret
		if err := r.Create(context.Background(), newSecret); err != nil {
			logger.WithError(err).Error("error creating secret")
			return nil, err
		}

		logger.Debug("created secret successfully")
		cr.Status.Provisioned = true
	}

	return cr, nil
}

func setMissingTargetNamespaceCondition(cr *minterv1.CredentialsRequest, missing bool) {
	var (
		msg, reason string
		status      corev1.ConditionStatus
		updateCheck utils.UpdateConditionCheck
	)
	if missing {
		msg = fmt.Sprintf("target namespace %v not found", cr.Spec.SecretRef.Namespace)
		status = corev1.ConditionTrue
		reason = namespaceMissing
		updateCheck = utils.UpdateConditionIfReasonOrMessageChange
	} else {
		msg = fmt.Sprintf("target namespace %v found", cr.Spec.SecretRef.Namespace)
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

func updateExistingSecret(existing, cloudCred *corev1.Secret) bool {
	if string(existing.Data[secretannotator.AwsAccessKeyName]) != string(cloudCred.Data[secretannotator.AwsAccessKeyName]) ||
		string(existing.Data[secretannotator.AwsSecretAccessKeyName]) != string(cloudCred.Data[secretannotator.AwsSecretAccessKeyName]) {
		existing.Data[secretannotator.AwsAccessKeyName] = cloudCred.Data[secretannotator.AwsAccessKeyName]
		existing.Data[secretannotator.AwsSecretAccessKeyName] = cloudCred.Data[secretannotator.AwsSecretAccessKeyName]
		return true
	}
	return false
}

func (r *ReconcileCredentialsRequest) mintCredsWithActuator(cr *minterv1.CredentialsRequest, logger log.FieldLogger) error {
	// Hand over to the actuator:
	exists, err := r.Actuator.Exists(context.TODO(), cr)
	if err != nil {
		logger.WithError(err).Error("actuator error checking if credentials exist")
		return err
	}
	if !exists {
		err = r.Actuator.Create(context.TODO(), cr)
		if err != nil {
			logger.WithError(err).Error("actuator error creating credentials")
			return err
		}
		cr.Status.Provisioned = true
	} else {
		err = r.Actuator.Update(context.TODO(), cr)
		if err != nil {
			logger.WithError(err).Error("actuator error updating credentials")
			return err
		}
		cr.Status.Provisioned = true
	}

	return nil
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

func properlyAnnotatedSecret(secret *corev1.Secret) bool {
	if secret.ObjectMeta.Annotations == nil {
		return false
	}

	if _, ok := secret.ObjectMeta.Annotations[secretannotator.AnnotationKey]; !ok {
		return false
	}

	return true
}

func getCredCreationMode(cloudCredSecret *corev1.Secret) string {
	return cloudCredSecret.Annotations[secretannotator.AnnotationKey]
}
