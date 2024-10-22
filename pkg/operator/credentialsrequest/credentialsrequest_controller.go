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

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/retry"

	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	corev1applyconfigurations "k8s.io/client-go/applyconfigurations/core/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/actuator"
	"github.com/openshift/cloud-credential-operator/pkg/operator/metrics"
	"github.com/openshift/cloud-credential-operator/pkg/operator/status"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

const (
	controllerName      = "credreq"
	labelControllerName = controllerName + "_labeller"

	namespaceMissing = "NamespaceMissing"
	namespaceExists  = "NamespaceExists"

	cloudCredsInsufficient = "CloudCredsInsufficient"
	cloudCredsSufficient   = "CloudCredsSufficient"

	credentialsProvisionFailure = "CredentialsProvisionFailure"
	credentialsProvisionSuccess = "CredentialsProvisionSuccess"

	cloudCredDeprovisionFailure = "CloudCredDeprovisionFailure"
	cloudCredDeprovisionSuccess = "CloudCredDeprovisionSuccess"

	credentialsRequestInfraMismatch = "InfrastructureMismatch"

	cloudResourceOrphaned = "CloudResourceOrphaned"
	cloudResourceCleaned  = "CloudResourceCleaned"
)

var (
	syncPeriod = time.Hour
	// Set some extra time when requeueing so we are guaranteed that the
	// syncPeriod has elapsed when we re-reconcile an object.
	defaultRequeueTime = syncPeriod + time.Minute*10
)

// AddWithActuator creates a new CredentialsRequest Controller and adds it to the Manager with
// default RBAC. The Manager will set fields on the Controller and Start it when
// the Manager is Started.
func AddWithActuator(mgr, adminMgr manager.Manager, actuator actuator.Actuator, platType configv1.PlatformType, mutatingClient corev1client.CoreV1Interface) error {
	if err := add(mgr, adminMgr, newReconciler(mgr, adminMgr, actuator, platType)); err != nil {
		return err
	}
	return addLabelController(mgr, mutatingClient)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr, adminMgr manager.Manager, actuator actuator.Actuator, platType configv1.PlatformType) reconcile.Reconciler {
	r := &ReconcileCredentialsRequest{
		Client:       mgr.GetClient(),
		AdminClient:  adminMgr.GetClient(),
		Actuator:     actuator,
		platformType: platType,
	}
	status.AddHandler(controllerName, r)

	return r
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr, adminMgr manager.Manager, r reconcile.Reconciler) error {
	operatorCache := mgr.GetCache()
	name := "credentialsrequest_controller"

	// Custom rateLimiter that sets minimum backoff to 2 seconds
	rateLimiter := workqueue.NewTypedMaxOfRateLimiter(
		workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.Request](2*time.Second, 1000*time.Second),
		&workqueue.TypedBucketRateLimiter[reconcile.Request]{Limiter: rate.NewLimiter(rate.Limit(10), 100)},
	)

	c, err := controller.New(name, mgr, controller.Options{
		Reconciler:  r,
		RateLimiter: rateLimiter,
	})
	if err != nil {
		return err
	}

	// Watch for changes to CredentialsRequest
	// TODO: we should limit the namespaces where we watch, we want all requests in one namespace so anyone with admin on a namespace cannot create
	// a request for any credentials they want.
	err = c.Watch(source.Kind(operatorCache, &minterv1.CredentialsRequest{}, &handler.TypedEnqueueRequestForObject[*minterv1.CredentialsRequest]{}))
	if err != nil {
		return err
	}

	// Define a mapping for secrets to the credentials requests that created them. (if applicable)
	// We use an annotation on secrets that refers back to their owning credentials request because
	// the normal owner reference is not namespaced, and we want to support credentials requests being
	// in a centralized namespace, but writing secrets into component namespaces.
	targetCredSecretMapFunc := handler.TypedEnqueueRequestsFromMapFunc(func(ctx context.Context, a *corev1.Secret) []reconcile.Request {
		namespace, name, err := cache.SplitMetaNamespaceKey(a.GetAnnotations()[minterv1.AnnotationCredentialsRequest])
		if err != nil {
			log.WithField("labels", a.GetAnnotations()).WithError(err).Error("error splitting namespace key for label")
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

	// These functions are used to determine if a event for the given Secret should trigger a sync:
	p := predicate.TypedFuncs[*corev1.Secret]{
		UpdateFunc: func(e event.TypedUpdateEvent[*corev1.Secret]) bool {

			// The object doesn't contain our label, so we have nothing to reconcile.
			if _, ok := e.ObjectOld.GetAnnotations()[minterv1.AnnotationCredentialsRequest]; !ok {
				return false
			}
			return true
		},
		CreateFunc: func(e event.TypedCreateEvent[*corev1.Secret]) bool {
			if _, ok := e.Object.GetAnnotations()[minterv1.AnnotationCredentialsRequest]; !ok {
				return false
			}
			return true
		},
		DeleteFunc: func(e event.TypedDeleteEvent[*corev1.Secret]) bool {
			if _, ok := e.Object.GetAnnotations()[minterv1.AnnotationCredentialsRequest]; !ok {
				return false
			}
			return true
		},
	}

	// Watch Secrets and reconcile if we see one with our label.
	err = c.Watch(
		source.Kind(mgr.GetCache(), &corev1.Secret{},
			targetCredSecretMapFunc,
			p))
	if err != nil {
		return err
	}

	// secretAllCredRequestsMapFn simply looks up all CredentialsRequests and requests they be reconciled.
	secretAllCredRequestsMapFn := handler.TypedEnqueueRequestsFromMapFunc(func(ctx context.Context, a *corev1.Secret) []reconcile.Request {
		log.Info("requeueing all CredentialsRequests")
		crs := &minterv1.CredentialsRequestList{}
		err := mgr.GetClient().List(ctx, crs)
		var requests []reconcile.Request
		if err != nil {
			log.WithError(err).Error("error listing all cred requests for requeue")
			return requests
		}
		for _, cr := range crs.Items {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      cr.Name,
					Namespace: cr.Namespace,
				},
			})
		}
		return requests
	})

	adminCredSecretPredicate := predicate.TypedFuncs[*corev1.Secret]{
		UpdateFunc: func(e event.TypedUpdateEvent[*corev1.Secret]) bool {
			return IsAdminCredSecret(e.ObjectNew.GetNamespace(), e.ObjectNew.GetName())
		},
		CreateFunc: func(e event.TypedCreateEvent[*corev1.Secret]) bool {
			return IsAdminCredSecret(e.Object.GetNamespace(), e.Object.GetName())
		},
		DeleteFunc: func(e event.TypedDeleteEvent[*corev1.Secret]) bool {
			return IsAdminCredSecret(e.Object.GetNamespace(), e.Object.GetName())
		},
	}
	// Watch Secrets and reconcile if we see an event for an admin credential secret in kube-system.
	err = c.Watch(
		source.Kind(adminMgr.GetCache(), &corev1.Secret{},
			secretAllCredRequestsMapFn,
			adminCredSecretPredicate))
	if err != nil {
		return err
	}

	// infraAllCredRequestsMapFn simply looks up all CredentialsRequests and requests they be reconciled.
	infraAllCredRequestsMapFn := handler.TypedEnqueueRequestsFromMapFunc(func(ctx context.Context, a *configv1.Infrastructure) []reconcile.Request {
		log.Info("requeueing all CredentialsRequests")
		crs := &minterv1.CredentialsRequestList{}
		err := mgr.GetClient().List(ctx, crs)
		var requests []reconcile.Request
		if err != nil {
			log.WithError(err).Error("error listing all cred requests for requeue")
			return requests
		}
		for _, cr := range crs.Items {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      cr.Name,
					Namespace: cr.Namespace,
				},
			})
		}
		return requests
	})

	// predicate functions to filter the events based on the AWS resourceTags presence.
	infraResourcePredicate := predicate.TypedFuncs[*configv1.Infrastructure]{
		CreateFunc: func(e event.TypedCreateEvent[*configv1.Infrastructure]) bool {
			return hasResourceTags(e.Object)
		},
		DeleteFunc: func(e event.TypedDeleteEvent[*configv1.Infrastructure]) bool {
			return false
		},
		UpdateFunc: func(e event.TypedUpdateEvent[*configv1.Infrastructure]) bool {
			return areTagsUpdated(e.ObjectOld, e.ObjectNew)
		},
	}
	// Watch for the changes happening to Infrastructure Resource
	err = c.Watch(
		source.Kind(adminMgr.GetCache(), &configv1.Infrastructure{}, infraAllCredRequestsMapFn, infraResourcePredicate))
	if err != nil {
		return err
	}

	// Monitor namespace creation, and check out list of credentials requests for any destined
	// for that new namespace. This allows us to be up and running for other components that don't
	// yet exist, but will.

	namespaceMapFn := handler.TypedEnqueueRequestsFromMapFunc(func(ctx context.Context, a *metav1.PartialObjectMetadata) []reconcile.Request {
		// Iterate all CredentailsRequests to determine if we have any that target
		// this new namespace. We are not anticipating huge numbers of CredentialsRequests,
		// nor namespace creations.
		newNamespace := a.GetName()
		log.WithField("namespace", newNamespace).Debug("checking for credentails requests targeting namespace")
		crs := &minterv1.CredentialsRequestList{}
		// Fixme: check for errors
		mgr.GetClient().List(ctx, crs)
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

	namespacePred := predicate.TypedFuncs[*metav1.PartialObjectMetadata]{
		CreateFunc: func(e event.TypedCreateEvent[*metav1.PartialObjectMetadata]) bool {
			// WARNING: on restart, the controller sees all namespaces as creates even if they
			// are pre-existing
			return true
		},
		UpdateFunc: func(e event.TypedUpdateEvent[*metav1.PartialObjectMetadata]) bool {
			return false
		},
		DeleteFunc: func(e event.TypedDeleteEvent[*metav1.PartialObjectMetadata]) bool {
			return false
		},
	}

	err = c.Watch(
		source.Kind(operatorCache, &metav1.PartialObjectMetadata{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Namespace",
				APIVersion: "v1",
			},
		},
			namespaceMapFn,
			namespacePred))
	if err != nil {
		return err
	}

	// configMapAllCredRequestsMapFn simply looks up all CredentialsRequests and requests they be reconciled.
	configMapAllCredRequestsMapFn := handler.TypedEnqueueRequestsFromMapFunc(func(ctx context.Context, a *corev1.ConfigMap) []reconcile.Request {
		log.Info("requeueing all CredentialsRequests")
		crs := &minterv1.CredentialsRequestList{}
		err := mgr.GetClient().List(ctx, crs)
		var requests []reconcile.Request
		if err != nil {
			log.WithError(err).Error("error listing all cred requests for requeue")
			return requests
		}
		for _, cr := range crs.Items {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      cr.Name,
					Namespace: cr.Namespace,
				},
			})
		}
		return requests
	})

	// Monitor the cloud-credential-operator-config configmap to check if operator is re-enabled.
	// Check if attempts were made to delete the credentials requests when the operator was disabled.
	// We have to have to reconcile all those credential requests.
	// Check if operator is re-enabled in cloud-credential-operator-config configmap
	configMapPredicate := predicate.TypedFuncs[*corev1.ConfigMap]{
		UpdateFunc: func(e event.TypedUpdateEvent[*corev1.ConfigMap]) bool {
			return isCloudCredOperatorConfigMap(e.ObjectNew)
		},
		CreateFunc: func(e event.TypedCreateEvent[*corev1.ConfigMap]) bool {
			return isCloudCredOperatorConfigMap(e.Object)
		},
		DeleteFunc: func(e event.TypedDeleteEvent[*corev1.ConfigMap]) bool {
			return isCloudCredOperatorConfigMap(e.Object)
		},
	}
	err = c.Watch(
		source.Kind(operatorCache, &corev1.ConfigMap{},
			configMapAllCredRequestsMapFn,
			configMapPredicate))
	if err != nil {
		return err
	}

	// credentialMapAllCredRequestsMapFn simply looks up all CredentialsRequests and requests they be reconciled.
	credentialMapAllCredRequestsMapFn := handler.TypedEnqueueRequestsFromMapFunc(func(ctx context.Context, a *operatorv1.CloudCredential) []reconcile.Request {
		log.Info("requeueing all CredentialsRequests")
		crs := &minterv1.CredentialsRequestList{}
		err := mgr.GetClient().List(ctx, crs)
		var requests []reconcile.Request
		if err != nil {
			log.WithError(err).Error("error listing all cred requests for requeue")
			return requests
		}
		for _, cr := range crs.Items {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      cr.Name,
					Namespace: cr.Namespace,
				},
			})
		}
		return requests
	})

	// Watch the CloudCredential config object and reconcile everything on changes.
	err = c.Watch(
		source.Kind(operatorCache, &operatorv1.CloudCredential{},
			credentialMapAllCredRequestsMapFn))
	if err != nil {
		return err
	}

	return nil
}

// hasResourceTags returns true if the AWS resourceTags are present in the Infrastructure resource
func hasResourceTags(event client.Object) bool {
	switch infra := event.(type) {
	case *configv1.Infrastructure:
		if infra != nil && infra.Status.PlatformStatus.AWS != nil && len(infra.Status.PlatformStatus.AWS.ResourceTags) != 0 {
			return true
		}
	default:
		return false
	}
	return false
}

// areTagsUpdated validates and returns a true if the resourceTags are updated in the new event
func areTagsUpdated(oldEvent, newEvent client.Object) bool {
	if !hasResourceTags(newEvent) {
		return false
	}

	if hasResourceTags(oldEvent) && hasResourceTags(newEvent) {
		return !reflect.DeepEqual(oldEvent.(*configv1.Infrastructure).Status.PlatformStatus.AWS.ResourceTags, newEvent.(*configv1.Infrastructure).Status.PlatformStatus.AWS.ResourceTags)
	}
	return true
}

// addLabelController adds a new Controller managing labels to mgr
func addLabelController(mgr manager.Manager, mutatingClient corev1client.CoreV1Interface) error {
	labelReconciler := &ReconcileSecretMissingLabel{
		cachedClient:   mgr.GetClient(),
		mutatingClient: mutatingClient,
	}
	labelController, err := controller.New(labelControllerName, mgr, controller.Options{
		Reconciler: labelReconciler,
	})
	if err != nil {
		return err
	}

	missingLabelSecretsMapFn := handler.TypedEnqueueRequestsFromMapFunc(func(_ context.Context, a *corev1.Secret) []reconcile.Request {
		return []reconcile.Request{
			{
				NamespacedName: types.NamespacedName{
					Name:      a.GetName(),
					Namespace: a.GetNamespace(),
				},
			},
		}
	})

	missingLabelCredSecretPredicate := predicate.TypedFuncs[*corev1.Secret]{
		UpdateFunc: func(e event.TypedUpdateEvent[*corev1.Secret]) bool {
			return IsMissingSecretLabel(e.ObjectNew)
		},
		CreateFunc: func(e event.TypedCreateEvent[*corev1.Secret]) bool {
			return IsMissingSecretLabel(e.Object)
		},
		DeleteFunc: func(e event.TypedDeleteEvent[*corev1.Secret]) bool {
			return IsMissingSecretLabel(e.Object)
		},
	}
	err = labelController.Watch(
		source.Kind(mgr.GetCache(), &corev1.Secret{},
			missingLabelSecretsMapFn,
			missingLabelCredSecretPredicate))
	if err != nil {
		return err
	}
	status.AddHandler(labelControllerName, labelReconciler)

	return nil
}

// IsMissingSecretLabel determines if the secret was created by the CCO but has not been labelled yet
func IsMissingSecretLabel(secret metav1.Object) bool {
	_, hasAnnotation := secret.GetAnnotations()[minterv1.AnnotationCredentialsRequest]
	value, hasLabel := secret.GetLabels()[minterv1.LabelCredentialsRequest]
	hasValue := hasLabel && value == minterv1.LabelCredentialsRequestValue

	return hasAnnotation && (!hasLabel || !hasValue)
}

type ReconcileSecretMissingLabel struct {
	cachedClient   client.Client
	mutatingClient corev1client.SecretsGetter
}

func (r *ReconcileSecretMissingLabel) GetConditions(logger log.FieldLogger) ([]configv1.ClusterOperatorStatusCondition, error) {
	var secrets corev1.SecretList
	if err := r.cachedClient.List(context.TODO(), &secrets); err != nil {
		return nil, err
	}
	var missing int
	for _, item := range secrets.Items {
		if IsMissingSecretLabel(&item) {
			missing += 1
		}
	}

	if missing > 0 {
		return []configv1.ClusterOperatorStatusCondition{{
			Type:    configv1.OperatorProgressing,
			Status:  configv1.ConditionTrue,
			Reason:  "LabelsMissing",
			Message: fmt.Sprintf("%d secrets created for CredentialsRequests have not been labelled", missing),
		}}, nil
	}
	return []configv1.ClusterOperatorStatusCondition{}, nil
}

func (r *ReconcileSecretMissingLabel) GetRelatedObjects(logger log.FieldLogger) ([]configv1.ObjectReference, error) {
	return nil, nil
}

func (r *ReconcileSecretMissingLabel) Name() string {
	return labelControllerName
}

var _ reconcile.Reconciler = (*ReconcileSecretMissingLabel)(nil)
var _ status.Handler = (*ReconcileSecretMissingLabel)(nil)

func (r *ReconcileSecretMissingLabel) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	start := time.Now()

	logger := log.WithFields(log.Fields{
		"controller": labelControllerName,
		"secret":     fmt.Sprintf("%s/%s", request.NamespacedName.Namespace, request.NamespacedName.Name),
	})

	defer func() {
		dur := time.Since(start)
		metrics.MetricControllerReconcileTime.WithLabelValues(labelControllerName).Observe(dur.Seconds())
	}()

	logger.Info("syncing secret")
	secret := &corev1.Secret{}
	err := r.cachedClient.Get(ctx, request.NamespacedName, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Debug("secret no longer exists")
			return reconcile.Result{}, nil
		}
		logger.WithError(err).Error("error getting secret, re-queuing")
		return reconcile.Result{}, err
	}

	applyConfig := corev1applyconfigurations.Secret(secret.Name, secret.Namespace)
	applyConfig.WithLabels(map[string]string{
		minterv1.LabelCredentialsRequest: minterv1.LabelCredentialsRequestValue,
	})

	if _, err := r.mutatingClient.Secrets(secret.Namespace).Apply(ctx, applyConfig, metav1.ApplyOptions{
		Force:        true, // we're the authoritative owner of this field and should not allow anyone to stomp it
		FieldManager: labelControllerName,
	}); err != nil {
		logger.WithError(err).Error("failed to update label")
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

// isCloudCredOperatorConfigMap returns true if given configmap is cloud-credential-operator-config configmap
func isCloudCredOperatorConfigMap(cm metav1.Object) bool {
	return cm.GetName() == constants.CloudCredOperatorConfigMap && cm.GetNamespace() == minterv1.CloudCredOperatorNamespace
}

func IsAdminCredSecret(namespace, secretName string) bool {
	if namespace == constants.CloudCredSecretNamespace {
		if secretName == constants.AWSCloudCredSecretName ||
			secretName == constants.AzureCloudCredSecretName ||
			secretName == constants.GCPCloudCredSecretName ||
			secretName == constants.OpenStackCloudCredsSecretName ||
			secretName == constants.OvirtCloudCredsSecretName ||
			secretName == constants.KubevirtCloudCredSecretName ||
			secretName == constants.VSphereCloudCredSecretName {
			log.WithField("secret", secretName).WithField("namespace", namespace).Info("observed admin cloud credential secret event")
			return true
		}
	}
	return false
}

var _ reconcile.Reconciler = &ReconcileCredentialsRequest{}

// ReconcileCredentialsRequest reconciles a CredentialsRequest object
type ReconcileCredentialsRequest struct {
	client.Client
	AdminClient  client.Client
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
func (r *ReconcileCredentialsRequest) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	start := time.Now()

	logger := log.WithFields(log.Fields{
		"controller": controllerName,
		"cr":         fmt.Sprintf("%s/%s", request.NamespacedName.Namespace, request.NamespacedName.Name),
	})

	defer func() {
		dur := time.Since(start)
		metrics.MetricControllerReconcileTime.WithLabelValues(controllerName).Observe(dur.Seconds())
	}()

	mode, conflict, err := utils.GetOperatorConfiguration(r.Client, logger)

	stsDetected := false
	stsDetected, _ = r.Actuator.IsTimedTokenCluster(r.Client, ctx, logger)
	if err != nil {
		logger.WithError(err).Error("error checking if operator is disabled")
		return reconcile.Result{}, err
	} else if conflict {
		logger.Error("configuration conflict between legacy configmap and operator config")
		return reconcile.Result{}, fmt.Errorf("configuration conflict")
	} else if mode == operatorv1.CloudCredentialsModeManual {
		if !stsDetected {
			logger.Infof("operator set to disabled / manual mode")
			return reconcile.Result{}, err
		} else {
			logger.Infof("operator detects timed access token enabled cluster (STS, Workload Identity, etc.)")
		}
	}

	logger.Info("syncing credentials request")
	cr := &minterv1.CredentialsRequest{}
	err = r.Get(ctx, request.NamespacedName, cr)
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

	// Ignore CR if it's for a different cloud/infra
	infraMatch, err := crInfraMatches(cr, r.platformType)
	if err != nil {
		logger.WithError(err).Error("failed to determine cloud platform type")
		return reconcile.Result{}, err
	}
	if !infraMatch {
		logger.Debug("ignoring cr as it is for a different cloud")
		setIgnoredCondition(cr, r.platformType)
		err := utils.UpdateStatus(r.Client, origCR, cr, logger)
		if err != nil {
			logger.WithError(err).Error("failed to update conditions")
		}
		return reconcile.Result{}, err
	}

	// Handle deletion and the deprovision finalizer:
	if cr.DeletionTimestamp != nil {
		if HasFinalizer(cr, minterv1.FinalizerDeprovision) {
			err = r.Actuator.Delete(ctx, cr)
			if err != nil {
				logger.WithError(err).Error("actuator error deleting credentials exist")

				setCredentialsDeprovisionFailureCondition(cr, true, err)
				if err := utils.UpdateStatus(r.Client, origCR, cr, logger); err != nil {
					logger.WithError(err).Error("failed to update condition")
					return reconcile.Result{}, err
				}
				return reconcile.Result{}, err
			} else {
				setCredentialsDeprovisionFailureCondition(cr, false, nil)
				if err := utils.UpdateStatus(r.Client, origCR, cr, logger); err != nil {
					// Just a warning, since on deprovision we're just tearing down
					// the CredentialsRequest object anyway
					logger.Warnf("unable to update condition: %v", err)
				}
			}

			// Delete the target secret if it exists:
			targetSecret := &corev1.Secret{}
			err := r.Client.Get(ctx, types.NamespacedName{Namespace: cr.Spec.SecretRef.Namespace, Name: cr.Spec.SecretRef.Name}, targetSecret)
			sLog := logger.WithFields(log.Fields{
				"targetSecret": fmt.Sprintf("%s/%s", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name),
			})
			if err != nil {
				if errors.IsNotFound(err) {
					sLog.Debug("target secret does not exist")
				} else {
					sLog.WithError(err).Error("unexpected error getting target secret to delete")
					return reconcile.Result{}, err
				}
			} else {
				err := r.Client.Delete(ctx, targetSecret)
				if err != nil {
					sLog.WithError(err).Error("error deleting target secret")
					return reconcile.Result{}, err
				} else {
					sLog.Info("target secret deleted successfully")
				}
			}

			logger.Info("actuator deletion complete, removing finalizer")
			err = r.removeDeprovisionFinalizer(ctx, cr)
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
			err = r.addDeprovisionFinalizer(ctx, cr)
			if err != nil {
				logger.WithError(err).Error("error adding finalizer")
			}
			return reconcile.Result{}, err
		}
	}

	// Ensure the target namespace exists for the secret, if not, there's no point
	// continuing:
	targetNS := &corev1.Namespace{}
	err = r.Get(ctx, types.NamespacedName{Name: cr.Spec.SecretRef.Namespace}, targetNS)
	if err != nil {
		if errors.IsNotFound(err) {
			// TODO: technically we should deprovision if a credential was in this ns, but it
			// was then deleted.
			logger.Warn("secret namespace does not yet exist")
			setMissingTargetNamespaceCondition(cr, true)
			if err := utils.UpdateStatus(r.Client, origCR, cr, logger); err != nil {
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

	// Check if the secret the credRequest wants created already exists
	var crSecretExists bool
	crSecret := &corev1.Secret{}
	secretKey := types.NamespacedName{Name: cr.Spec.SecretRef.Name, Namespace: cr.Spec.SecretRef.Namespace}
	if err := r.Get(ctx, secretKey, crSecret); err != nil {
		if errors.IsNotFound(err) {
			crSecretExists = false
		} else {
			logger.WithError(err).Error("could not query whether secret already exists")
			return reconcile.Result{}, err
		}
	} else {
		crSecretExists = true
	}
	if stsDetected {
		// create time-based tokens based on settings in CredentialsRequests
		logger.Debugf("timed token access cluster detected: %t, so not trying to provision with root secret",
			stsDetected)
		credsExists, err := r.Actuator.Exists(ctx, cr)
		if err != nil {
			logger.Errorf("error checking whether credentials already exists: %v", err)
			return reconcile.Result{}, err
		}

		var syncErr error
		syncErr = r.CreateOrUpdateOnCredsExist(ctx, credsExists, syncErr, cr)
		if syncErr != nil {
			switch t := syncErr.(type) {
			case actuator.ActuatorStatus:
				if t.Reason() == minterv1.OrphanedCloudResource {
					// not a critical error, just set the condition to communicate
					// what happened with updateActuatorConditions()
				} else {
					logger.Errorf("error syncing credentials: %v", syncErr)
				}
				// syncErr means we failed to provision, so cr.status.provisioned is set false
				updateErr := r.UpdateProvisionedStatus(cr, false)
				if updateErr != nil {
					logger.Errorf("failed to update credentialsrequest status: %v", updateErr)
				}

				logger.Errorf("errored with condition: %v", t.Reason())
				r.updateActuatorConditions(cr, t.Reason(), syncErr)
				// Update the status of the CredentialsRequest object
				err := r.Client.Status().Update(ctx, cr)
				if err != nil {
					logger.Errorf("failed to update credentialsrequest status: %v", err)
				}
			default:
				logger.Errorf("unexpected error while syncing credentialsrequest: %v", syncErr)
				return reconcile.Result{}, syncErr
			}

		} else {
			// it worked so clear any actuator conditions if they exist
			r.updateActuatorConditions(cr, "", nil)
			updateErr := r.UpdateProvisionedStatus(cr, true)
			// same as in non-STS case, sync happened so update the lastSyncGeneration
			cr.Status.LastSyncGeneration = origCR.Generation
			if updateErr != nil {
				logger.Errorf("failed to update credentialsrequest status: %v", updateErr)
			}
			err = utils.UpdateStatus(r.Client, origCR, cr, logger)
			if err != nil {
				logger.Errorf("error updating status: %v", err)
				return reconcile.Result{}, err
			}
		}
	} else {
		credentialsRootSecret, err := r.Actuator.GetCredentialsRootSecret(ctx, cr)
		if err != nil {
			log.WithError(err).Debug("error retrieving cloud credentials secret, admin can remove root credentials in mint mode")
		}
		cloudCredsSecretUpdated := credentialsRootSecret != nil && credentialsRootSecret.ResourceVersion != cr.Status.LastSyncCloudCredsSecretResourceVersion
		infra, err := utils.GetInfrastructure(r.Client)
		if err != nil {
			log.WithError(err).Debug("unable to retrieve the infrastructure resource")
		}
		isInfrastructureUpdated := infra != nil && infra.ResourceVersion != cr.Status.LastSyncInfrastructureResourceVersion

		isStale := cr.Generation != cr.Status.LastSyncGeneration
		hasRecentlySynced := cr.Status.LastSyncTimestamp != nil && cr.Status.LastSyncTimestamp.Add(syncPeriod).After(time.Now())
		hasActiveFailureConditions := checkForFailureConditions(cr)

		log.WithFields(log.Fields{
			"cloudCredsSecretUpdated":        cloudCredsSecretUpdated,
			"NOT isStale":                    isStale,
			"hasRecentlySynced":              hasRecentlySynced,
			"crSecretExists":                 crSecretExists,
			"NOT hasActiveFailureConditions": hasActiveFailureConditions,
			"cr.Status.Provisioned":          cr.Status.Provisioned,
		}).Debug("The above are ANDed together to determine: lastsyncgeneration is current and lastsynctimestamp < an hour ago")
		if !cloudCredsSecretUpdated && !isStale && !isInfrastructureUpdated && hasRecentlySynced && crSecretExists && !hasActiveFailureConditions && cr.Status.Provisioned {
			logger.Debug("lastsyncgeneration is current and lastsynctimestamp was less than an hour ago, so no need to sync")
			// Since we get no events for changes made directly to the cloud/platform, set the requeueAfter so that we at
			// least periodically check that nothing out in the cloud/platform was modified that would require us to fix up
			// users/permissions/tags/etc.
			return reconcile.Result{RequeueAfter: defaultRequeueTime}, nil
		}

		credsExists, err := r.Actuator.Exists(ctx, cr)
		if err != nil {
			logger.Errorf("error checking whether credentials already exists: %v", err)
			return reconcile.Result{}, err
		}

		var syncErr error
		syncErr = r.CreateOrUpdateOnCredsExist(ctx, credsExists, syncErr, cr)

		var provisionErr bool
		if syncErr != nil {
			switch t := syncErr.(type) {
			case actuator.ActuatorStatus:
				if t.Reason() == minterv1.OrphanedCloudResource {
					// not a critical error, just set the condition to communicate
					// what happened
					provisionErr = false
				} else {
					logger.Errorf("error syncing credentials: %v", syncErr)
					provisionErr = true
				}

				cr.Status.Provisioned = !provisionErr

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
		}

		// if provisionErr == false, it means we successfully provisioned even if there
		// were non-critical errors encountered
		if !provisionErr {
			cr.Status.LastSyncTimestamp = &metav1.Time{
				Time: time.Now(),
			}
			cr.Status.LastSyncGeneration = origCR.Generation
			if credentialsRootSecret != nil {
				cr.Status.LastSyncCloudCredsSecretResourceVersion = credentialsRootSecret.ResourceVersion
			}
		}

		// updating the LastSyncInfrastructureResourceVersion
		if infra != nil {
			cr.Status.LastSyncInfrastructureResourceVersion = infra.ResourceVersion
		}

		err = utils.UpdateStatus(r.Client, origCR, cr, logger)
		if err != nil {
			logger.Errorf("error updating status: %v", err)
			return reconcile.Result{}, err
		}

		// Since we get no events for changes made directly to the cloud/platform, set the requeueAfter so that we at
		// least periodically check that nothing out in the cloud/platform was modified that would require us to fix up
		// users/permissions/tags/etc.
		if syncErr != nil && !provisionErr {
			// We could have a non-critical error (eg OrphanedCloudResource) in the syncErr
			// but we wouldn't want to treat that as an overal controller error while
			// reconciling.
			return reconcile.Result{RequeueAfter: defaultRequeueTime}, nil
		} else {
			return reconcile.Result{RequeueAfter: defaultRequeueTime}, syncErr
		}
	}
	return reconcile.Result{RequeueAfter: defaultRequeueTime}, nil
}

func (r *ReconcileCredentialsRequest) CreateOrUpdateOnCredsExist(ctx context.Context, credsExists bool, syncErr error, cr *minterv1.CredentialsRequest) error {
	if !credsExists {
		syncErr = r.Actuator.Create(ctx, cr)
	} else {
		syncErr = r.Actuator.Update(ctx, cr)
	}
	return syncErr
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

	if reason == minterv1.OrphanedCloudResource {
		setOrphanedCloudResourceCondition(cr, true, conditionError)
	} else {
		setOrphanedCloudResourceCondition(cr, false, conditionError)
	}

	return
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

func setOrphanedCloudResourceCondition(cr *minterv1.CredentialsRequest, orphaned bool, orphanedErr error) {
	var (
		msg, reason string
		status      corev1.ConditionStatus
		updateCheck utils.UpdateConditionCheck
	)

	if orphaned {
		msg = fmt.Sprintf("unable to clean up previously created cloud resource: %s", orphanedErr.Error())
		status = corev1.ConditionTrue
		reason = cloudResourceOrphaned
		updateCheck = utils.UpdateConditionIfReasonOrMessageChange
	} else {
		msg = "cleaned up cloud resources"
		status = corev1.ConditionFalse
		reason = cloudResourceCleaned
		updateCheck = utils.UpdateConditionNever
	}
	cr.Status.Conditions = utils.SetCredentialsRequestCondition(cr.Status.Conditions, minterv1.OrphanedCloudResource,
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
		msg = fmt.Sprintf("failed to grant creds: %v", utils.ErrorScrub(err))
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
		msg = fmt.Sprintf("failed to deprovision resource: %v", utils.ErrorScrub(err))
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
	for _, cond := range minterv1.FailureConditionTypes {
		cr.Status.Conditions = utils.SetCredentialsRequestCondition(cr.Status.Conditions, cond,
			corev1.ConditionFalse, reason, msg, updateCheck)
	}
}

func (r *ReconcileCredentialsRequest) addDeprovisionFinalizer(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	AddFinalizer(cr, minterv1.FinalizerDeprovision)
	return r.Update(ctx, cr)
}

func (r *ReconcileCredentialsRequest) removeDeprovisionFinalizer(ctx context.Context, cr *minterv1.CredentialsRequest) error {
	DeleteFinalizer(cr, minterv1.FinalizerDeprovision)
	return r.Update(ctx, cr)
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
	case configv1.KubevirtPlatformType:
		return cloudType == reflect.TypeOf(minterv1.KubevirtProviderSpec{}).Name(), nil
	default:
		// Unsupported platform, not considered an error. (i.e. bare metal)
		return false, nil
	}
}

func checkForFailureConditions(cr *minterv1.CredentialsRequest) bool {
	for _, t := range minterv1.FailureConditionTypes {
		failureCond := utils.FindCredentialsRequestCondition(cr.Status.Conditions, t)
		if failureCond != nil && failureCond.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// UpdateProvisionedStatus will update the status subresource of this CredentialsRequest
func (r *ReconcileCredentialsRequest) UpdateProvisionedStatus(cr *minterv1.CredentialsRequest, provisioned bool) error {
	// Check if the status subresource is already set
	if cr.Status.LastSyncTimestamp == nil {
		// Create a new status object and set its fields
		cr.Status = minterv1.CredentialsRequestStatus{
			LastSyncTimestamp: &metav1.Time{Time: time.Now()},
			Provisioned:       provisioned,
			ProviderStatus:    &runtime.RawExtension{},
		}
	} else {
		// Update the Provisioned field with the given parameter
		cr.Status.Provisioned = provisioned

		// Update the LastSyncTimestamp to the current time
		cr.Status.LastSyncTimestamp = &metav1.Time{Time: time.Now()}
	}

	// Use retry.RetryOnConflict() to update the status subresource
	err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		return r.Client.Status().Update(context.Background(), cr)
	})
	if err != nil {
		return err
	}
	return nil
}
