package status

import (
	"context"
	"os"
	"reflect"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

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

	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/metrics"
	"github.com/openshift/cloud-credential-operator/pkg/operator/platform"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

const (
	controllerName         = "status"
	msgOperatorDisabled    = "Credential minting is disabled by cluster admin"
	reasonOperatorDisabled = "OperatorDisabledByAdmin"
	defaultRequeuePeriod   = time.Minute * 5
)

// Handler produces conditions and related objects to be reflected
// in the cloud-credential-operator ClusterOperatorStatus
type Handler interface {
	GetConditions(logger log.FieldLogger) ([]configv1.ClusterOperatorStatusCondition, error)
	GetRelatedObjects(logger log.FieldLogger) ([]configv1.ObjectReference, error)
	Name() string
}

var (
	statusHandlers = map[string]Handler{}
)

// AddHandler registers a Handler that will be called whenever
// an update to the ClusterOperator status is needed.
// Each controller providing their own status calculations should
// use their unique controller name to register themselves.
func AddHandler(name string, handler Handler) {
	statusHandlers[name] = handler
}

// clearHandlers allows clearing the registered handlers for test cases
func clearHandlers() {
	statusHandlers = map[string]Handler{}
}

func newReconciler(mgr manager.Manager, platformType configv1.PlatformType) reconcile.Reconciler {
	c := mgr.GetClient()
	r := &ReconcileStatus{
		Client:   c,
		Logger:   log.WithField("controller", controllerName),
		platform: platformType,
	}

	return r
}

func alwaysReconcileCCOConfigObject(handler.MapObject) []reconcile.Request {
	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Name: constants.CloudCredOperatorConfig,
			},
		},
	}
}

// Add creates a new Status Controller and adds it to the Manager.
func Add(mgr manager.Manager, kubeConfig string) error {

	infraStatus, err := platform.GetInfraStatusUsingKubeconfig(mgr, kubeConfig)
	if err != nil {
		log.Fatal(err)
	}
	platformType := platform.GetType(infraStatus)

	r := newReconciler(mgr, platformType)

	// Create a new controller
	c, err := controller.New(controllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	if err := c.Watch(&source.Kind{Type: &operatorv1.CloudCredential{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return err
	}

	// Whenever a CredentialsRequest is modified, recalculate status
	err = c.Watch(&source.Kind{Type: &credreqv1.CredentialsRequest{}}, &handler.EnqueueRequestsFromMapFunc{
		ToRequests: handler.ToRequestsFunc(alwaysReconcileCCOConfigObject),
	})
	if err != nil {
		return err
	}

	// These functions are used to determine if an event for the given Secret should trigger a sync
	// We are watching for:
	// 	Future known secrets to set appropriate Upgradeable conditions.
	//	Secrets with the CCO annotation on them (secrets created by CCO).
	//	The root cloud cred secret in the kube-system namespace.
	p := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			return isWatchedSecret(platformType, e.MetaNew.GetNamespace(), e.MetaNew.GetName(), e.MetaNew.GetAnnotations())
		},
		CreateFunc: func(e event.CreateEvent) bool {
			return isWatchedSecret(platformType, e.Meta.GetNamespace(), e.Meta.GetName(), e.Meta.GetAnnotations())
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return isWatchedSecret(platformType, e.Meta.GetNamespace(), e.Meta.GetName(), e.Meta.GetAnnotations())
		},
	}

	// Whenever one of our watched Secrets is updated, recalculate status
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}},
		&handler.EnqueueRequestsFromMapFunc{
			ToRequests: handler.ToRequestsFunc(alwaysReconcileCCOConfigObject),
		},
		p,
	)

	return nil
}

var _ reconcile.Reconciler = &ReconcileStatus{}

// ReconcileStatus reconciles the entire status for this operator.
type ReconcileStatus struct {
	client.Client
	Logger   log.FieldLogger
	platform configv1.PlatformType
}

// Reconcile will ensure the ClusterOperator status conditions are updating by calling to each
// registered domain-specific status handler. This function will ensure default conditions are set
// if none of the handlers set a condition.
func (r *ReconcileStatus) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	start := time.Now()

	defer func() {
		dur := time.Since(start)
		metrics.MetricControllerReconcileTime.WithLabelValues(controllerName).Observe(dur.Seconds())
	}()

	err := syncStatus(r.Client, r.Logger)
	return reconcile.Result{
		RequeueAfter: defaultRequeuePeriod,
	}, err
}

// syncStatus is written in a way so that if we expose this function it would allow
// external controllers to trigger a static sync. But for now we will make this an internal
// function until the need arises to expose it.
func syncStatus(kubeClient client.Client, logger log.FieldLogger) error {
	log.Info("reconciling clusteroperator status")

	co := &configv1.ClusterOperator{}
	err := kubeClient.Get(context.TODO(), types.NamespacedName{Name: constants.CloudCredClusterOperatorName}, co)
	isNotFound := k8errors.IsNotFound(err)
	if err != nil && !isNotFound {
		logger.WithError(err).WithField("clusterOperator", constants.CloudCredClusterOperatorName).Error("failed to retrive ClusterOperator")
		return err
	}

	oldConditions := co.Status.Conditions
	oldVersions := co.Status.Versions
	oldRelatedObjects := co.Status.RelatedObjects

	// We rebuild the conditions from scratch each time.
	// Handlers return abnormal (non-default) conditions they wish to set.
	// If the controller is functioning normally, it should return an empty slice of conditions.
	conditions := []configv1.ClusterOperatorStatusCondition{}
	relatedObjects := []configv1.ObjectReference{}
	for handlerName, handler := range statusHandlers {
		handlerConditions, err := handler.GetConditions(logger)
		logger.WithFields(log.Fields{
			"handlerconditions": handlerConditions,
			"statushandler":     handlerName,
		}).Debug("received conditions from handler")
		if err != nil {
			logger.WithError(err).WithField("statushandler", handlerName).Errorf("failed to get conditions from status handler")
			continue
		}
		conditions = mergeConditions(conditions, handlerConditions, handlerName, logger)
		handlerRelatedObjects, err := handler.GetRelatedObjects(logger)
		if err != nil {
			logger.WithField("statushandler", handlerName).Errorf("failed to get related objects from status handler")
			continue
		}
		relatedObjects = append(relatedObjects, handlerRelatedObjects...)
	}

	// sets defaults for condition not set by any handler
	conditions = defaultUnsetConditions(conditions)

	// at this point we know all condition types exist in conditions

	co.Status.Conditions = conditions
	co.Status.RelatedObjects = relatedObjects
	co.Status.Versions = computeClusterOperatorVersions()

	// check if the operator is disabled and reflect that in the Available condition
	mode, _, err := utils.GetOperatorConfiguration(kubeClient, logger)
	if err != nil {
		return errors.Wrap(err, "failed to check if operator is disabled")
	}
	if mode == operatorv1.CloudCredentialsModeManual {
		available, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorAvailable)
		if available.Status == configv1.ConditionTrue {
			available.Reason = reasonOperatorDisabled
			available.Message = msgOperatorDisabled
		}
	}

	// Update transition time for any condition that has changed
	setLastTransitionTime(oldConditions, co.Status.Conditions)

	// Check if version changed, if so force a progressing last transition update:
	if !reflect.DeepEqual(oldVersions, co.Status.Versions) {
		logger.WithFields(log.Fields{
			"old": oldVersions,
			"new": co.Status.Versions,
		}).Info("version has changed, updating progressing condition lastTransitionTime")
		progressing, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
		// We know this should be there.
		progressing.LastTransitionTime = metav1.Now()
	}

	// ClusterOperator should already exist (from the manifest payload), but recreate it if needed
	if isNotFound {
		if err := kubeClient.Create(context.TODO(), co); err != nil {
			return errors.Wrap(err, "failed to create clusteroperator")
		}
		logger.Info("created clusteroperator")
		// return error so we can immediately recalculate status???
		return nil
	}

	// Update status fields if needed
	if !reflect.DeepEqual(oldConditions, co.Status.Conditions) ||
		!reflect.DeepEqual(oldVersions, co.Status.Versions) ||
		!reflect.DeepEqual(oldRelatedObjects, co.Status.RelatedObjects) {

		if err := kubeClient.Status().Update(context.TODO(), co); err != nil {
			return errors.Wrap(err, "failed to update clusteroperator status")
		}
		logger.Info("clusteroperator status updated")
	}

	return nil
}

// mergeConditions will take the existing list of conditions and merge in the list of new conditions.
// Any pre-existing condition will be overwritten with the values found in the new list (and logged).
func mergeConditions(existing, new []configv1.ClusterOperatorStatusCondition, handlerName string, logger log.FieldLogger) []configv1.ClusterOperatorStatusCondition {
	for _, newCondition := range new {
		existingCondition, index := findClusterOperatorCondition(existing, newCondition.Type)
		if existingCondition == nil {
			existing = append(existing, newCondition)
		} else {
			logger.WithField("statushandler", handlerName).Warningf("condition already set for type %s by a previous handler, the new condition from the current handler will be accepted: %v", newCondition.Type, newCondition)
			existing[index] = newCondition
		}
	}
	return existing
}

// findClusterOperatorCondition iterates all conditions on a ClusterOperator looking for the
// specified condition type. If none exists nil will be returned.
func findClusterOperatorCondition(conditions []configv1.ClusterOperatorStatusCondition, conditionType configv1.ClusterStatusConditionType) (*configv1.ClusterOperatorStatusCondition, int) {
	for i, condition := range conditions {
		if condition.Type == conditionType {
			return &conditions[i], i
		}
	}
	return nil, 0
}

func defaultUnsetConditions(existing []configv1.ClusterOperatorStatusCondition) []configv1.ClusterOperatorStatusCondition {
	var conditions []configv1.ClusterOperatorStatusCondition
	for _, conditionType := range []configv1.ClusterStatusConditionType{
		configv1.OperatorAvailable,
		configv1.OperatorDegraded,
		configv1.OperatorProgressing,
		configv1.OperatorUpgradeable,
	} {
		existingCondition, _ := findClusterOperatorCondition(existing, conditionType)
		if existingCondition != nil {
			conditions = append(conditions, *existingCondition)
		} else {
			// No handler set this condition type, set to defaults
			defaultCondition := configv1.ClusterOperatorStatusCondition{
				Type: conditionType,
			}
			switch conditionType {
			case configv1.OperatorAvailable:
				defaultCondition.Status = configv1.ConditionTrue
			case configv1.OperatorDegraded:
				defaultCondition.Status = configv1.ConditionFalse
			case configv1.OperatorProgressing:
				defaultCondition.Status = configv1.ConditionFalse
			case configv1.OperatorUpgradeable:
				defaultCondition.Status = configv1.ConditionTrue
			}
			conditions = append(conditions, defaultCondition)
		}
	}
	return conditions
}

func computeClusterOperatorVersions() []configv1.OperandVersion {
	currentVersion := os.Getenv("RELEASE_VERSION")
	version := []configv1.OperandVersion{
		{
			Name:    "operator",
			Version: currentVersion,
		},
	}
	return version
}

func setLastTransitionTime(oldConditions []configv1.ClusterOperatorStatusCondition, newConditions []configv1.ClusterOperatorStatusCondition) {
	for i := range newConditions {
		newCondition := &newConditions[i]
		oldCondition, _ := findClusterOperatorCondition(oldConditions, newCondition.Type)
		if oldCondition == nil || !ConditionEqual(*oldCondition, *newCondition) {
			newCondition.LastTransitionTime = metav1.Now()
		} else {
			newCondition.LastTransitionTime = oldCondition.LastTransitionTime
		}
	}
}

// ConditionEqual compares every field except LastTransitionTime.
func ConditionEqual(a, b configv1.ClusterOperatorStatusCondition) bool {
	if a.Type == b.Type &&
		a.Status == b.Status &&
		a.Reason == b.Reason &&
		a.Message == b.Message {
		return true
	}
	return false
}

// isWatchedSecret is used to identify if a given secret namespace + name is one we're expecting in the future
// or the root credential for the cluster, or a CCO-managed secret.
func isWatchedSecret(platformType configv1.PlatformType, namespace, name string, annotations map[string]string) bool {
	for _, nsn := range getWatchedSecrets(platformType) {
		if nsn.Namespace == namespace && nsn.Name == name {
			return true
		}
	}

	if _, ok := annotations[credreqv1.AnnotationCredentialsRequest]; ok {
		return true
	}

	return false
}

func getWatchedSecrets(platformType configv1.PlatformType) []types.NamespacedName {
	secrets := []types.NamespacedName{}

	rootSecret := types.NamespacedName{
		Namespace: constants.CloudCredSecretNamespace,
		// Fill in platform-specific name below
	}

	switch platformType {
	case configv1.AWSPlatformType:
		rootSecret.Name = constants.AWSCloudCredSecretName
		secrets = append(secrets, constants.AWSUpcomingSecrets...)
	case configv1.AzurePlatformType:
		rootSecret.Name = constants.AzureCloudCredSecretName
		secrets = append(secrets, constants.AzureUpcomingSecrets...)
	case configv1.GCPPlatformType:
		rootSecret.Name = constants.GCPCloudCredSecretName
		secrets = append(secrets, constants.GCPUpcomingSecrets...)
	case configv1.OpenStackPlatformType:
		rootSecret.Name = constants.OpenStackCloudCredsSecretName
		secrets = append(secrets, constants.OpenStackUpcomingSecrets...)
	case configv1.OvirtPlatformType:
		rootSecret.Name = constants.OvirtCloudCredsSecretName
		secrets = append(secrets, constants.OvirtUpcomingSecrets...)
	case configv1.VSpherePlatformType:
		rootSecret.Name = constants.VSphereCloudCredSecretName
		secrets = append(secrets, constants.VsphereUpcomingSecrets...)
	default:
		log.Infof("unable to provide upcoming secrets for unknown platform: %v", platformType)
		return []types.NamespacedName{}
	}

	secrets = append(secrets, rootSecret)
	return secrets
}
