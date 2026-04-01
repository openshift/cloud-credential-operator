package status

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"sort"
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

	reasonVersionChanged = "VersionChanged"
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

func alwaysReconcileCCOConfigObject[T any](ctx context.Context, object T) []reconcile.Request {
	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Name: constants.CloudCredOperatorConfig,
			},
		},
	}
}

// Add creates a new Status Controller and adds it to the Manager.
func Add(mgr, rootCredentialManager manager.Manager, kubeConfig string) error {

	infraStatus, err := platform.GetInfraStatusUsingKubeconfig(kubeConfig)
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
	operatorCache := mgr.GetCache()

	if err := c.Watch(source.Kind(operatorCache, &operatorv1.CloudCredential{}, &handler.TypedEnqueueRequestForObject[*operatorv1.CloudCredential]{})); err != nil {
		return err
	}

	// Watch ClusterVersion so we can detect cluster-wide upgrades and suppress Degraded accordingly.
	if err := c.Watch(source.Kind(operatorCache, &configv1.ClusterVersion{}, handler.TypedEnqueueRequestsFromMapFunc[*configv1.ClusterVersion](alwaysReconcileCCOConfigObject))); err != nil {
		return err
	}

	// always reconcile status when the clusteroperator/cloud-credential changes.
	if err := c.Watch(source.Kind(operatorCache, &configv1.ClusterOperator{}, handler.TypedEnqueueRequestsFromMapFunc[*configv1.ClusterOperator](alwaysReconcileCCOConfigObject), predicate.TypedFuncs[*configv1.ClusterOperator]{
		CreateFunc: func(e event.TypedCreateEvent[*configv1.ClusterOperator]) bool {
			return e.Object != nil && e.Object.GetName() == constants.CloudCredClusterOperatorName
		},
		UpdateFunc: func(e event.TypedUpdateEvent[*configv1.ClusterOperator]) bool {
			return e.ObjectNew != nil && e.ObjectNew.GetName() == constants.CloudCredClusterOperatorName
		},
		DeleteFunc: func(e event.TypedDeleteEvent[*configv1.ClusterOperator]) bool {
			return e.Object != nil && e.Object.GetName() == constants.CloudCredClusterOperatorName
		},
	})); err != nil {
		return err
	}

	// Whenever a CredentialsRequest is modified, recalculate status
	err = c.Watch(source.Kind(operatorCache, &credreqv1.CredentialsRequest{}, handler.TypedEnqueueRequestsFromMapFunc[*credreqv1.CredentialsRequest](alwaysReconcileCCOConfigObject)))
	if err != nil {
		return err
	}

	// These functions are used to determine if an event for the given Secret should trigger a sync
	// We are watching for:
	// 	Future known secrets to set appropriate Upgradeable conditions.
	//	Secrets with the CCO annotation on them (secrets created by CCO).
	//	The root cloud cred secret in the kube-system namespace.
	p := predicate.TypedFuncs[*corev1.Secret]{
		UpdateFunc: func(e event.TypedUpdateEvent[*corev1.Secret]) bool {
			return isWatchedSecret(platformType, e.ObjectNew.GetNamespace(), e.ObjectNew.GetName(), e.ObjectNew.GetAnnotations())
		},
		CreateFunc: func(e event.TypedCreateEvent[*corev1.Secret]) bool {
			return isWatchedSecret(platformType, e.Object.GetNamespace(), e.Object.GetName(), e.Object.GetAnnotations())
		},
		DeleteFunc: func(e event.TypedDeleteEvent[*corev1.Secret]) bool {
			return isWatchedSecret(platformType, e.Object.GetNamespace(), e.Object.GetName(), e.Object.GetAnnotations())
		},
	}

	// Whenever one of our watched Secrets is updated, recalculate status
	err = c.Watch(source.Kind(operatorCache, &corev1.Secret{},
		handler.TypedEnqueueRequestsFromMapFunc[*corev1.Secret](alwaysReconcileCCOConfigObject),
		p,
	))
	if err != nil {
		return err
	}

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
func (r *ReconcileStatus) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
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
	handlerNames := make([]string, 0, len(statusHandlers))
	for name := range statusHandlers {
		handlerNames = append(handlerNames, name)
	}
	sort.Strings(handlerNames)
	for _, handlerName := range handlerNames {
		handler := statusHandlers[handlerName]
		handlerConditions, err := handler.GetConditions(logger)
		logger.WithFields(log.Fields{
			"handlerconditions": handlerConditions,
			"statushandler":     handlerName,
		}).Debug("received conditions from handler")
		if err != nil {
			// Do not continue — a handler failure would leave its condition
			// types unset, causing defaultUnsetConditions to mark them
			// "AsExpected" and masking real problems. Abort the reconcile
			// so the last published status is preserved.
			logger.WithError(err).WithField("statushandler", handlerName).Errorf("failed to get conditions from status handler")
			return fmt.Errorf("status handler %s failed: %w", handlerName, err)
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

	// Spec: report Progressing=True when actively rolling out a version change.
	// On the reconcile where the version changes, set Progressing=True. On
	// subsequent reconciles, handlers dictate the Progressing state — if no
	// handler reports Progressing=True, we are done progressing.
	progressing, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorProgressing)
	if !reflect.DeepEqual(oldVersions, co.Status.Versions) {
		// Version just changed — set Progressing=True with VersionChanged reason.
		logger.WithFields(log.Fields{
			"old": oldVersions,
			"new": co.Status.Versions,
		}).Info("version has changed, setting Progressing=True")
		if progressing != nil {
			oldProgressing, _ := findClusterOperatorCondition(oldConditions, configv1.OperatorProgressing)
			if oldProgressing == nil || oldProgressing.Status != configv1.ConditionTrue {
				progressing.LastTransitionTime = metav1.Now()
			} else {
				progressing.LastTransitionTime = oldProgressing.LastTransitionTime
			}
			progressing.Status = configv1.ConditionTrue
			progressing.Reason = reasonVersionChanged
			progressing.Message = "Operator version is updating"
		}
	}

	// Spec: "A component must not report Degraded during the course of a normal upgrade."
	// Suppression is scoped to when this operator is actively progressing as part
	// of the upgrade. Once CCO finishes its upgrade work (Progressing=False), Degraded
	// is no longer suppressed — even if the cluster-wide upgrade is still running —
	// because any failure at that point is a real problem, not an upgrade artifact.
	// Available is NOT suppressed during upgrades — multi-replica deployments spread
	// across nodes handle upgrade availability naturally.
	operatorIsProgressing := progressing != nil && progressing.Status == configv1.ConditionTrue
	clusterUpgrading, upgradeErr := isClusterUpgrading(kubeClient, logger)
	if upgradeErr != nil {
		// Cannot determine cluster upgrade state — default to not suppressing
		// Degraded so the rest of the status sync can proceed. This avoids
		// leaving stale conditions when the ClusterVersion is temporarily
		// unreadable (e.g., during API server restarts).
		logger.WithError(upgradeErr).Warn("unable to determine cluster upgrade state, defaulting to not suppressing Degraded")
		clusterUpgrading = false
	}
	if clusterUpgrading && operatorIsProgressing {
		degraded, _ := findClusterOperatorCondition(co.Status.Conditions, configv1.OperatorDegraded)
		if degraded != nil && degraded.Status == configv1.ConditionTrue {
			logger.Info("suppressing Degraded condition during cluster upgrade")
			originalMessage := fmt.Sprintf("Degraded=True suppressed during cluster upgrade (reason: %s, message: %s)",
				degraded.Reason, degraded.Message)
			degraded.Status = configv1.ConditionFalse
			degraded.Reason = "UpgradeInProgress"
			degraded.Message = originalMessage
			// Preserve transition time: if the old condition was already False
			// (suppressed on a previous reconcile), carry its transition time forward
			// rather than using the one setLastTransitionTime computed from the
			// intermediate True state.
			oldDegraded, _ := findClusterOperatorCondition(oldConditions, configv1.OperatorDegraded)
			if oldDegraded != nil && oldDegraded.Status == configv1.ConditionFalse {
				degraded.LastTransitionTime = oldDegraded.LastTransitionTime
			} else {
				degraded.LastTransitionTime = metav1.Now()
			}
		}
	}

	// ClusterOperator should already exist (from the manifest payload), but recreate it if needed
	if isNotFound {
		co.Name = constants.CloudCredClusterOperatorName
		if err := kubeClient.Create(context.TODO(), co); err != nil {
			return errors.Wrap(err, "failed to create clusteroperator")
		}
		logger.Info("created clusteroperator")
		if err := kubeClient.Status().Update(context.TODO(), co); err != nil {
			return errors.Wrap(err, "failed to update clusteroperator status after creation")
		}
		logger.Info("updated clusteroperator status after creation")
		return nil
	}

	// Sort arrays for predictable output and deep equal checks
	sortStatusArrays(&co.Status)

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
// When multiple handlers set the same condition type, the "worst" status wins:
// for Degraded/Progressing True is worse; for Available/Upgradeable False is worse.
// When both are equally bad, messages are concatenated so no information is lost.
func mergeConditions(existing, new []configv1.ClusterOperatorStatusCondition, handlerName string, logger log.FieldLogger) []configv1.ClusterOperatorStatusCondition {
	for _, newCondition := range new {
		existingCondition, index := findClusterOperatorCondition(existing, newCondition.Type)
		if existingCondition == nil {
			existing = append(existing, newCondition)
		} else {
			logger.WithField("statushandler", handlerName).Infof("condition already set for type %s by a previous handler, merging with worst-wins", newCondition.Type)
			existing[index] = worstCondition(*existingCondition, newCondition)
		}
	}
	return existing
}

// isWorse returns true if candidate is a worse status than current for the
// given condition type. For Degraded/Progressing, True is worse. For
// Available/Upgradeable, False is worse.
func isWorse(conditionType configv1.ClusterStatusConditionType, candidate, current configv1.ConditionStatus) bool {
	if candidate == current {
		return false
	}
	switch conditionType {
	case configv1.OperatorAvailable, configv1.OperatorUpgradeable:
		return candidate == configv1.ConditionFalse
	default: // Degraded, Progressing
		return candidate == configv1.ConditionTrue
	}
}

// worstCondition returns the condition with the worse status, preserving the
// winner's reason. When both have equally bad status, messages are concatenated.
func worstCondition(a, b configv1.ClusterOperatorStatusCondition) configv1.ClusterOperatorStatusCondition {
	if isWorse(a.Type, b.Status, a.Status) {
		// b is worse — take b but append a's message for context
		b.Message = b.Message + "; " + a.Message
		return b
	}
	if isWorse(a.Type, a.Status, b.Status) {
		// a is already worse — keep a but append b's message
		a.Message = a.Message + "; " + b.Message
		return a
	}
	// Same status — keep a's reason, concatenate messages
	a.Message = a.Message + "; " + b.Message
	return a
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
			// No handler set this condition type, set to defaults.
			// Spec: Available defaults to True (component is functional),
			// Degraded defaults to False (no persistent issues),
			// Progressing defaults to False (no active rollout),
			// Upgradeable defaults to True (safe to upgrade).
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
			defaultCondition.Reason = "AsExpected"
			defaultCondition.Message = "All is well"
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
		if oldCondition == nil || oldCondition.Status != newCondition.Status {
			newCondition.LastTransitionTime = metav1.Now()
		} else {
			newCondition.LastTransitionTime = oldCondition.LastTransitionTime
		}
	}
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
	case configv1.AzurePlatformType:
		rootSecret.Name = constants.AzureCloudCredSecretName
	case configv1.GCPPlatformType:
		rootSecret.Name = constants.GCPCloudCredSecretName
	case configv1.OpenStackPlatformType:
		rootSecret.Name = constants.OpenStackCloudCredsSecretName
	case configv1.OvirtPlatformType:
		rootSecret.Name = constants.OvirtCloudCredsSecretName
	case configv1.VSpherePlatformType:
		rootSecret.Name = constants.VSphereCloudCredSecretName
	default:
		return []types.NamespacedName{}
	}

	secrets = append(secrets, rootSecret)
	return secrets
}

// isClusterUpgrading checks whether the cluster is currently performing an upgrade
// by reading the ClusterVersion object's Progressing condition. Returns an error
// if the ClusterVersion cannot be read, so callers can treat upgrade state as
// unknown rather than assuming "not upgrading" on transient failures.
func isClusterUpgrading(kubeClient client.Client, logger log.FieldLogger) (bool, error) {
	cv := &configv1.ClusterVersion{}
	if err := kubeClient.Get(context.TODO(), types.NamespacedName{Name: "version"}, cv); err != nil {
		return false, errors.Wrap(err, "unable to get ClusterVersion")
	}
	for _, cond := range cv.Status.Conditions {
		if cond.Type == configv1.OperatorProgressing {
			return cond.Status == configv1.ConditionTrue, nil
		}
	}
	return false, nil
}

func sortStatusArrays(status *configv1.ClusterOperatorStatus) {
	sort.SliceStable(status.Conditions, func(i, j int) bool {
		return string(status.Conditions[i].Type) < string(status.Conditions[j].Type)
	})

	sort.SliceStable(status.RelatedObjects, func(i, j int) bool {
		return string(status.RelatedObjects[i].Name) < string(status.RelatedObjects[j].Name)
	})
}
