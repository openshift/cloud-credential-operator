package podidentity

import (
	"context"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/clock"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	configv1 "github.com/openshift/api/config/v1"
	utiltls "github.com/openshift/controller-runtime-common/pkg/tls"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"

	"github.com/openshift/cloud-credential-operator/pkg/assets/v410_00_assets"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/platform"
	"github.com/openshift/cloud-credential-operator/pkg/operator/status"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

const (
	controllerName                      = "pod-identity"
	deploymentName                      = "cloud-credential-operator"
	operatorNamespace                   = "openshift-cloud-credential-operator"
	retryInterval                       = 10 * time.Second
	reasonStaticResourceReconcileFailed = "StaticResourceReconcileFailed"

	// degradedGracePeriod is the minimum duration reconciliation must fail
	// before reporting Degraded. Per the spec, Degraded represents a persistent
	// condition — transient errors should not immediately surface.
	degradedGracePeriod = 5 * time.Minute
	pdb                 = "v4.1.0/common/poddisruptionbudget.yaml"
)

var (
	defaultCodecs = serializer.NewCodecFactory(scheme.Scheme)
	defaultCodec  = defaultCodecs.UniversalDeserializer()
	staticFiles   = []string{
		"v4.1.0/common/sa.yaml",
		"v4.1.0/common/clusterrole.yaml",
		"v4.1.0/common/role.yaml",
		"v4.1.0/common/clusterrolebinding.yaml",
		"v4.1.0/common/rolebinding.yaml",
		"v4.1.0/common/svc.yaml",
	}
	relatedObjects = []configv1.ObjectReference{
		{
			Resource:  "serviceaccounts",
			Namespace: operatorNamespace,
			Name:      "pod-identity-webhook",
		},
		{
			Group:    "rbac.authorization.k8s.io",
			Resource: "clusterroles",
			Name:     "pod-identity-webhook",
		},
		{
			Group:    "rbac.authorization.k8s.io",
			Resource: "clusterrolebindings",
			Name:     "pod-identity-webhook",
		},
		{
			Group:     "rbac.authorization.k8s.io",
			Resource:  "roles",
			Namespace: operatorNamespace,
			Name:      "pod-identity-webhook",
		},
		{
			Group:     "rbac.authorization.k8s.io",
			Resource:  "rolebindings",
			Namespace: operatorNamespace,
			Name:      "pod-identity-webhook",
		},
		{
			Resource:  "services",
			Namespace: operatorNamespace,
			Name:      "pod-identity-webhook",
		},
		{
			Group:     "apps",
			Resource:  "deployments",
			Namespace: operatorNamespace,
			Name:      "pod-identity-webhook",
		},
		{
			Group:    "admissionregistration.k8s.io",
			Resource: "mutatingwebhookconfigurations",
			Name:     "pod-identity-webhook",
		},
	}
)

type PodIdentityManifestSource interface {
	ApplyDeploymentSubstitutionsInPlace(deployment *appsv1.Deployment, client client.Client, logger log.FieldLogger, tlsProfileSpec configv1.TLSProfileSpec) error
	Deployment() string
	GetImagePullSpec() string
	Webhook() string
	ShouldBeDeployed(ctx context.Context, clientSet kubernetes.Interface, namespace string) (bool, error)
	Name() string
}

type podIdentityController struct {
	reconciler *staticResourceReconciler
	cache      cache.Cache
	logger     log.FieldLogger
}

func (c *podIdentityController) Start(ctx context.Context) error {
	retryTimer := time.NewTimer(retryInterval)
	defer retryTimer.Stop()
	for {
		err := c.reconciler.reconcileAndUpdateConditions(ctx)
		if err != nil {
			retryTimer.Reset(retryInterval)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-retryTimer.C:
			}
		} else {
			break
		}
	}
	go c.cache.Start(ctx)

	return nil
}

func Add(mgr, _ manager.Manager, kubeconfig string) error {
	infraStatus, err := platform.GetInfraStatusUsingKubeconfig(kubeconfig)
	if err != nil {
		return err
	}
	// Do not add controller when ControlPlaneTopology is External
	if infraStatus.ControlPlaneTopology == configv1.ExternalTopologyMode {
		return nil
	}

	var podIdentityType PodIdentityManifestSource
	platformType := platform.GetType(infraStatus)
	switch platformType {
	case configv1.AWSPlatformType:
		podIdentityType = AwsPodIdentity{}
	case configv1.AzurePlatformType:
		podIdentityType = AzurePodIdentity{}
	case configv1.GCPPlatformType:
		podIdentityType = GcpPodIdentity{}
	default:
		log.WithField("controller", controllerName).Warn("Failed to get platform type")
		return nil
	}
	ctx := context.TODO()
	logger := log.WithFields(log.Fields{"platform": platformType, "controller": controllerName})

	config := mgr.GetConfig()
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	shouldBeDeployed, err := podIdentityType.ShouldBeDeployed(ctx, clientset, operatorNamespace)
	if err != nil {
		return err
	}
	if !shouldBeDeployed {
		logger.Info("pod identity was not enabled, nothing to deploy")
		return nil
	}

	logger.Info("setting up pod identity controller")

	controllerRef := &corev1.ObjectReference{
		Kind:      "deployment",
		Namespace: operatorNamespace,
		Name:      deploymentName,
	}

	eventRecorder := events.NewKubeRecorder(clientset.CoreV1().Events(operatorNamespace), deploymentName, controllerRef, clock.RealClock{})

	imagePullSpec := podIdentityType.GetImagePullSpec()
	if len(imagePullSpec) == 0 {
		logger.Warnf("%s_POD_IDENTITY_WEBHOOK_IMAGE is not set, pod identity webhook will not be deployed",
			strings.ToUpper(string(platformType)))
		return nil
	}

	r := &staticResourceReconciler{
		client:          mgr.GetClient(),
		clientset:       clientset,
		logger:          logger,
		eventRecorder:   eventRecorder,
		imagePullSpec:   imagePullSpec,
		conditions:      []configv1.ClusterOperatorStatusCondition{},
		cache:           resourceapply.NewResourceCache(),
		podIdentityType: podIdentityType,
		tlsProfileSpec:  configv1.TLSProfileSpec{},
	}

	k8sClient, err := client.New(config, client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		return err
	}

	tlsAdherence, err := utiltls.FetchAPIServerTLSAdherencePolicy(ctx, k8sClient)
	if err != nil {
		return err
	}

	initialTLSProfile, err := utiltls.FetchAPIServerTLSProfile(ctx, k8sClient)
	if err != nil {
		return err
	}

	if libgocrypto.ShouldHonorClusterTLSProfile(tlsAdherence) {
		r.tlsProfileSpec = initialTLSProfile
	}

	c, err := controller.New(controllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	p := []predicate.Predicate{
		predicate.Funcs{
			UpdateFunc: func(e event.UpdateEvent) bool {
				return isManaged(e.ObjectNew)
			},
			CreateFunc: func(e event.CreateEvent) bool {
				return isManaged(e.Object)
			},
			DeleteFunc: func(e event.DeleteEvent) bool {
				return isManaged(e.Object)
			},
		},
	}
	var namespaces = make(map[string]cache.Config)
	namespaces[operatorNamespace] = cache.Config{}

	// Create a namespace local cache separate from the Manager cache
	// A namespace scoped cache can still handle cluster scoped resources
	controllerCache, err := cache.New(config, cache.Options{DefaultNamespaces: namespaces})
	if err != nil {
		return err
	}

	allFiles := append(staticFiles, []string{podIdentityType.Webhook(), podIdentityType.Deployment(), pdb}...)
	for _, file := range allFiles {
		objBytes := v410_00_assets.MustAsset(file)
		obj, _, err := defaultCodec.Decode(objBytes, nil, nil)
		if err != nil {
			return err
		}

		co, ok := obj.(client.Object)
		if !ok {
			return fmt.Errorf("failed to convert runtime.Object to client.Object")
		}
		informer, err := controllerCache.GetInformer(ctx, co)
		if err != nil {
			return err
		}

		err = c.Watch(&source.Informer{
			Informer:   informer,
			Handler:    &handler.EnqueueRequestForObject{},
			Predicates: p,
		},
		)
		if err != nil {
			return err
		}
	}

	status.AddHandler(controllerName, r)
	if err := mgr.Add(&podIdentityController{reconciler: r, cache: controllerCache, logger: logger}); err != nil {
		return err
	}

	return nil
}

func isManaged(meta metav1.Object) bool {
	// all managed resources are named pod-identity-webhook
	if meta.GetName() == "pod-identity-webhook" {
		return true
	}
	return false
}

type staticResourceReconciler struct {
	client               client.Client
	clientset            kubernetes.Interface
	logger               log.FieldLogger
	eventRecorder        events.Recorder
	deploymentGeneration int64
	imagePullSpec        string
	conditions           []configv1.ClusterOperatorStatusCondition
	cache                resourceapply.ResourceCache
	podIdentityType      PodIdentityManifestSource
	tlsProfileSpec       configv1.TLSProfileSpec
	// degradedSince tracks when reconciliation errors started. On pod restart
	// this resets to zero; seedDegradedSince recovers it from the published
	// ClusterOperator Degraded condition so the grace period is not re-granted.
	degradedSince time.Time
}

var _ reconcile.Reconciler = &staticResourceReconciler{}

const podIdentityWebhookDeploymentName = "pod-identity-webhook"

func (r *staticResourceReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	r.logger.Debugf("reconciling after watch event %#v", request)

	err := r.reconcileAndUpdateConditions(ctx)
	if err != nil {
		r.logger.WithError(err).Errorf("reconciliation error, requeueing in %s", retryInterval)
		// Return nil so controller-runtime honors RequeueAfter instead of
		// applying exponential backoff. The error is already logged above and
		// recorded via condition updates in reconcileAndUpdateConditions.
		return reconcile.Result{RequeueAfter: retryInterval}, nil
	}
	return reconcile.Result{}, nil
}

// reconcileAndUpdateConditions performs resource reconciliation and updates
// r.conditions with deployment-derived state (Progressing, Available) and
// any error-derived Degraded condition. Used by both Reconcile() and Start()
// so that bootstrap retries also publish accurate conditions.
func (r *staticResourceReconciler) reconcileAndUpdateConditions(ctx context.Context) error {
	// Fetch the current deployment state from the API. This is the source of
	// truth for condition synthesis (Progressing, Available).
	var deployment *appsv1.Deployment
	currentDeployment, err := r.clientset.AppsV1().Deployments(operatorNamespace).Get(ctx, podIdentityWebhookDeploymentName, metav1.GetOptions{})
	if err == nil {
		deployment = currentDeployment
	} else if !apierrors.IsNotFound(err) {
		// Non-NotFound errors (network, RBAC, etc.) should be propagated so we
		// don't silently lose rollout state by treating the deployment as absent.
		return fmt.Errorf("failed to get deployment %s: %w", podIdentityWebhookDeploymentName, err)
	}
	// If NotFound, deployment stays nil and deploymentConditions will return
	// an empty slice.

	d, err := r.ReconcileResources(ctx)
	if d != nil {
		deployment = d
	}

	// Build deployment-derived conditions first (Progressing, Available) so they
	// are always reported regardless of whether ReconcileResources succeeded.
	// Without this, a transient error would drop Progressing=True during rollout
	// or flip Available=False back to the default True.
	r.conditions = deploymentConditions(deployment)

	if err != nil {
		r.logger.Errorf("reconciliation failed, retrying in %s", retryInterval.String())
		// Spec: Degraded means the component does not match its desired state
		// "over a period of time." Only report Degraded after the grace period
		// to avoid surfacing transient errors.
		// Suppression during cluster upgrades is handled centrally in syncStatus.
		if r.degradedSince.IsZero() {
			r.degradedSince = r.seedDegradedSince(ctx)
		}
		if time.Since(r.degradedSince) > degradedGracePeriod {
			r.conditions = append(r.conditions, configv1.ClusterOperatorStatusCondition{
				Type:    configv1.OperatorDegraded,
				Status:  configv1.ConditionTrue,
				Reason:  reasonStaticResourceReconcileFailed,
				Message: fmt.Sprintf("static resource reconciliation failed: %v", err),
			})
		}
		return err
	}

	r.degradedSince = time.Time{}
	return nil
}

// seedDegradedSince recovers the degraded start time after a pod restart.
// If the ClusterOperator already has Degraded=True published, the failure was
// ongoing before the restart — use the condition's LastTransitionTime so the
// grace period is not re-granted. Falls back to time.Now() on any error or
// if no prior Degraded=True is found.
func (r *staticResourceReconciler) seedDegradedSince(ctx context.Context) time.Time {
	co := &configv1.ClusterOperator{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: constants.CloudCredClusterOperatorName}, co); err != nil {
		r.logger.WithError(err).Debug("unable to read ClusterOperator for degraded seeding, starting fresh")
		return time.Now()
	}
	for _, cond := range co.Status.Conditions {
		if cond.Type == configv1.OperatorDegraded {
			if cond.Status == configv1.ConditionTrue {
				r.logger.WithField("lastTransitionTime", cond.LastTransitionTime.Time).
					Info("seeded degradedSince from published ClusterOperator Degraded condition")
				return cond.LastTransitionTime.Time
			}
			// If Degraded was suppressed during an upgrade, the failure was ongoing
			// before the restart. Don't re-grant the grace period.
			if cond.Reason == "UpgradeInProgress" {
				r.logger.Info("seeded degradedSince from suppressed Degraded condition, skipping grace period")
				return time.Now().Add(-degradedGracePeriod)
			}
		}
	}
	return time.Now()
}

// deploymentConditions returns Progressing/Available conditions derived from the
// current deployment state. Called in both success and error paths so that
// deployment-derived conditions are never dropped by a transient reconcile error.
func deploymentConditions(deployment *appsv1.Deployment) []configv1.ClusterOperatorStatusCondition {
	var conditions []configv1.ClusterOperatorStatusCondition
	if deployment == nil {
		// Deployment does not exist — the webhook is non-functional.
		conditions = append(conditions, configv1.ClusterOperatorStatusCondition{
			Type:    configv1.OperatorAvailable,
			Status:  configv1.ConditionFalse,
			Reason:  "DeploymentNotFound",
			Message: "pod-identity-webhook deployment does not exist",
		})
		return conditions
	}
	progressing, msg := isDeploymentProgressing(deployment)
	if progressing {
		// Spec: report Progressing=True when actively rolling out new code.
		conditions = append(conditions, configv1.ClusterOperatorStatusCondition{
			Type:    configv1.OperatorProgressing,
			Status:  configv1.ConditionTrue,
			Reason:  "Deploying",
			Message: strings.Replace(msg, "Deployment", "pod-identity-webhook deployment", 1),
		})
	}
	if deployment.Status.AvailableReplicas == 0 {
		// Available and Progressing are independent conditions. If there are
		// no available replicas, the component is non-functional regardless of
		// whether a rollout is in progress. Multi-replica deployments spread
		// across nodes handle upgrade availability naturally.
		conditions = append(conditions, configv1.ClusterOperatorStatusCondition{
			Type:    configv1.OperatorAvailable,
			Status:  configv1.ConditionFalse,
			Reason:  "DeploymentUnavailable",
			Message: "pod-identity-webhook deployment has no available pods",
		})
	}
	return conditions
}

func (r *staticResourceReconciler) ReconcileResources(ctx context.Context) (*appsv1.Deployment, error) {
	topology, err := utils.LoadInfrastructureTopology(r.client, r.logger)
	if err != nil {
		return nil, err
	}

	applyResults := resourceapply.ApplyDirectly(
		ctx,
		(&resourceapply.ClientHolder{}).WithKubernetes(r.clientset),
		r.eventRecorder,
		r.cache,
		v410_00_assets.Asset,
		staticFiles...,
	)
	for _, result := range applyResults {
		if result.Error != nil {
			r.logger.WithError(result.Error).Errorf("error reconciling %s", result.Type)
			return nil, result.Error
		}
		if !result.Changed {
			continue
		}
		r.logger.Infof("%s reconciled successfully", result.Type)
	}

	requestedDeployment := resourceread.ReadDeploymentV1OrDie(v410_00_assets.MustAsset(r.podIdentityType.Deployment()))
	if topology == configv1.SingleReplicaTopologyMode {
		// Set replicas=1 for deployment on single replica topology clusters
		requestedDeployment.Spec.Replicas = pointer.Int32(1)
	}

	requestedDeployment.Spec.Template.Spec.Containers[0].Image = r.imagePullSpec

	err = r.podIdentityType.ApplyDeploymentSubstitutionsInPlace(requestedDeployment, r.client, r.logger, r.tlsProfileSpec)
	if err != nil {
		r.logger.WithError(err).Error("error substituting Deployment")
		return nil, err
	}

	resultDeployment, modified, err := resourceapply.ApplyDeployment(ctx, r.clientset.AppsV1(), r.eventRecorder, requestedDeployment, r.deploymentGeneration)
	if err != nil {
		r.logger.WithError(err).Error("error applying Deployment")
		return nil, err
	}
	r.deploymentGeneration = resultDeployment.Generation
	if modified {
		r.logger.Infof("Deployment reconciled successfully")
	}

	requestedMutatingWebhookConfiguration := resourceread.ReadMutatingWebhookConfigurationV1OrDie(v410_00_assets.MustAsset(r.podIdentityType.Webhook()))
	_, modified, err = resourceapply.ApplyMutatingWebhookConfigurationImproved(ctx, r.clientset.AdmissionregistrationV1(), r.eventRecorder, requestedMutatingWebhookConfiguration, r.cache)
	if err != nil {
		r.logger.WithError(err).Error("error applying MutatingWebhookConfiguration")
		return resultDeployment, err
	}
	if modified {
		r.logger.Infof("MutatingWebhookConfiguration reconciled successfully")
	}

	if topology == configv1.SingleReplicaTopologyMode {
		// Don't deploy the PDB to single replica topology clusters
		r.logger.Debugf("not deploying PodDisruptionBudget to single replica topology")
	} else {
		requestedPDB := resourceread.ReadPodDisruptionBudgetV1OrDie(v410_00_assets.MustAsset(pdb))
		_, modified, err = resourceapply.ApplyPodDisruptionBudget(ctx, r.clientset.PolicyV1(), r.eventRecorder, requestedPDB)
		if err != nil {
			r.logger.WithError(err).Error("error applying PodDisruptionBudget")
			return resultDeployment, err
		}
		if modified {
			r.logger.Infof("PodDisruptionBudget reconciled successfully")
		}
	}
	return resultDeployment, nil
}

// isDeploymentProgressing checks whether the deployment is actively rolling out.
// Copied from github.com/openshift/library-go/pkg/operator/deploymentcontroller/deployment_controller.go
func isDeploymentProgressing(deployment *appsv1.Deployment) (bool, string) {
	var deploymentExpectedReplicas int32
	if deployment.Spec.Replicas != nil {
		deploymentExpectedReplicas = *deployment.Spec.Replicas
	}

	switch {
	case deployment.Generation != deployment.Status.ObservedGeneration:
		return true, "Waiting for Deployment to act on changes"
	case hasDeploymentFinishedProgressing(deployment):
		return false, ""
	case deployment.Status.UnavailableReplicas > 0:
		return true, "Waiting for Deployment to deploy pods"
	case deployment.Status.UpdatedReplicas < deploymentExpectedReplicas:
		return true, "Waiting for Deployment to update pods"
	case deployment.Status.AvailableReplicas < deploymentExpectedReplicas:
		return true, "Waiting for Deployment to deploy pods"
	}
	return false, ""
}

// hasDeploymentFinishedProgressing checks whether the deployment rollout is complete.
// Copied from github.com/openshift/library-go/pkg/operator/deploymentcontroller/deployment_controller.go
func hasDeploymentFinishedProgressing(deployment *appsv1.Deployment) bool {
	// Deployment whose rollout is complete gets Progressing condition with Reason NewReplicaSetAvailable condition.
	// https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#complete-deployment
	// Any subsequent missing replicas (e.g. caused by a node reboot) must not change the Progressing condition.
	for _, cond := range deployment.Status.Conditions {
		if cond.Type == appsv1.DeploymentProgressing {
			return cond.Status == corev1.ConditionTrue && cond.Reason == "NewReplicaSetAvailable"
		}
	}
	return false
}

var _ status.Handler = &staticResourceReconciler{}

func (r *staticResourceReconciler) GetConditions(logger log.FieldLogger) ([]configv1.ClusterOperatorStatusCondition, error) {
	return r.conditions, nil
}

func (r *staticResourceReconciler) GetRelatedObjects(logger log.FieldLogger) ([]configv1.ObjectReference, error) {
	return relatedObjects, nil
}

func (r *staticResourceReconciler) Name() string {
	return controllerName
}
