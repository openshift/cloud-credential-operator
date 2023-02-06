package awspodidentity

import (
	"context"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
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
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"

	"github.com/openshift/cloud-credential-operator/pkg/assets/v410_00_assets"
	"github.com/openshift/cloud-credential-operator/pkg/operator/platform"
	"github.com/openshift/cloud-credential-operator/pkg/operator/status"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

const (
	controllerName                      = "awspodidentity"
	deploymentName                      = "cloud-credential-operator"
	operatorNamespace                   = "openshift-cloud-credential-operator"
	retryInterval                       = 10 * time.Second
	reasonStaticResourceReconcileFailed = "StaticResourceReconcileFailed"
)

var (
	defaultCodecs = serializer.NewCodecFactory(scheme.Scheme)
	defaultCodec  = defaultCodecs.UniversalDeserializer()
	staticFiles   = []string{
		"v4.1.0/aws-pod-identity-webhook/sa.yaml",
		"v4.1.0/aws-pod-identity-webhook/clusterrole.yaml",
		"v4.1.0/aws-pod-identity-webhook/role.yaml",
		"v4.1.0/aws-pod-identity-webhook/clusterrolebinding.yaml",
		"v4.1.0/aws-pod-identity-webhook/rolebinding.yaml",
		"v4.1.0/aws-pod-identity-webhook/svc.yaml",
	}
	templateFiles = []string{
		"v4.1.0/aws-pod-identity-webhook/deployment.yaml",
		"v4.1.0/aws-pod-identity-webhook/mutatingwebhook.yaml",
		"v4.1.0/aws-pod-identity-webhook/poddisruptionbudget.yaml",
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

type awsPodIdentityController struct {
	reconciler *staticResourceReconciler
	cache      cache.Cache
	logger     log.FieldLogger
}

func (c *awsPodIdentityController) Start(ctx context.Context) error {
	retryTimer := time.NewTimer(retryInterval)
	for {
		err := c.reconciler.ReconcileResources(ctx)
		if err != nil {
			retryTimer.Reset(retryInterval)
			<-retryTimer.C
		} else {
			break
		}
	}
	go c.cache.Start(ctx)

	return nil
}

func Add(mgr manager.Manager, kubeconfig string) error {
	infraStatus, err := platform.GetInfraStatusUsingKubeconfig(mgr, kubeconfig)
	if err != nil {
		return err
	}
	platformType := platform.GetType(infraStatus)
	if platformType != configv1.AWSPlatformType {
		return nil
	}

	log.Info("setting up AWS pod identity controller")

	config := mgr.GetConfig()
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	controllerRef := &corev1.ObjectReference{
		Kind:      "deployment",
		Namespace: operatorNamespace,
		Name:      deploymentName,
	}
	eventRecorder := events.NewKubeRecorder(clientset.CoreV1().Events(operatorNamespace), deploymentName, controllerRef)
	logger := log.WithFields(log.Fields{"controller": controllerName})
	imagePullSpec := os.Getenv("AWS_POD_IDENTITY_WEBHOOK_IMAGE")
	if len(imagePullSpec) == 0 {
		logger.Warn("AWS_POD_IDENTITY_WEBHOOK_IMAGE is not set, AWS pod identity webhook will not be deployed")
		return nil
	}

	r := &staticResourceReconciler{
		client:        mgr.GetClient(),
		clientset:     clientset,
		logger:        logger,
		eventRecorder: eventRecorder,
		imagePullSpec: imagePullSpec,
		conditions:    []configv1.ClusterOperatorStatusCondition{},
		cache:         resourceapply.NewResourceCache(),
	}

	c, err := controller.New(controllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	p := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			return isManaged(e.ObjectNew)
		},
		CreateFunc: func(e event.CreateEvent) bool {
			return isManaged(e.Object)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return isManaged(e.Object)
		},
	}

	// Create a namespace local cache separate from the Manager cache
	// A namespace scoped cache can still handle cluster scoped resources
	cache, err := cache.New(config, cache.Options{Namespace: operatorNamespace})
	if err != nil {
		return err
	}
	allFiles := append(staticFiles, templateFiles...)
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
		informer, err := cache.GetInformer(context.TODO(), co)
		if err != nil {
			return err
		}

		err = c.Watch(&source.Informer{Informer: informer}, &handler.EnqueueRequestForObject{}, p)
		if err != nil {
			return err
		}
	}

	status.AddHandler(controllerName, r)
	if err := mgr.Add(&awsPodIdentityController{reconciler: r, cache: cache, logger: logger}); err != nil {
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
}

var _ reconcile.Reconciler = &staticResourceReconciler{}

func (r *staticResourceReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	r.logger.Debugf("reconciling after watch event %#v", request)
	err := r.ReconcileResources(ctx)
	if err != nil {
		r.logger.Errorf("reconciliation failed, retrying in %s", retryInterval.String())
		r.conditions = []configv1.ClusterOperatorStatusCondition{
			{
				Type:    configv1.OperatorDegraded,
				Status:  configv1.ConditionTrue,
				Reason:  reasonStaticResourceReconcileFailed,
				Message: fmt.Sprintf("static resource reconciliation failed: %v", err),
			},
		}
		return reconcile.Result{RequeueAfter: retryInterval}, err
	}
	r.conditions = []configv1.ClusterOperatorStatusCondition{}
	return reconcile.Result{}, nil
}

func (r *staticResourceReconciler) ReconcileResources(ctx context.Context) error {
	topology, err := utils.LoadInfrastructureTopology(r.client, r.logger)
	if err != nil {
		return err
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
			return result.Error
		}
		if !result.Changed {
			continue
		}
		r.logger.Infof("%s reconciled successfully", result.Type)
	}

	// "v4.1.0/aws-pod-identity-webhook/deployment.yaml"
	requestedDeployment := resourceread.ReadDeploymentV1OrDie(v410_00_assets.MustAsset("v4.1.0/aws-pod-identity-webhook/deployment.yaml"))
	if topology == configv1.SingleReplicaTopologyMode {
		// Set replicas=1 for deployment on single replica topology clusters
		requestedDeployment.Spec.Replicas = pointer.Int32(1)
	}
	requestedDeployment.Spec.Template.Spec.Containers[0].Image = r.imagePullSpec
	resultDeployment, modified, err := resourceapply.ApplyDeployment(ctx, r.clientset.AppsV1(), r.eventRecorder, requestedDeployment, r.deploymentGeneration)
	if err != nil {
		r.logger.WithError(err).Error("error applying Deployment")
		return err
	}
	r.deploymentGeneration = resultDeployment.Generation
	if modified {
		r.logger.Infof("Deployment reconciled successfully")
	}

	// "v4.1.0/aws-pod-identity-webhook/mutatingwebhook.yaml"
	requestedMutatingWebhookConfiguration := resourceread.ReadMutatingWebhookConfigurationV1OrDie(v410_00_assets.MustAsset("v4.1.0/aws-pod-identity-webhook/mutatingwebhook.yaml"))
	_, modified, err = resourceapply.ApplyMutatingWebhookConfigurationImproved(context.TODO(), r.clientset.AdmissionregistrationV1(), r.eventRecorder, requestedMutatingWebhookConfiguration, r.cache)
	if err != nil {
		r.logger.WithError(err).Error("error applying MutatingWebhookConfiguration")
		return err
	}
	if modified {
		r.logger.Infof("MutatingWebhookConfiguration reconciled successfully")
	}

	if topology == configv1.SingleReplicaTopologyMode {
		// Don't deploy the PDB to single replica topology clusters
		r.logger.Debugf("not deploying PodDisruptionBudget to single replica topology")
	} else {
		// "v4.1.0/aws-pod-identity-webhook/poddisruptionbudget.yaml"
		requestedPDB := resourceread.ReadPodDisruptionBudgetV1OrDie(v410_00_assets.MustAsset("v4.1.0/aws-pod-identity-webhook/poddisruptionbudget.yaml"))
		_, modified, err = resourceapply.ApplyPodDisruptionBudget(context.TODO(), r.clientset.PolicyV1(), r.eventRecorder, requestedPDB)
		if err != nil {
			r.logger.WithError(err).Error("error applying PodDisruptionBudget")
			return err
		}
		if modified {
			r.logger.Infof("PodDisruptionBudget reconciled successfully")
		}
	}
	return nil
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
