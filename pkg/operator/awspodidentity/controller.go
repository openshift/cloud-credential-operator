package awspodidentity

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	admissionregistrationclientv1 "k8s.io/client-go/kubernetes/typed/admissionregistration/v1"

	"sigs.k8s.io/controller-runtime/pkg/cache"
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
	"github.com/openshift/library-go/pkg/operator/resource/resourcehelper"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"

	"github.com/openshift/cloud-credential-operator/pkg/assets/v410_00_assets"
	"github.com/openshift/cloud-credential-operator/pkg/operator/platform"
	"github.com/openshift/cloud-credential-operator/pkg/operator/status"
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

func (c *awsPodIdentityController) Start(stopCh <-chan struct{}) error {
	retryTimer := time.NewTimer(retryInterval)
	for {
		err := c.reconciler.ReconcileResources()
		if err != nil {
			retryTimer.Reset(retryInterval)
			<-retryTimer.C
		} else {
			break
		}
	}
	go c.cache.Start(stopCh)
	<-stopCh
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
		clientset:     clientset,
		logger:        logger,
		eventRecorder: eventRecorder,
		imagePullSpec: imagePullSpec,
		conditions:    []configv1.ClusterOperatorStatusCondition{},
	}

	c, err := controller.New(controllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	p := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			return isManaged(e.MetaNew)
		},
		CreateFunc: func(e event.CreateEvent) bool {
			return isManaged(e.Meta)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return isManaged(e.Meta)
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

		informer, err := cache.GetInformer(context.TODO(), obj)
		if err != nil {
			return err
		}

		err = c.Watch(&source.Informer{Informer: informer}, &handler.EnqueueRequestForObject{}, p)
		if err != nil {
			return err
		}
	}

	status.AddHandler(controllerName, r)
	mgr.Add(&awsPodIdentityController{reconciler: r, cache: cache, logger: logger})

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
	clientset            *kubernetes.Clientset
	logger               log.FieldLogger
	eventRecorder        events.Recorder
	deploymentGeneration int64
	imagePullSpec        string
	conditions           []configv1.ClusterOperatorStatusCondition
}

var _ reconcile.Reconciler = &staticResourceReconciler{}

func (r *staticResourceReconciler) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	r.logger.Debugf("reconciling after watch event %#v", request)
	err := r.ReconcileResources()
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

func (r *staticResourceReconciler) ReconcileResources() error {
	applyResults := resourceapply.ApplyDirectly(
		(&resourceapply.ClientHolder{}).WithKubernetes(r.clientset),
		r.eventRecorder,
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
	requestedDeployment.Spec.Template.Spec.Containers[0].Image = r.imagePullSpec
	resultDeployment, modified, err := resourceapply.ApplyDeployment(r.clientset.AppsV1(), r.eventRecorder, requestedDeployment, r.deploymentGeneration)
	r.deploymentGeneration = resultDeployment.Generation
	if err != nil {
		r.logger.WithError(err).Error("error applying Deployment")
		return err
	}
	if modified {
		r.logger.Infof("Deployment reconciled successfully")
	}

	// "v4.1.0/aws-pod-identity-webhook/mutatingwebhook.yaml"
	requestedMutatingWebhookConfiguration := ReadMutatingWebhookConfigurationV1OrDie(v410_00_assets.MustAsset("v4.1.0/aws-pod-identity-webhook/mutatingwebhook.yaml"))
	_, modified, err = ApplyMutatingWebhookConfiguration(r.clientset.AdmissionregistrationV1(), r.eventRecorder, requestedMutatingWebhookConfiguration)
	if err != nil {
		r.logger.WithError(err).Error("error applying MutatingWebhookConfiguration")
		return err
	}
	if modified {
		r.logger.Infof("MutatingWebhookConfiguration reconciled successfully")
	}
	return nil
}

// TODO: add MutatingWebhookConfiguration helpers to library-go/operator/resource

func ReadMutatingWebhookConfigurationV1OrDie(objBytes []byte) *admissionregistrationv1.MutatingWebhookConfiguration {
	requiredObj, err := runtime.Decode(defaultCodecs.UniversalDecoder(admissionregistrationv1.SchemeGroupVersion), objBytes)
	if err != nil {
		panic(err)
	}
	return requiredObj.(*admissionregistrationv1.MutatingWebhookConfiguration)
}

// ApplyMutatingWebhookConfiguration merges objectmeta, does not worry about anything else
func ApplyMutatingWebhookConfiguration(client admissionregistrationclientv1.MutatingWebhookConfigurationsGetter, recorder events.Recorder, required *admissionregistrationv1.MutatingWebhookConfiguration) (*admissionregistrationv1.MutatingWebhookConfiguration, bool, error) {
	existing, err := client.MutatingWebhookConfigurations().Get(context.TODO(), required.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		actual, err := client.MutatingWebhookConfigurations().Create(context.TODO(), required, metav1.CreateOptions{})
		reportCreateEvent(recorder, required, err)
		return actual, true, err
	}
	if err != nil {
		return nil, false, err
	}

	modified := resourcemerge.BoolPtr(false)
	existingCopy := existing.DeepCopy()

	resourcemerge.EnsureObjectMeta(modified, &existingCopy.ObjectMeta, required.ObjectMeta)

	// TODO: add deeper inspection of the existing resource to make sure it is what we require

	if !*modified {
		return existingCopy, false, nil
	}

	actual, err := client.MutatingWebhookConfigurations().Update(context.TODO(), existingCopy, metav1.UpdateOptions{})
	reportUpdateEvent(recorder, required, err)
	return actual, true, err
}

func reportCreateEvent(recorder events.Recorder, obj runtime.Object, originalErr error) {
	gvk := resourcehelper.GuessObjectGroupVersionKind(obj)
	if originalErr == nil {
		recorder.Eventf(fmt.Sprintf("%sCreated", gvk.Kind), "Created %s because it was missing", resourcehelper.FormatResourceForCLI(obj))
		return
	}
	recorder.Warningf(fmt.Sprintf("%sCreateFailed", gvk.Kind), "Failed to create %s: %v", resourcehelper.FormatResourceForCLI(obj), originalErr)
}

func reportUpdateEvent(recorder events.Recorder, obj runtime.Object, originalErr error, details ...string) {
	gvk := resourcehelper.GuessObjectGroupVersionKind(obj)
	switch {
	case originalErr != nil:
		recorder.Warningf(fmt.Sprintf("%sUpdateFailed", gvk.Kind), "Failed to update %s: %v", resourcehelper.FormatResourceForCLI(obj), originalErr)
	case len(details) == 0:
		recorder.Eventf(fmt.Sprintf("%sUpdated", gvk.Kind), "Updated %s because it changed", resourcehelper.FormatResourceForCLI(obj))
	default:
		recorder.Eventf(fmt.Sprintf("%sUpdated", gvk.Kind), "Updated %s:\n%s", resourcehelper.FormatResourceForCLI(obj), strings.Join(details, "\n"))
	}
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
