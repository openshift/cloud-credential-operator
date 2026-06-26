package gcp

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
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

	operatorv1 "github.com/openshift/api/operator/v1"

	ccgcp "github.com/openshift/cloud-credential-operator/pkg/gcp"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/metrics"
	"github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/status"
	secretutils "github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/utils"
	statuscontroller "github.com/openshift/cloud-credential-operator/pkg/operator/status"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
	gcputils "github.com/openshift/cloud-credential-operator/pkg/operator/utils/gcp"
)

const (
	controllerName = "secretannotator"

	// GCPAuthJSONKey is the key name in GCP credentials secrets where the json auth
	// contents will be stored.
	GCPAuthJSONKey = "service_account.json"
)

func NewReconciler(client, rootCredClient client.Client, projectName string) reconcile.Reconciler {
	r := &ReconcileCloudCredSecret{
		Client:           client,
		RootCredClient:   rootCredClient,
		Logger:           log.WithField("controller", constants.SecretAnnotatorControllerName),
		GCPClientBuilder: ccgcp.NewClientFromJSON,
		ProjectName:      projectName,
	}

	s := status.NewSecretStatusHandler(client)
	statuscontroller.AddHandler(controllerName, s)

	return r
}

func cloudCredSecretObjectCheck(secret metav1.Object) bool {
	return secret.GetNamespace() == constants.CloudCredSecretNamespace && secret.GetName() == constants.GCPCloudCredSecretName
}

func Add(mgr, rootCredMgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New(constants.SecretAnnotatorControllerName, rootCredMgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to cluster cloud secret
	p := predicate.TypedFuncs[*corev1.Secret]{
		UpdateFunc: func(e event.TypedUpdateEvent[*corev1.Secret]) bool {
			return cloudCredSecretObjectCheck(e.ObjectNew)
		},
		CreateFunc: func(e event.TypedCreateEvent[*corev1.Secret]) bool {
			return cloudCredSecretObjectCheck(e.Object)
		},
		DeleteFunc: func(e event.TypedDeleteEvent[*corev1.Secret]) bool {
			return cloudCredSecretObjectCheck(e.Object)
		},
	}
	err = c.Watch(source.Kind(rootCredMgr.GetCache(), &corev1.Secret{}, &handler.TypedEnqueueRequestForObject[*corev1.Secret]{}, p))
	if err != nil {
		return err
	}

	err = secretutils.WatchCCOConfig(mgr.GetCache(), c, types.NamespacedName{
		Namespace: constants.CloudCredSecretNamespace,
		Name:      constants.GCPCloudCredSecretName,
	}, mgr)
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileCloudCredSecret{}

type ReconcileCloudCredSecret struct {
	Client           client.Client
	RootCredClient   client.Client
	ProjectName      string
	Logger           log.FieldLogger
	GCPClientBuilder func(projectName string, authJSON []byte) (ccgcp.Client, error)
}

// Reconcile will typically annotate the cloud cred secret to indicate the capabilities of the cloud credentials:
// 1) 'mint' for indicating that the creds can be used to create new sub-creds
// 2) 'passthrough' for indicating that the creds are capable enough to potentially be used as-is
// 3) 'insufficient' for indicating that the creds are not usable for the cluster
// In the event that the operator config resource has specified a mode to operate under (mint/passthrough)
// then skip trying to determine the capabilities, and just annotate the secret.
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;update
func (r *ReconcileCloudCredSecret) Reconcile(ctx context.Context, request reconcile.Request) (returnResult reconcile.Result, returnErr error) {
	start := time.Now()

	defer func() {
		dur := time.Since(start)
		metrics.MetricControllerReconcileTime.WithLabelValues(controllerName).Observe(dur.Seconds())
	}()

	mode, conflict, err := utils.GetOperatorConfiguration(r.Client, r.Logger)
	if err != nil {
		r.Logger.WithError(err).Error("error checking operator configuration")
		return reconcile.Result{}, err
	}
	if !utils.IsValidMode(mode) {
		r.Logger.Errorf("invalid mode of %s set", mode)
		return reconcile.Result{}, fmt.Errorf("invalide mode of %s set", mode)
	}
	if conflict {
		r.Logger.Error("configuration conflict between legacy configmap and operator config")
		return reconcile.Result{}, fmt.Errorf("configuration conflict")
	}
	if mode == operatorv1.CloudCredentialsModeManual {
		r.Logger.Info("operator in disabled / manual mode")
		return reconcile.Result{}, err
	}

	secret := &corev1.Secret{}
	err = r.RootCredClient.Get(context.Background(), request.NamespacedName, secret)
	if err != nil {
		r.Logger.Debugf("secret not found: %v", err)
		return reconcile.Result{}, err
	}

	if mode != operatorv1.CloudCredentialsModeDefault {
		annotation, err := utils.ModeToAnnotation(mode)
		if err != nil {
			r.Logger.WithError(err).Errorf("failed to convert operator mode to annotation")
			return reconcile.Result{}, err
		}
		err = r.updateSecretAnnotations(secret, annotation)
		if err != nil {
			r.Logger.WithError(err).Error("errored while annotating secret")
		}
		return reconcile.Result{}, err
	}

	r.Logger.Info("validating cloud cred secret")

	err = r.validateCloudCredsSecret(secret)
	if err != nil {
		r.Logger.Errorf("error while validating cloud credentials: %v", err)
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileCloudCredSecret) validateCloudCredsSecret(secret *corev1.Secret) error {
	authJSON, ok := secret.Data[GCPAuthJSONKey]
	if !ok {
		r.Logger.Errorf("Couldn't fetch key containing authentication details from cloud cred secret")
		return r.updateSecretAnnotations(secret, constants.InsufficientAnnotation)
	}

	gcpClient, err := r.GCPClientBuilder(r.ProjectName, authJSON)
	if err != nil {
		return fmt.Errorf("error creating gcp client: %v", err)
	}

	// Can we mint new creds?
	mintResult, err := gcputils.CheckCloudCredCreation(gcpClient, r.Logger)
	if err != nil {
		r.updateSecretAnnotations(secret, constants.InsufficientAnnotation)
		return fmt.Errorf("error checking whether we can mint new creds: %v", err)
	}

	if mintResult {
		r.Logger.Info("Verified cloud creds can be used for minting new creds")
		return r.updateSecretAnnotations(secret, constants.MintAnnotation)
	}

	// Else, can we just pass through the current creds?
	passthroughResult, err := gcputils.CheckCloudCredPassthrough(gcpClient, r.Logger)
	if err != nil {
		r.updateSecretAnnotations(secret, constants.InsufficientAnnotation)
		return fmt.Errorf("error checking whether we can passthrough cloud creds: %v", err)
	}

	if passthroughResult {
		r.Logger.Info("Verified cloud creds can be used as-is (passthrough)")
		return r.updateSecretAnnotations(secret, constants.PassthroughAnnotation)
	}

	// Else, these creds aren't presently useful
	r.Logger.Warning("Cloud creds unable to be used for either minting or passthrough")
	return r.updateSecretAnnotations(secret, constants.InsufficientAnnotation)
}

func (r *ReconcileCloudCredSecret) updateSecretAnnotations(secret *corev1.Secret, value string) error {
	secretAnnotations := secret.GetAnnotations()
	if secretAnnotations == nil {
		secretAnnotations = map[string]string{}
	}

	secretAnnotations[constants.AnnotationKey] = value
	secret.SetAnnotations(secretAnnotations)

	return r.RootCredClient.Update(context.TODO(), secret)
}
