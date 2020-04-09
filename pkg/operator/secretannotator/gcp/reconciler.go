package gcp

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	ccgcp "github.com/openshift/cloud-credential-operator/pkg/gcp"
	"github.com/openshift/cloud-credential-operator/pkg/operator/metrics"
	"github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
	gcputils "github.com/openshift/cloud-credential-operator/pkg/operator/utils/gcp"
)

const (
	controllerName = "secretannotator"

	// GCPCloudCredSecretName is the name of the secret created by installer containing cloud creds.
	GCPCloudCredSecretName = "gcp-credentials"

	// GCPAuthJSONKey is the key name in GCP credentials secrets where the json auth
	// contents will be stored.
	GCPAuthJSONKey = "service_account.json"
)

func NewReconciler(mgr manager.Manager, projectName string) reconcile.Reconciler {
	return &ReconcileCloudCredSecret{
		Client:           mgr.GetClient(),
		Logger:           log.WithField("controller", constants.ControllerName),
		GCPClientBuilder: ccgcp.NewClient,
		ProjectName:      projectName,
	}
}

func cloudCredSecretObjectCheck(secret metav1.Object) bool {
	return secret.GetNamespace() == constants.CloudCredSecretNamespace && secret.GetName() == GCPCloudCredSecretName
}

func Add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New(constants.ControllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to cluster cloud secret
	p := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			return cloudCredSecretObjectCheck(e.MetaNew)
		},
		CreateFunc: func(e event.CreateEvent) bool {
			return cloudCredSecretObjectCheck(e.Meta)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return cloudCredSecretObjectCheck(e.Meta)
		},
	}
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForObject{}, p)
	if err != nil {
		return err
	}
	return nil
}

var _ reconcile.Reconciler = &ReconcileCloudCredSecret{}

type ReconcileCloudCredSecret struct {
	client.Client
	ProjectName      string
	Logger           log.FieldLogger
	GCPClientBuilder func(projectName string, authJSON []byte) (ccgcp.Client, error)
}

// Reconcile will annotate the cloud cred secret to indicate the capabilities of the cloud credentials:
// 1) 'mint' for indicating that the creds can be used to create new sub-creds
// 2) 'passthrough' for indicating that the creds are capable enough to potentially be used as-is
// 3) 'insufficient' for indicating that the creds are not usable for the cluster
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;update
func (r *ReconcileCloudCredSecret) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	start := time.Now()

	r.Logger.Info("validating cloud cred secret")

	operatorIsDisabled, err := utils.IsOperatorDisabled(r.Client, r.Logger)
	if err != nil {
		r.Logger.WithError(err).Error("error checking if operator is disabled")
		return reconcile.Result{}, err
	} else if operatorIsDisabled {
		r.Logger.Infof("operator disabled in %s ConfigMap", minterv1.CloudCredOperatorConfigMap)
		return reconcile.Result{}, err
	}

	defer func() {
		dur := time.Since(start)
		metrics.MetricControllerReconcileTime.WithLabelValues(controllerName).Observe(dur.Seconds())
	}()

	secret := &corev1.Secret{}
	err = r.Get(context.Background(), request.NamespacedName, secret)
	if err != nil {
		r.Logger.Debugf("secret not found: %v", err)
		return reconcile.Result{}, err
	}

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

	return r.Update(context.TODO(), secret)
}
