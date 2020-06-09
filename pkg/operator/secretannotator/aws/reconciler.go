package aws

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	ccaws "github.com/openshift/cloud-credential-operator/pkg/aws"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/metrics"
	secretconstants "github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
	awsutils "github.com/openshift/cloud-credential-operator/pkg/operator/utils/aws"
)

const (
	controllerName = "secretannotator"

	AwsAccessKeyName       = "aws_access_key_id"
	AwsSecretAccessKeyName = "aws_secret_access_key"
)

func NewReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileCloudCredSecret{
		Client:           mgr.GetClient(),
		Logger:           log.WithField("controller", secretconstants.ControllerName),
		AWSClientBuilder: awsutils.ClientBuilder,
	}
}

func cloudCredSecretObjectCheck(secret metav1.Object) bool {
	return secret.GetNamespace() == secretconstants.CloudCredSecretNamespace && secret.GetName() == secretconstants.AWSCloudCredSecretName
}

func Add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New(secretconstants.ControllerName, mgr, controller.Options{Reconciler: r})
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
	Logger           log.FieldLogger
	AWSClientBuilder func(accessKeyID, secretAccessKey []byte, c client.Client) (ccaws.Client, error)
}

// Reconcile will annotate the cloud cred secret to indicate the capabilities of the cred's capabilities:
// 1) 'mint' for indicating that the creds can be used to create new sub-creds
// 2) 'passthrough' for indicating that the creds are capable enough for other components to reuse the creds as-is
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
		r.Logger.Infof("operator disabled in %s ConfigMap", constants.CloudCredOperatorConfigMap)
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
	accessKey, ok := secret.Data[AwsAccessKeyName]
	if !ok {
		r.Logger.Errorf("Couldn't fetch key containing AWS_ACCESS_KEY_ID from cloud cred secret")
		return r.updateSecretAnnotations(secret, secretconstants.InsufficientAnnotation)
	}

	secretKey, ok := secret.Data[AwsSecretAccessKeyName]
	if !ok {
		r.Logger.Errorf("Couldn't fetch key containing AWS_SECRET_ACCESS_KEY from cloud cred secret")
		return r.updateSecretAnnotations(secret, secretconstants.InsufficientAnnotation)
	}

	awsClient, err := r.AWSClientBuilder(accessKey, secretKey, r.Client)
	if err != nil {
		return fmt.Errorf("error creating aws client: %v", err)
	}

	// Can we mint new creds?
	cloudCheckResult, err := ccaws.CheckCloudCredCreation(awsClient, r.Logger)
	if err != nil {
		r.updateSecretAnnotations(secret, secretconstants.InsufficientAnnotation)
		return fmt.Errorf("failed checking create cloud creds: %v", err)
	}

	if cloudCheckResult {
		r.Logger.Info("Verified cloud creds can be used for minting new creds")
		return r.updateSecretAnnotations(secret, secretconstants.MintAnnotation)
	}

	// Else, can we just pass through the current creds?
	region, err := awsutils.LoadInfrastructureRegion(r.Client, r.Logger)
	if err != nil {
		return err
	}
	simParams := &ccaws.SimulateParams{
		Region: region,
	}
	cloudCheckResult, err = ccaws.CheckCloudCredPassthrough(awsClient, simParams, r.Logger)
	if err != nil {
		r.updateSecretAnnotations(secret, secretconstants.InsufficientAnnotation)
		return fmt.Errorf("failed checking passthrough cloud creds: %v", err)
	}

	if cloudCheckResult {
		r.Logger.Info("Verified cloud creds can be used as-is (passthrough)")
		return r.updateSecretAnnotations(secret, secretconstants.PassthroughAnnotation)
	}

	// Else, these creds aren't presently useful
	r.Logger.Warning("Cloud creds unable to be used for either minting or passthrough")
	return r.updateSecretAnnotations(secret, secretconstants.InsufficientAnnotation)
}

func (r *ReconcileCloudCredSecret) updateSecretAnnotations(secret *corev1.Secret, value string) error {
	secretAnnotations := secret.GetAnnotations()
	if secretAnnotations == nil {
		secretAnnotations = map[string]string{}
	}

	secretAnnotations[secretconstants.AnnotationKey] = value
	secret.SetAnnotations(secretAnnotations)

	return r.Update(context.Background(), secret)
}
