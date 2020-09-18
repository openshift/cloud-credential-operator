package aws

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	operatorv1 "github.com/openshift/api/operator/v1"

	ccaws "github.com/openshift/cloud-credential-operator/pkg/aws"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/metrics"
	"github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/status"
	secretutils "github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/utils"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
	awsutils "github.com/openshift/cloud-credential-operator/pkg/operator/utils/aws"
	"github.com/openshift/cloud-credential-operator/pkg/util/clusteroperator"
)

const (
	AwsAccessKeyName       = "aws_access_key_id"
	AwsSecretAccessKeyName = "aws_secret_access_key"
)

func NewReconciler(mgr manager.Manager) reconcile.Reconciler {
	c := mgr.GetClient()
	r := &ReconcileCloudCredSecret{
		Client:           c,
		Logger:           log.WithField("controller", constants.SecretAnnotatorControllerName),
		AWSClientBuilder: awsutils.ClientBuilder,
	}

	s := status.NewSecretStatusHandler(c)
	clusteroperator.AddStatusHandler(s)

	return r
}

func cloudCredSecretObjectCheck(secret metav1.Object) bool {
	return secret.GetNamespace() == constants.CloudCredSecretNamespace && secret.GetName() == constants.AWSCloudCredSecretName
}

func Add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New(constants.SecretAnnotatorControllerName, mgr, controller.Options{Reconciler: r})
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

	err = secretutils.WatchCCOConfig(c, types.NamespacedName{
		Namespace: constants.CloudCredSecretNamespace,
		Name:      constants.AWSCloudCredSecretName,
	})
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

// Reconcile will typically annotate the cloud cred secret to indicate the capabilities of the cred's capabilities:
// 1) 'mint' for indicating that the creds can be used to create new sub-creds
// 2) 'passthrough' for indicating that the creds are capable enough for other components to reuse the creds as-is
// 3) 'insufficient' for indicating that the creds are not usable for the cluster
// In the event that the operator config resource has specified a mode to operate under (mint/passthrough)
// then skip trying to determine the capabilities, and just annotate the secret.
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;update
func (r *ReconcileCloudCredSecret) Reconcile(request reconcile.Request) (returnResult reconcile.Result, returnErr error) {
	start := time.Now()

	defer func() {
		dur := time.Since(start)
		metrics.MetricControllerReconcileTime.WithLabelValues(constants.SecretAnnotatorControllerName).Observe(dur.Seconds())
	}()

	defer func() {
		if err := status.SyncOperatorStatus(r.Client); err != nil {
			r.Logger.WithError(err).Errorf("failed to sync operator status")
			if returnErr == nil {
				returnErr = err
			}
		}
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
	err = r.Get(context.Background(), request.NamespacedName, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			r.Logger.Info("parent credential secret does not exist")
			return reconcile.Result{}, nil
		}
		r.Logger.WithError(err).Error("failed to fetch secret")
		return reconcile.Result{}, err
	}

	// In the event that the CCO config indicates what mode CCO should be running with,
	// just force annotate the secret and bypass all the permissions checking.
	if mode != operatorv1.CloudCredentialsModeDefault {
		annotation, err := utils.ModeToAnnotation(mode)
		if err != nil {
			r.Logger.WithError(err).Error("failed to convert operator mode to annotation")
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
	accessKey, ok := secret.Data[AwsAccessKeyName]
	if !ok {
		r.Logger.Errorf("Couldn't fetch key containing AWS_ACCESS_KEY_ID from cloud cred secret")
		return r.updateSecretAnnotations(secret, constants.InsufficientAnnotation)
	}

	secretKey, ok := secret.Data[AwsSecretAccessKeyName]
	if !ok {
		r.Logger.Errorf("Couldn't fetch key containing AWS_SECRET_ACCESS_KEY from cloud cred secret")
		return r.updateSecretAnnotations(secret, constants.InsufficientAnnotation)
	}

	awsClient, err := r.AWSClientBuilder(accessKey, secretKey, r.Client)
	if err != nil {
		return fmt.Errorf("error creating aws client: %v", err)
	}

	// Can we mint new creds?
	cloudCheckResult, err := ccaws.CheckCloudCredCreation(awsClient, r.Logger)
	if err != nil {
		r.updateSecretAnnotations(secret, constants.InsufficientAnnotation)
		return fmt.Errorf("failed checking create cloud creds: %v", err)
	}

	if cloudCheckResult {
		r.Logger.Info("Verified cloud creds can be used for minting new creds")
		return r.updateSecretAnnotations(secret, constants.MintAnnotation)
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
		r.updateSecretAnnotations(secret, constants.InsufficientAnnotation)
		return fmt.Errorf("failed checking passthrough cloud creds: %v", err)
	}

	if cloudCheckResult {
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

	return r.Update(context.Background(), secret)
}
