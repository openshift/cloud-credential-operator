package metrics

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	configv1 "github.com/openshift/api/config/v1"

	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/credentialsrequest/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/platform"
	secretconstants "github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

const (
	controllerName = "metrics"
)

var (
	metricCredentialsRequestTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cco_credentials_requests",
		Help: "Total number of credentials requests.",
	}, []string{"cloud_type"})

	// Capture the various conditions set on the CredentialsRequests
	metricCredentialsRequestConditions = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cco_credentials_requests_conditions",
		Help: "Credentials requests with asserted conditions.",
	}, []string{"condition"})

	// Report on the mode CCO is operating under
	metricCredentialsMode = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cco_credentials_mode",
		Help: "Track current mode the cloud-credentials-operator is functioning under.",
	}, []string{"mode"})

	// MetricControllerReconcileTime tracks the length of time our reconcile loops take. controller-runtime
	// technically tracks this for us, but due to bugs currently also includes time in the queue, which leads to
	// extremely strange results. For now, track our own metric.
	MetricControllerReconcileTime = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cco_controller_reconcile_seconds",
			Help:    "Distribution of the length of time each controllers reconcile loop takes.",
			Buckets: []float64{0.001, 0.01, 0.1, 1, 10, 30, 60, 120},
		},
		[]string{"controller"},
	)
)

func init() {
	metrics.Registry.MustRegister(metricCredentialsRequestTotal)
	metrics.Registry.MustRegister(metricCredentialsRequestConditions)
	metrics.Registry.MustRegister(metricCredentialsMode)

	metrics.Registry.MustRegister(MetricControllerReconcileTime)
}

// Add creates a new metrics Calculator and adds it to the Manager.
func Add(mgr manager.Manager, kubeConfig string) error {
	logger := log.WithField("controller", controllerName)

	mc := &Calculator{
		Client:   mgr.GetClient(),
		Interval: 2 * time.Minute,
		log:      logger,
	}
	err := mgr.Add(mc)
	if err != nil {
		return err
	}
	return nil
}

// Calculator runs in a goroutine and periodically calculates and publishes
// Prometheus metrics which will be exposed at our /metrics endpoint. Note that this is not
// a standard controller watching Kube resources, it runs periodically and then goes to sleep.
//
// This should be used for metrics which do not fit well into controller reconcile loops,
// things that are calculated globally rather than metrics releated to specific reconciliations.
type Calculator struct {
	Client client.Client

	// Interval is the length of time we sleep between metrics calculations.
	Interval time.Duration

	log log.FieldLogger
}

// Start begins the metrics calculation loop.
func (mc *Calculator) Start(stopCh <-chan struct{}) error {
	mc.log.Info("started metrics calculator goroutine")

	// Run forever, sleep at the end:
	wait.Until(mc.metricsLoop, mc.Interval, stopCh)

	return nil
}

func (mc *Calculator) metricsLoop() {
	start := time.Now()
	defer func() {
		dur := time.Since(start)
		MetricControllerReconcileTime.WithLabelValues(controllerName).Observe(dur.Seconds())
		mc.log.WithField("elapsed", dur).Info("reconcile complete")
	}()

	mc.log.Info("calculating metrics for all CredentialsRequests")

	ccoDisabled, err := utils.IsOperatorDisabled(mc.Client, mc.log)
	if err != nil {
		mc.log.WithError(err).Error("failed to determine whether CCO is disabled")
		return
	}

	credRequests := &credreqv1.CredentialsRequestList{}
	if err := mc.Client.List(context.TODO(), credRequests); err != nil {
		mc.log.WithError(err).Error("error listing CredentialsRequests")
		return
	}

	accumulator := newAccumulator(mc.log)
	for _, cr := range credRequests.Items {
		accumulator.processCR(&cr, ccoDisabled)
	}

	cloudSecret, err := mc.getCloudSecret()
	if err != nil && !errors.IsNotFound(err) {
		mc.log.WithError(err).Error("failed to fetch cloud secret")
		return
	}
	accumulator.setCredentialsMode(ccoDisabled, cloudSecret, errors.IsNotFound(err))

	accumulator.setMetrics()
}

func (mc *Calculator) getCloudSecret() (*corev1.Secret, error) {
	infraStatus, err := platform.GetInfraStatus(mc.Client)
	if err != nil {
		mc.log.WithError(err).Error("failed to get Infrastructure.Status")
		return nil, err
	}
	platformType := platform.GetType(infraStatus)

	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{Namespace: secretconstants.CloudCredSecretNamespace}
	switch platformType {
	case configv1.AWSPlatformType:
		secretKey.Name = secretconstants.AWSCloudCredSecretName
	case configv1.AzurePlatformType:
		secretKey.Name = secretconstants.AzureCloudCredSecretName
	case configv1.GCPPlatformType:
		secretKey.Name = secretconstants.GCPCloudCredSecretName
	case configv1.OpenStackPlatformType:
		secretKey.Name = secretconstants.OpenStackCloudCredsSecretName
	case configv1.OvirtPlatformType:
		secretKey.Name = secretconstants.OvirtCloudCredsSecretName
	case configv1.VSpherePlatformType:
		secretKey.Name = secretconstants.VSphereCloudCredSecretName
	default:
		mc.log.WithField("cloud", platformType).Info("unsupported cloud for determing CCO mode")
		return nil, nil
	}
	err = mc.Client.Get(context.TODO(), secretKey, secret)
	return secret, err
}

func cloudProviderSpecToMetricsKey(cloud string) string {
	switch cloud {
	case "AWSProviderSpec":
		return "aws"
	case "AzureProviderSpec":
		return "azure"
	case "GCPProviderSpec":
		return "gcp"
	case "OpenStackProviderSpec":
		return "openstack"
	case "OvirtProviderSpec":
		return "ovirt"
	case "VsphereProviderSpec":
		return "vsphere"
	default:
		return "unknown"
	}
}

type credRequestAccumulator struct {
	logger log.FieldLogger

	crTotals     map[string]int
	crConditions map[credreqv1.CredentialsRequestConditionType]int
	crMode       map[constants.CredentialsMode]int
}

func newAccumulator(logger log.FieldLogger) *credRequestAccumulator {
	acc := &credRequestAccumulator{
		logger:       logger,
		crTotals:     map[string]int{},
		crConditions: map[credreqv1.CredentialsRequestConditionType]int{},
		crMode:       map[constants.CredentialsMode]int{},
	}

	// make entries with '0' so we make sure to send updated metrics for any
	// condititons that may have cleared
	for _, c := range constants.FailureConditionTypes {
		acc.crConditions[c] = 0
	}

	// First set all possibilities to zero (in case we have switched modes since last time)
	for _, mode := range constants.CredentialsModeList {
		acc.crMode[mode] = 0
	}

	return acc
}

func (a *credRequestAccumulator) processCR(cr *credreqv1.CredentialsRequest, ccoDisabled bool) {
	cloudType, err := utils.GetCredentialsRequestCloudType(cr.Spec.ProviderSpec)
	if err != nil {
		a.logger.WithError(err).Warningf("unable to determine cloud type for CredentialsRequest: %v", cr.Name)
	}
	cloudKey := cloudProviderSpecToMetricsKey(cloudType)
	a.crTotals[cloudKey]++

	// Skip reporting conditions if CCO is disabled, as we shouldn't be alerting in that case.
	if !ccoDisabled {
		for _, cond := range cr.Status.Conditions {
			if cond.Status == corev1.ConditionTrue {
				a.crConditions[cond.Type]++
			}
		}
	}
}

func (a *credRequestAccumulator) setCredentialsMode(ccoDisabled bool, secret *corev1.Secret, notFound bool) {
	if ccoDisabled {
		a.crMode[constants.ModeManual] = 1
		return
	}

	// if secret returned was nil and it wasn't a notFound err, then we have an unsupported
	// cloud and we'll just set it to "unknown" mode
	if secret == nil && !notFound {
		a.crMode[constants.ModeUnknown] = 1
		return
	}

	if notFound {
		a.crMode[constants.ModeCredsRemoved] = 1
		return
	}

	fmt.Printf("SECRET: %+v", secret.Annotations)

	annotation, ok := secret.Annotations[secretconstants.AnnotationKey]
	if !ok {
		// Unannotated secret...let it fall through so we get ModeUnknown???
		return
	}

	switch annotation {
	case secretconstants.MintAnnotation:
		a.crMode[constants.ModeMint] = 1
	case secretconstants.PassthroughAnnotation:
		a.crMode[constants.ModePassthrough] = 1
	case secretconstants.InsufficientAnnotation:
		a.crMode[constants.ModeDegraded] = 1
	default:
		a.crMode[constants.ModeUnknown] = 1
	}

	return
}

func (a *credRequestAccumulator) setMetrics() {
	for k, v := range a.crTotals {
		metricCredentialsRequestTotal.WithLabelValues(k).Set(float64(v))
	}

	for k, v := range a.crConditions {
		metricCredentialsRequestConditions.WithLabelValues(string(k)).Set(float64(v))
	}

	for k, v := range a.crMode {
		metricCredentialsMode.WithLabelValues(string(k)).Set(float64(v))
	}
}
