package metrics

import (
	"context"
	"strings"
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
	operatorv1 "github.com/openshift/api/operator/v1"

	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/platform"
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
func Add(mgr, rootCredentialManager manager.Manager, kubeConfig string) error {
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
func (mc *Calculator) Start(ctx context.Context) error {
	mc.log.Info("started metrics calculator goroutine")

	// Run forever, sleep at the end:
	wait.Until(mc.metricsLoop, mc.Interval, ctx.Done())

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

	mode, _, err := utils.GetOperatorConfiguration(mc.Client, mc.log)
	if err != nil {
		mc.log.WithError(err).Error("failed to determine whether CCO is disabled")
		return
	}
	ccoDisabled := mode == operatorv1.CloudCredentialsModeManual

	credRequests := &credreqv1.CredentialsRequestList{}
	if err := mc.Client.List(context.TODO(), credRequests); err != nil {
		mc.log.WithError(err).Error("error listing CredentialsRequests")
		return
	}

	accumulator := newAccumulator(mc.Client, mc.log)
	for _, cr := range credRequests.Items {
		accumulator.processCR(&cr, ccoDisabled)
	}
	accumulator.setMetrics()

	cloudSecret, err := mc.getCloudSecret()
	if err != nil && !errors.IsNotFound(err) {
		mc.log.WithError(err).Error("failed to fetch cloud secret")
		return
	}
	setCredentialsMode(&clusterState{
		mode:                        mode,
		rootSecret:                  cloudSecret,
		rootSecretNotFound:          errors.IsNotFound(err),
		foundPodIdentityCredentials: accumulator.podIdentityCredentials > 0,
	}, mc.log)
}

func (mc *Calculator) getCloudSecret() (*corev1.Secret, error) {
	infraStatus, err := platform.GetInfraStatus(mc.Client)
	if err != nil {
		mc.log.WithError(err).Error("failed to get Infrastructure.Status")
		return nil, err
	}
	platformType := platform.GetType(infraStatus)

	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{Namespace: constants.CloudCredSecretNamespace}
	switch platformType {
	case configv1.AWSPlatformType:
		secretKey.Name = constants.AWSCloudCredSecretName
	case configv1.AzurePlatformType:
		secretKey.Name = constants.AzureCloudCredSecretName
	case configv1.GCPPlatformType:
		secretKey.Name = constants.GCPCloudCredSecretName
	case configv1.OpenStackPlatformType:
		secretKey.Name = constants.OpenStackCloudCredsSecretName
	case configv1.OvirtPlatformType:
		secretKey.Name = constants.OvirtCloudCredsSecretName
	case configv1.VSpherePlatformType:
		secretKey.Name = constants.VSphereCloudCredSecretName
	case configv1.KubevirtPlatformType:
		secretKey.Name = constants.KubevirtCloudCredSecretName
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
	case "KubevirtProviderSpec":
		return "kubevirt"
	default:
		return "unknown"
	}
}

type credRequestAccumulator struct {
	kubeClient client.Client
	logger     log.FieldLogger

	crTotals     map[string]int
	crConditions map[credreqv1.CredentialsRequestConditionType]int
	crMode       map[constants.CredentialsMode]int

	podIdentityCredentials int
}

func newAccumulator(client client.Client, logger log.FieldLogger) *credRequestAccumulator {
	acc := &credRequestAccumulator{
		kubeClient:             client,
		logger:                 logger,
		crTotals:               map[string]int{},
		crConditions:           map[credreqv1.CredentialsRequestConditionType]int{},
		podIdentityCredentials: 0,
	}

	// make entries with '0' so we make sure to send updated metrics for any
	// condititons that may have cleared
	for _, c := range credreqv1.FailureConditionTypes {
		acc.crConditions[c] = 0
	}
	acc.crConditions[credreqv1.StaleCredentials] = 0

	return acc
}

func (a *credRequestAccumulator) processCR(cr *credreqv1.CredentialsRequest, ccoDisabled bool) {
	cloudType, err := utils.GetCredentialsRequestCloudType(cr.Spec.ProviderSpec)
	if err != nil {
		a.logger.WithError(err).Warningf("unable to determine cloud type for CredentialsRequest: %v", cr.Name)
	}
	cloudKey := cloudProviderSpecToMetricsKey(cloudType)
	a.crTotals[cloudKey]++

	isPodIdentity, err := credRequestIsPodIdentity(cr, cloudType, a.kubeClient)
	if err != nil {
		a.logger.WithError(err).Error("failed to determine whether CredentialsRequest is of type STS")
	}

	if isPodIdentity {
		a.podIdentityCredentials++
	}

	// Skip reporting conditions if CCO is disabled, as we shouldn't be alerting in that case, except for stale credentials.
	// condition. The stale credentials are removed by cleanup controller. But when CCO is disabled the only way to inform
	// users to remove these credentials is through alerts.
	if !ccoDisabled {
		for _, cond := range cr.Status.Conditions {
			// do not report stale credentials when CCO is enabled as it will be removed by cleanup controller.
			if cond.Status == corev1.ConditionTrue && cond.Type != credreqv1.StaleCredentials {
				a.crConditions[cond.Type]++
			}
		}
	} else {
		for _, cond := range cr.Status.Conditions {
			if cond.Status == corev1.ConditionTrue && cond.Type == credreqv1.StaleCredentials {
				a.crConditions[cond.Type]++
			}
		}
	}
}

type clusterState struct {
	mode                        operatorv1.CloudCredentialsMode
	rootSecret                  *corev1.Secret
	rootSecretNotFound          bool
	foundPodIdentityCredentials bool
}

func setCredentialsMode(state *clusterState, logger log.FieldLogger) {
	crMode := map[constants.CredentialsMode]int{}

	// First set all possibilities to zero (in case we have switched modes since last time)
	for _, mode := range constants.CredentialsModeList {
		crMode[mode] = 0
	}

	detectedMode := determineCredentialsMode(state, logger)

	crMode[detectedMode] = 1

	for k, v := range crMode {
		if v > 0 {
			metricCredentialsMode.WithLabelValues(string(k)).Set(float64(v))
		} else {
			// Ensure unused modes are cleared if we've recently changed mode:
			metricCredentialsMode.Delete(map[string]string{"mode": string(k)})
		}
	}
}

func determineCredentialsMode(state *clusterState, logger log.FieldLogger) constants.CredentialsMode {
	if state == nil {
		logger.Error("unexpectedly received a nil state for calculating mode")
		return constants.ModeUnknown
	}

	if state.mode == operatorv1.CloudCredentialsModeManual {

		// if the accumulator found any Secrets with pod identity credentials data
		// then we'll report the PodIdentity submode of Manual mode
		if state.foundPodIdentityCredentials {
			return constants.ModeManualPodIdentity
		}

		//else return generic ModeManual
		return constants.ModeManual
	}

	// if secret returned was nil and it wasn't a notFound err, then we have an unsupported
	// cloud and we'll just set it to "unknown" mode
	if state.rootSecret == nil && !state.rootSecretNotFound {
		return constants.ModeUnknown
	}

	if state.rootSecretNotFound {
		return constants.ModeCredsRemoved
	}

	annotation, ok := state.rootSecret.Annotations[constants.AnnotationKey]
	if !ok {
		logger.Warn("Secret missing mode annotation, assuming ModeUnknown")
		return constants.ModeUnknown
	}

	switch annotation {
	case constants.MintAnnotation:
		return constants.ModeMint
	case constants.PassthroughAnnotation:
		return constants.ModePassthrough
	case constants.InsufficientAnnotation:
		return constants.ModeDegraded
	default:
		return constants.ModeUnknown
	}
}

func (a *credRequestAccumulator) setMetrics() {
	for k, v := range a.crTotals {
		metricCredentialsRequestTotal.WithLabelValues(k).Set(float64(v))
	}

	for k, v := range a.crConditions {
		metricCredentialsRequestConditions.WithLabelValues(string(k)).Set(float64(v))
	}
}

func credRequestIsPodIdentity(cr *credreqv1.CredentialsRequest, cloudType string, kubeClient client.Client) (bool, error) {
	secretKey := types.NamespacedName{Name: cr.Spec.SecretRef.Name, Namespace: cr.Spec.SecretRef.Namespace}
	secret := &corev1.Secret{}

	err := kubeClient.Get(context.TODO(), secretKey, secret)
	if errors.IsNotFound(err) {
		// Secret for CredReq doesn't exist so we can't query it
		return false, nil
	} else if err != nil {
		return false, err
	}

	switch cloudType {
	case "AWSProviderSpec":
		secretData, ok := secret.Data[constants.AWSSecretDataCredentialsKey]
		if !ok {
			return false, nil
		}

		// web_identity_token_file is a clear indicator that the credentials
		// are configured for pod identity / STS credentials
		if strings.Contains(string(secretData), "web_identity_token_file") {
			return true, nil
		}

		return false, nil
	default:
		return false, nil
	}

}
