package util

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/openshift/library-go/pkg/operator/events"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/clock"

	"sigs.k8s.io/controller-runtime/pkg/client/config"

	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
)

const (
	DefaultCCONamespace string = "openshift-cloud-credential-operator"
)

// GetEnabledFeatureGates returns the enabled feature gates from the list provided.
func GetEnabledFeatureGates() (featuregates.FeatureGate, error) {
	featureGateAccessor, err := GetFeatureGateAccessor()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	go featureGateAccessor.Run(ctx)

	select {
	case <-featureGateAccessor.InitialFeatureGatesObserved():
		currentFeatureGates, _ := featureGateAccessor.CurrentFeatureGates()
		log.Info("FeatureGates initialized", "knownFeatures", currentFeatureGates.KnownFeatures())
	case <-time.After(1 * time.Minute):
		log.Error(nil, "timed out waiting for FeatureGate detection")
		return nil, fmt.Errorf("timed out waiting for FeatureGate detection")
	}

	return featureGateAccessor.CurrentFeatureGates()
}

// GetFeatureGateAccessor retrieves a feature gate accessor that provides the caller with
// access to known feature gates in the cluster.
func GetFeatureGateAccessor() (featuregates.FeatureGateAccess, error) {
	kubeConfig, err := config.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get kube config: %v", err)
	}

	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kube client: %w", err)
	}
	eventRecorder := events.NewKubeRecorder(
		kubeClient.CoreV1().Events(DefaultCCONamespace),
		"cloud-credential-operator",
		&corev1.ObjectReference{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
			Namespace:  DefaultCCONamespace,
			Name:       "cloud-credential-operator",
		},
		clock.RealClock{},
	)

	configClient, err := configclient.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}
	configInformers := configinformers.NewSharedInformerFactory(configClient, 10*time.Minute)
	desiredVersion := "0.0.1-snapshot"
	missingVersion := "0.0.1-snapshot"

	// By default, this will exit(0) the process if the featuregates ever change to a different set of values.
	featureGateAccessor := featuregates.NewFeatureGateAccess(
		desiredVersion, missingVersion,
		configInformers.Config().V1().ClusterVersions(), configInformers.Config().V1().FeatureGates(),
		eventRecorder,
	)

	return featureGateAccessor, nil
}
