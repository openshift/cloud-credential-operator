package platform

import (
	"context"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	configv1 "github.com/openshift/api/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/events"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crtconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// GetInfraStatusUsingKubeconfig queries the k8s api for the infrastructure CR using the kubeconfig file
// pointed to by the passed in kubeconfig (pass in empty string to use default k8s client configurations)
func GetInfraStatusUsingKubeconfig(m manager.Manager, kubeconfig string) (*configv1.InfrastructureStatus, error) {
	c, err := getClient(kubeconfig)
	if err != nil {
		return nil, err
	}

	return GetInfraStatus(c)
}

// GetInfraStatus will return the clusterwide Infrastructure's object status
func GetInfraStatus(kClient client.Client) (*configv1.InfrastructureStatus, error) {
	infra := &configv1.Infrastructure{}
	infraName := types.NamespacedName{Name: "cluster"}

	if err := kClient.Get(context.Background(), infraName, infra); err != nil {
		return nil, err
	}
	return &infra.Status, nil
}

// GetType returns the platform type given an infrastructure status. If PlatformStatus is set,
// it will get the platform type from it, otherwise it will get it from InfraStatus.Platform which
// is deprecated in 4.2
func GetType(infraStatus *configv1.InfrastructureStatus) configv1.PlatformType {
	if infraStatus.PlatformStatus != nil && len(infraStatus.PlatformStatus.Type) > 0 {
		return infraStatus.PlatformStatus.Type
	}
	return infraStatus.Platform
}

func getClient(explicitKubeconfig string) (client.Client, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = explicitKubeconfig
	kubeconfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{})
	cfg, err := kubeconfig.ClientConfig()
	if err != nil {
		return nil, err
	}

	//apis.AddToScheme(scheme.Scheme)
	dynamicClient, err := client.New(cfg, client.Options{})
	if err != nil {
		return nil, err
	}

	return dynamicClient, nil
}

func GetFeatureGates(ctx context.Context) (featuregates.FeatureGate, error) {
	stop := make(chan struct{})
	ctx, cancelFn := context.WithCancel(ctx)
	go func() {
		defer cancelFn()
		<-stop
	}()

	config, err := crtconfig.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get kube config: %v", err)
	}
	clientSet, err := configclient.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	configInformers := configinformers.NewSharedInformerFactory(clientSet, 10*time.Minute)
	desiredVersion := computeClusterOperatorVersions()
	missingVersion := desiredVersion

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kube client: %w", err)
	}
	eventRecorder := events.NewKubeRecorder(kubeClient.CoreV1().Events("openshift-cloud-credential-operator"), "cloud-credential-operator", &corev1.ObjectReference{
		APIVersion: "apps/v1",
		Kind:       "Deployment",
		Namespace:  "openshift-cloud-credential-operator",
		Name:       "cloud-credential-operator",
	})

	// By default, this will exit(0) the process if the featuregates ever change to a different set of values.
	featureGateAccessor := featuregates.NewFeatureGateAccess(
		desiredVersion, missingVersion,
		configInformers.Config().V1().ClusterVersions(), configInformers.Config().V1().FeatureGates(),
		eventRecorder,
	)
	go featureGateAccessor.Run(ctx)
	go configInformers.Start(stop)

	select {
	case <-featureGateAccessor.InitialFeatureGatesObserved():
		featureGates, _ := featureGateAccessor.CurrentFeatureGates()
		log.Info("FeatureGates initialized", "knownFeatures", featureGates.KnownFeatures())
	case <-time.After(1 * time.Minute):
		log.Error(nil, "timed out waiting for FeatureGate detection")
		return nil, fmt.Errorf("timed out waiting for FeatureGate detection")
	}

	featureGates, err := featureGateAccessor.CurrentFeatureGates()
	if err != nil {
		return nil, err
	}
	return featureGates, nil
}

func computeClusterOperatorVersions() string {
	currentVersion := os.Getenv("RELEASE_VERSION")
	return currentVersion
}
