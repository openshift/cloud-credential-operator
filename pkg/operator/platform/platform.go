package platform

import (
	"context"

	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	//if infraStatus.PlatformStatus != nil && len(infraStatus.PlatformStatus.Type) > 0 {
	//	return infraStatus.PlatformStatus.Type
	//}
	return configv1.AWSPlatformType
	//return infraStatus.Platform
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
