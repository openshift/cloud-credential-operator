package platform

import (
	"context"

	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// Get queries the ku8s api for the infrastructure config map and retrieves the current platform.
func GetStatus(m manager.Manager) (*configv1.PlatformStatus, error) {
	c, err := getClient()
	if err != nil {
		return nil, err
	}
	infraName := types.NamespacedName{Name: "cluster"}
	infra := &configv1.Infrastructure{}
	err = c.Get(context.Background(), infraName, infra)
	if err != nil {
		return nil, err
	}
	return infra.Status.PlatformStatus, nil
}

func getClient() (client.Client, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
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
