/*
Copyright 2018 The OpenShift Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"

	awsactuator "github.com/openshift/cloud-credential-operator/pkg/aws/actuator"
	"github.com/openshift/cloud-credential-operator/pkg/controller/credentialsrequest/actuator"

	configv1 "github.com/openshift/api/config/v1"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	log "github.com/sirupsen/logrus"
)

const (
	installConfigMap   = "cluster-config-v1"
	installConfigMapNS = "kube-system"
)

// AddToManagerFuncs is a list of functions to add all Controllers to the Manager
var AddToManagerFuncs []func(manager.Manager) error

// AddToManagerWithActuatorFuncs is a list of functions to add all Controllers with Actuators to the Manager
var AddToManagerWithActuatorFuncs []func(manager.Manager, actuator.Actuator) error

// AddToManager adds all Controllers to the Manager
func AddToManager(m manager.Manager) error {
	for _, f := range AddToManagerFuncs {
		if err := f(m); err != nil {
			return err
		}
	}
	for _, f := range AddToManagerWithActuatorFuncs {
		// Check if this is an AWS cluster and if not, add a dummy actuator:
		// TODO: Use infrastructure type to determine this in future, it's not being populated yet:
		// https://github.com/openshift/api/blob/master/config/v1/types_infrastructure.go#L11
		var err error
		var a actuator.Actuator
		isAWS, err := isAWSCluster(m)
		if err != nil {
			log.Fatal(err)
		}
		if isAWS {
			log.Info("initializing AWS actuator")
			a, err = awsactuator.NewAWSActuator(m.GetClient(), m.GetScheme())
			if err != nil {
				return err
			}
		} else {
			log.Info("initializing no-op actuator (not an AWS cluster)")
			a = &actuator.DummyActuator{}
		}
		if err := f(m, a); err != nil {
			return err
		}
	}
	return nil
}

func isAWSCluster(m manager.Manager) (bool, error) {
	client, err := getClient()
	if err != nil {
		return false, err
	}
	infraName := types.NamespacedName{Name: "cluster"}
	infra := &configv1.Infrastructure{}
	err = client.Get(context.Background(), infraName, infra)
	if err != nil {
		return false, err
	}
	return infra.Status.Platform == configv1.AWSPlatformType, nil
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
