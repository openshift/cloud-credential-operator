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
	awsactuator "github.com/openshift/cloud-credential-operator/pkg/aws/actuator"
	"github.com/openshift/cloud-credential-operator/pkg/controller/credentialsrequest/actuator"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/manager"
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
		// TODO: cleanup hard coded AWS instantiation here:
		awsActuator, err := awsactuator.NewAWSActuator(m.GetClient(), scheme.Scheme)
		if err != nil {
			return err
		}
		if err := f(m, awsActuator); err != nil {
			return err
		}
	}
	return nil
}
