/*
Copyright 2020 The OpenShift Authors.

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

package loglevel

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	operatorv1 "github.com/openshift/api/operator/v1"
	logLevelUtils "github.com/openshift/library-go/pkg/operator/loglevel"

	"github.com/openshift/cloud-credential-operator/pkg/operator/status"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

const (
	controllerName = "loglevel"
)

// Add creates a new ConfigController and adds it to the Manager.
func Add(mgr, rootCredentialManager manager.Manager, kubeConfig string) error {
	r := newReconciler(mgr)

	// Create a new controller
	c, err := controller.New(controllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to CloudCredential object and reconcile the loglevel changes
	err = c.Watch(
		source.Kind(mgr.GetCache(), &operatorv1.CloudCredential{},
			&handler.TypedEnqueueRequestForObject[*operatorv1.CloudCredential]{}))

	if err != nil {
		return err
	}

	return nil
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	r := &ReconcileCloudCredentialConfig{
		Client: mgr.GetClient(),
	}
	status.AddHandler(controllerName, r)

	return r
}

var _ reconcile.Reconciler = &ReconcileCloudCredentialConfig{}

// ReconcileCloudCredentialConfig reconciles a CredentialConfig object
type ReconcileCloudCredentialConfig struct {
	client.Client
}

// Reconcile reads the state of the cluster for a CredentialConfig object and
// makes changes based on the state read and what is in the CredentialConfig.LogLevel
// Automatically generate RBAC rules to allow the Controller to read and write required types.
// +kubebuilder:rbac:groups=operator.openshift.io,resources=cloudcredential/spec,verbs=get
func (r *ReconcileCloudCredentialConfig) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	logger := log.WithFields(log.Fields{
		"controller": controllerName,
		"cr":         fmt.Sprintf("%s/%s", request.NamespacedName.Namespace, request.NamespacedName.Name),
	})

	// Check OperatorLogLevel and LogLevel
	log.Debug("Checking log level for Reconcile request")
	desiredOperatorLogLevel, err := utils.GetOperatorLogLevel(r, logger)
	if err != nil {
		return reconcile.Result{}, err
	}
	if !logLevelUtils.ValidLogLevel(desiredOperatorLogLevel) {
		return reconcile.Result{}, fmt.Errorf("the operatorLogLevel defined for the cloudcredential object is invalid")
	}

	desiredLogLevel, err := utils.GetLogLevel(r, logger)
	if err != nil {
		return reconcile.Result{}, err
	}

	if !logLevelUtils.ValidLogLevel(desiredLogLevel) {
		return reconcile.Result{}, fmt.Errorf("the logLevel defined for the cloudcredential object is invalid")
	}

	// Pick the logLevel with the highest verbosity level.
	maxLogLevel := desiredOperatorLogLevel
	if logLevelUtils.LogLevelToVerbosity(desiredLogLevel) > logLevelUtils.LogLevelToVerbosity(desiredOperatorLogLevel) {
		maxLogLevel = desiredLogLevel
	}

	currentLogLevel, errBool := logLevelUtils.GetLogLevel()
	if errBool {
		log.Debug("Unable to get the current loglevel. Defaulting the current level to 'Normal'")
	}

	if currentLogLevel == maxLogLevel {
		return reconcile.Result{}, nil
	}

	// Set klog logLevel to the desired level
	err = logLevelUtils.SetLogLevel(maxLogLevel)
	if err != nil {
		return reconcile.Result{}, err
	}

	log.Infof("klog level changed to %v", maxLogLevel)

	// Set lorus logLevel to the desired level
	logrusLevel := crLogLevelToLogrusLevel(maxLogLevel)
	log.SetLevel(logrusLevel)
	log.Infof("logrus level changed to %s", logrusLevel)

	return reconcile.Result{}, nil
}

func crLogLevelToLogrusLevel(logLevel operatorv1.LogLevel) (logrusLevel log.Level) {
	switch logLevel {
	case operatorv1.Debug:
		logrusLevel = log.DebugLevel
	case operatorv1.Trace, operatorv1.TraceAll:
		logrusLevel = log.TraceLevel
	case operatorv1.Normal:
		logrusLevel = log.InfoLevel
	default:
		logrusLevel = log.InfoLevel
	}
	return logrusLevel
}
