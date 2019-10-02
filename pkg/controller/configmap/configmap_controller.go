/*
Copyright 2019 The OpenShift Authors.

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

package configmap

import (
	"context"
	"crypto/md5"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	controllerName   = "configmap"
	configMapName    = "cco-trusted-ca"
	configMapKeyName = "ca-bundle.crt"
	ccoNamespace     = "openshift-cloud-credential-operator"
)

// Add creates a new ConfigMap controller and adds it to the manager.
// Ignore the kubeconfigPath parameter as it is not needed for this controller.
func Add(mgr manager.Manager, kubeconfigPath string) error {
	return AddToManager(mgr, NewReconciler(mgr))
}

// NewReconciler returns a new reconcile.Reconciler
func NewReconciler(mgr manager.Manager) *ReconcileConfigMap {
	logFields := log.Fields{
		"controller": controllerName,
		// Controller only watches this one single configmap.
		"configmap": fmt.Sprintf("%s/%s", ccoNamespace, configMapName),
	}
	return &ReconcileConfigMap{
		Client: mgr.GetClient(),
		logger: log.WithFields(logFields),
		exit:   exitFunc,
	}
}

// AddToManager adds a new Controller to mgr with r as the reconcile.Reconciler
//func AddToManager(mgr manager.Manager, r *ReconcileConfigMap) error {
func AddToManager(mgr manager.Manager, r reconcile.Reconciler) error {
	c, err := controller.New(controllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		log.WithField("controller", controllerName).WithError(err).Error("Error creating controller")
		return err
	}

	// Watch for changes to the configMap containing the trusted CAs
	p := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			return configMapCheck(e.MetaNew)
		},
		CreateFunc: func(e event.CreateEvent) bool {
			return configMapCheck(e.Meta)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return configMapCheck(e.Meta)
		},
	}
	err = c.Watch(&source.Kind{Type: &corev1.ConfigMap{}}, &handler.EnqueueRequestForObject{}, p)
	if err != nil {
		return err
	}
	return nil
}

func configMapCheck(cm metav1.Object) bool {
	return cm.GetName() == configMapName && cm.GetNamespace() == ccoNamespace
}

var _ reconcile.Reconciler = &ReconcileConfigMap{}

// ReconcileConfigMap reconciles the ConfigMap containing the list of trusted CAs against
// any detected changes in the contents of the ConfigMap since the cloud-cred-operator
// pod started.
type ReconcileConfigMap struct {
	client.Client
	logger            log.FieldLogger
	configMapDataHash string
	// Allow testing to catch an exit call from the controller
	exit func()
}

// Reconcile checks for changes to the contents of the certificate authority configMap
func (r *ReconcileConfigMap) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	cm := &corev1.ConfigMap{}
	if err := r.Get(context.TODO(), request.NamespacedName, cm); err != nil {
		r.logger.WithError(err).Error("failed to read in configmap")
		return reconcile.Result{}, err
	}

	cmHash := fmt.Sprintf("%x", md5.Sum([]byte(cm.Data[configMapKeyName])))

	if r.configMapDataHash == "" {
		r.logger.Info("Saving hash of proxy CA configmap")
		r.configMapDataHash = cmHash
	} else if r.configMapDataHash == cmHash {
		r.logger.Debug("no change in proxy CA configmap detected")
	} else {
		r.logger.Info("Proxy CA configmap change detected, restarting pod")
		r.exit()
	}

	return reconcile.Result{}, nil
}

func exitFunc() {
	os.Exit(0)
}
