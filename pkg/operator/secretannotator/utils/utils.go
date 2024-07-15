package utils

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
)

var cloudSecretKeyPassThru types.NamespacedName

// WatchCCOConfig will add a watch to the provided controller for the operator
// config resource which will schedule the provided secret for reconciliation.
func WatchCCOConfig(cache cache.Cache, c controller.Controller, cloudSecretKey types.NamespacedName, mgr manager.Manager) error {
	cloudSecretKeyPassThru = cloudSecretKey

	configPredicate := predicate.TypedFuncs[*operatorv1.CloudCredential]{
		UpdateFunc: func(e event.TypedUpdateEvent[*operatorv1.CloudCredential]) bool {
			return cloudCredentialConfigObjectCheck(e.ObjectNew)
		},
		CreateFunc: func(e event.TypedCreateEvent[*operatorv1.CloudCredential]) bool {
			return cloudCredentialConfigObjectCheck(e.Object)
		},
		DeleteFunc: func(e event.TypedDeleteEvent[*operatorv1.CloudCredential]) bool {
			return cloudCredentialConfigObjectCheck(e.Object)
		},
	}

	err := c.Watch(source.Kind[*operatorv1.CloudCredential](cache, &operatorv1.CloudCredential{},
		handler.TypedEnqueueRequestsFromMapFunc[*operatorv1.CloudCredential](cloudCredSecretRequest[*operatorv1.CloudCredential]),
		configPredicate))
	return err
}

func cloudCredentialConfigObjectCheck(conf metav1.Object) bool {
	return conf.GetName() == constants.CloudCredOperatorConfig
}

func cloudCredSecretRequest[T *operatorv1.CloudCredential](ctx context.Context, object T) []reconcile.Request {
	// Just requeue the cloud-cred secret for any change to the CCO config object
	return []reconcile.Request{
		{
			NamespacedName: cloudSecretKeyPassThru,
		},
	}
}
