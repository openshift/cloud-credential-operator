package util

import (
	log "github.com/sirupsen/logrus"

	"k8s.io/apimachinery/pkg/runtime"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/cloud-credential-operator/pkg/apis"
)

func SetupScheme(scheme *runtime.Scheme) {
	// Setup Scheme for all resources
	log.Info("setting up scheme")
	if err := apis.AddToScheme(scheme); err != nil {
		log.WithError(err).Fatal("unable to add APIs to scheme")
	}

	// Setup OpenShift operator configs
	if err := operatorv1.Install(scheme); err != nil {
		log.Fatal(err)
	}

	// Setup Openshift config scheme:
	if err := configv1.Install(scheme); err != nil {
		log.Fatal(err)
	}
}
