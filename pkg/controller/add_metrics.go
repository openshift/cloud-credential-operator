package controller

import (
	"github.com/openshift/cloud-credential-operator/pkg/controller/metrics"
)

func init() {
	// AddToManagerFUncs is a list of functions to create controller for and add them to a manager.
	AddToManagerFuncs = append(AddToManagerFuncs, metrics.Add)
}
