package loglevel

import (
	log "github.com/sirupsen/logrus"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/status"
)

var _ status.Handler = &ReconcileCloudCredentialConfig{}

func (r *ReconcileCloudCredentialConfig) GetConditions(logger log.FieldLogger) ([]configv1.ClusterOperatorStatusCondition, error) {
	return []configv1.ClusterOperatorStatusCondition{}, nil
}

func (r *ReconcileCloudCredentialConfig) GetRelatedObjects(logger log.FieldLogger) ([]configv1.ObjectReference, error) {
	return []configv1.ObjectReference{}, nil
}

func (r *ReconcileCloudCredentialConfig) Name() string {
	return controllerName
}
