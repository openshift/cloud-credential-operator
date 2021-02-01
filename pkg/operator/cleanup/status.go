package cleanup

import (
	log "github.com/sirupsen/logrus"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/status"
)

var _ status.Handler = &ReconcileStaleCredentialsRequest{}

func (r *ReconcileStaleCredentialsRequest) GetConditions(logger log.FieldLogger) ([]configv1.ClusterOperatorStatusCondition, error) {
	return []configv1.ClusterOperatorStatusCondition{}, nil
}

func (r *ReconcileStaleCredentialsRequest) GetRelatedObjects(logger log.FieldLogger) ([]configv1.ObjectReference, error) {
	return []configv1.ObjectReference{}, nil
}

func (r *ReconcileStaleCredentialsRequest) Name() string {
	return controllerName
}
