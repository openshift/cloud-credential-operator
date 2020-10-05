package status

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/status"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

type SecretStatusHandler struct {
	kubeClient client.Client
}

func NewSecretStatusHandler(kubeClient client.Client) *SecretStatusHandler {
	return &SecretStatusHandler{
		kubeClient: kubeClient,
	}
}

var _ status.Handler = &SecretStatusHandler{}

func (s *SecretStatusHandler) GetConditions(logger log.FieldLogger) ([]configv1.ClusterOperatorStatusCondition, error) {
	conditions := []configv1.ClusterOperatorStatusCondition{}

	mode, conflict, err := utils.GetOperatorConfiguration(s.kubeClient, logger)
	if err != nil {
		return conditions, err
	}

	// shouldn't happen with the server-side enforcement of the CRDs enum specification
	if !utils.IsValidMode(mode) {
		conditions = append(conditions, configv1.ClusterOperatorStatusCondition{
			Type:    configv1.OperatorDegraded,
			Status:  configv1.ConditionTrue,
			Reason:  constants.StatusModeInvalid,
			Message: fmt.Sprintf("operator mode of %s is invalid", mode),
		})
	} else if conflict {
		conditions = append(conditions, configv1.ClusterOperatorStatusCondition{
			Type:   configv1.OperatorDegraded,
			Status: configv1.ConditionTrue,
			Reason: constants.StatusModeMismatch,
			Message: fmt.Sprintf("legacy configmap disabled setting conflicts with operator config mode of %s",
				mode),
		})
	}

	return conditions, nil
}

func (s *SecretStatusHandler) GetRelatedObjects(logger log.FieldLogger) ([]configv1.ObjectReference, error) {
	related := []configv1.ObjectReference{
		{
			Group:    operatorv1.GroupName,
			Resource: "cloudcredentials",
			Name:     constants.CloudCredOperatorConfig,
		},
	}

	// check for the legacy configmap
	cm, err := utils.GetLegacyConfigMap(s.kubeClient)
	if err != nil && !errors.IsNotFound(err) {
		logger.WithError(err).Error("failed fetching legacy configmap")
		return related, err
	}

	// add the configmap if it exists
	if !errors.IsNotFound(err) {
		related = append(related, configv1.ObjectReference{
			Resource:  "configmap",
			Namespace: cm.Namespace,
			Name:      cm.Name,
		})
	}

	return related, nil
}

func (s *SecretStatusHandler) Name() string {
	return constants.SecretAnnotatorControllerName
}
