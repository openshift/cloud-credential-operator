package utils

import (
	"context"
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilrand "k8s.io/apimachinery/pkg/util/rand"

	"sigs.k8s.io/controller-runtime/pkg/client"

	log "github.com/sirupsen/logrus"

	configv1 "github.com/openshift/api/config/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
)

const (
	awsCredsSecretIDKey          = "aws_access_key_id"
	awsCredsSecretAccessKey      = "aws_secret_access_key"
	operatorConfigMapDisabledKey = "disabled"
)

func LoadCredsFromSecret(kubeClient client.Client, namespace, secretName string) ([]byte, []byte, error) {

	secret := &corev1.Secret{}
	err := kubeClient.Get(context.TODO(),
		types.NamespacedName{
			Name:      secretName,
			Namespace: namespace,
		},
		secret)
	if err != nil {
		return nil, nil, err
	}
	accessKeyID, ok := secret.Data[awsCredsSecretIDKey]
	if !ok {
		return nil, nil, fmt.Errorf("AWS credentials secret %v did not contain key %v",
			secretName, awsCredsSecretIDKey)
	}
	secretAccessKey, ok := secret.Data[awsCredsSecretAccessKey]
	if !ok {
		return nil, nil, fmt.Errorf("AWS credentials secret %v did not contain key %v",
			secretName, awsCredsSecretAccessKey)
	}
	return accessKeyID, secretAccessKey, nil
}

// LoadInfrastructureName loads the cluster Infrastructure config and returns the infra name
// used to identify this cluster, and tag some cloud objects.
func LoadInfrastructureName(c client.Client, logger log.FieldLogger) (string, error) {
	infra := &configv1.Infrastructure{}
	err := c.Get(context.Background(), types.NamespacedName{Name: "cluster"}, infra)
	if err != nil {
		logger.WithError(err).Error("error loading Infrastructure config 'cluster'")
		return "", err
	}

	logger.Debugf("Loaded infrastructure name: %s", infra.Status.InfrastructureName)
	return infra.Status.InfrastructureName, nil

}

// GetCredentialsRequestCloudType decodes a Spec.ProviderSpec and returns the kind
// field.
func GetCredentialsRequestCloudType(providerSpec *runtime.RawExtension) (string, error) {
	codec, err := minterv1.NewCodec()
	if err != nil {
		return "", err
	}
	unknown := runtime.Unknown{}
	err = codec.DecodeProviderSpec(providerSpec, &unknown)
	if err != nil {
		return "", err
	}
	return unknown.Kind, nil
}

// GenerateUniqueNameWithFieldLimits will take infraName and crName and shorten them if necessary to no longer
// than their respective MaxLen argument. it will then add a unique ending to the resulting name
// by appending '-<5 random chars>' to the resulting string.
// Example: passing "thisIsInfraName", 8, "thisIsCrName", 8 will return:
//		'thisIsIn-thisIsCr-<5 random chars>'
func GenerateUniqueNameWithFieldLimits(infraName string, infraNameMaxLen int, crName string, crNameMaxlen int) (string, error) {
	genName, err := GenerateNameWithFieldLimits(infraName, infraNameMaxLen, crName, crNameMaxlen)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s-%s", genName, utilrand.String(5)), nil
}

// GenerateNameWithFieldLimits lets you pass in two strings which will be clipped to their respective
// maximum lengths.
// Example: passing "thisIsInfraName", 8, "thisIsCrName", 8 will return:
//      'thisIsIn-thisIsCr'
func GenerateNameWithFieldLimits(infraName string, infraNameMaxLen int, crName string, crNameLen int) (string, error) {
	if crName == "" {
		return "", fmt.Errorf("empty credential request name")
	}

	infraPrefix := ""
	if infraName != "" {
		if len(infraName) > infraNameMaxLen {
			infraName = infraName[0:infraNameMaxLen]
		}
		infraPrefix = infraName + "-"
	}
	if len(crName) > crNameLen {
		crName = crName[0:crNameLen]
	}
	return fmt.Sprintf("%s%s", infraPrefix, crName), nil
}

// IsOperatorDisabled checks the cloud-credential-operator-config ConfigMap for a
// "disabled" property set to true. If the configmap or property do not exist, we assume
// false and continue normal operation. This should be used in all controllers to shutdown
// functionality in environments where admins want to manage their credentials themselves.
func IsOperatorDisabled(kubeClient client.Client, logger log.FieldLogger) (bool, error) {
	cm := &corev1.ConfigMap{}
	err := kubeClient.Get(context.TODO(),
		types.NamespacedName{
			Namespace: minterv1.CloudCredOperatorNamespace,
			Name:      minterv1.CloudCredOperatorConfigMap,
		}, cm)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Debugf("%s ConfigMap does not exist, assuming default behavior", minterv1.CloudCredOperatorConfigMap)
			return false, nil
		}
		return false, err
	}

	disabled, ok := cm.Data[operatorConfigMapDisabledKey]
	if !ok {
		logger.Debugf("%s ConfigMap has no %s key, assuming default behavior", minterv1.CloudCredOperatorConfigMap, operatorConfigMapDisabledKey)
		return false, nil
	}
	return strconv.ParseBool(disabled)
}
