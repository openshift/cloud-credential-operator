package utils

import (
	"context"
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metaerrors "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilrand "k8s.io/apimachinery/pkg/util/rand"

	"sigs.k8s.io/controller-runtime/pkg/client"

	log "github.com/sirupsen/logrus"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
)

const (
	awsCredsSecretIDKey          = "aws_access_key_id"
	awsCredsSecretAccessKey      = "aws_secret_access_key"
	operatorConfigMapDisabledKey = "disabled"

	// OperatorDisabledDefault holds the default behavior of whether CCO is disabled
	// in the absence of any setting in the ConfigMap
	OperatorDisabledDefault = false
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
	infra, err := getInfrastructure(c)
	if err != nil {
		logger.WithError(err).Error("error loading Infrastructure config 'cluster'")
		return "", err
	}
	logger.Debugf("Loading infrastructure name: %s", infra.Status.InfrastructureName)
	return infra.Status.InfrastructureName, nil
}

// LoadInfrastructureRegion loads the AWS region the cluster is installed to.
func LoadInfrastructureRegion(c client.Client, logger log.FieldLogger) (string, error) {
	infra, err := getInfrastructure(c)
	if err != nil {
		logger.WithError(err).Error("error loading Infrastructure region")
		return "", err
	}
	if infra.Status.PlatformStatus == nil {
		// Older clusters may have an Infrastructure object without the PlatformStatus fields.
		// Send back an empty region and the AWS client will use default settings.
		// The permissions simulation will also simply not fill out the region for simulations.
		return "", nil
	}
	return infra.Status.PlatformStatus.AWS.Region, nil
}

func getInfrastructure(c client.Client) (*configv1.Infrastructure, error) {
	infra := &configv1.Infrastructure{}
	if err := c.Get(context.TODO(), types.NamespacedName{Name: "cluster"}, infra); err != nil {
		return nil, err
	}
	return infra, nil
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

// isOperatorDisabledViaConfigmap checks the cloud-credential-operator-config ConfigMap for a
// "disabled" property set to true. If the configmap or property does not exist, we assume
// false and continue normal operation.
// DEPRECATED (and unexported), use GetOperatorConfiguration to determine disabled state.
func isOperatorDisabledViaConfigmap(kubeClient client.Client, logger log.FieldLogger) (bool, error) {
	cm, err := GetLegacyConfigMap(kubeClient)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Debugf("%s ConfigMap does not exist, assuming default behavior", constants.CloudCredOperatorConfigMap)
			return OperatorDisabledDefault, nil
		}
		return OperatorDisabledDefault, err
	}

	return CCODisabledCheck(cm, logger)
}

func GetLegacyConfigMap(kubeClient client.Client) (*corev1.ConfigMap, error) {
	cm := &corev1.ConfigMap{}
	err := kubeClient.Get(context.TODO(),
		types.NamespacedName{
			Namespace: minterv1.CloudCredOperatorNamespace,
			Name:      minterv1.CloudCredOperatorConfigMap,
		}, cm)
	return cm, err
}

// GetOperatorConfiguration will return the value in the operator config (reporting "manual" mode if necessary),
// and whether there is a conflict between the legacy ConfigMap and CCO config (in the even of a conflict, the
// operator mode will be reported to reflect the actual value in the operator config).
func GetOperatorConfiguration(kubeClient client.Client, logger log.FieldLogger) (
	effectiveOperatorMode operatorv1.CloudCredentialsMode,
	configurationConflict bool,
	err error) {
	var operatorMode operatorv1.CloudCredentialsMode
	operatorMode, err = getOperatorMode(kubeClient, logger)
	if err != nil {
		return
	}

	var disabledViaConfigMap bool
	disabledViaConfigMap, err = isOperatorDisabledViaConfigmap(kubeClient, logger)
	if err != nil {
		return
	}

	effectiveOperatorMode, configurationConflict = GetEffectiveOperatorMode(disabledViaConfigMap, operatorMode)
	if configurationConflict {
		log.Errorf("legacy configmap disabled set to %v conflicts with operator CR mode of %s",
			disabledViaConfigMap, operatorMode)
	}

	return
}

// GetEffectiveOperatorMode will take the legacy configmap and the value in the operator config, and return
// the effective CCO mode and whether there is a conflict between the legacy and operator config values.
func GetEffectiveOperatorMode(configMapDisabledValue bool, operatorConfigMode operatorv1.CloudCredentialsMode) (operatorv1.CloudCredentialsMode, bool) {

	// if no mode is set, then only the value in the configmap can end up disabling CCO
	if operatorConfigMode == "" {
		if configMapDisabledValue {
			return operatorv1.CloudCredentialsModeManual, false
		}
		return operatorConfigMode, false
	}

	// else see if there is a disconnect between the operator mode and the
	// opt-in value of 'disabled: "true"' in the ConfigMap
	disabledViaOperatorConfig := operatorConfigMode == operatorv1.CloudCredentialsModeManual
	if configMapDisabledValue && !disabledViaOperatorConfig {
		return operatorConfigMode, true
	}

	return operatorConfigMode, false

}

func getOperatorMode(kubeClient client.Client, logger log.FieldLogger) (operatorv1.CloudCredentialsMode, error) {
	conf := &operatorv1.CloudCredential{}

	err := kubeClient.Get(context.TODO(),
		types.NamespacedName{
			Name: constants.CloudCredOperatorConfig,
		}, conf)
	if err != nil {
		// TODO: is it valuable to watch for this error, or just return the error
		// at the bottom of this block???
		if metaerrors.IsNoMatchError(err) {
			logger.WithError(err).Debug("no config CRD found")
			return "", err
		}
		if errors.IsNotFound(err) {
			logger.Debugf("%s CCO operator config does not exist", constants.CloudCredOperatorConfig)
			return "", err
		}
		return "", err
	}

	return conf.Spec.CredentialsMode, nil
}

// CCODisabledCheck will take the operator configuration ConfigMap and return
// whether the CCO operator is set to enabled or disabled.
// TODO: investigate unexporting this once the bootstrap render process can
// deal with the new config CR
func CCODisabledCheck(cm *corev1.ConfigMap, logger log.FieldLogger) (bool, error) {
	disabled, ok := cm.Data[operatorConfigMapDisabledKey]
	if !ok {
		logger.Debugf("%s ConfigMap has no %s key, assuming default behavior", minterv1.CloudCredOperatorConfigMap, operatorConfigMapDisabledKey)
		return OperatorDisabledDefault, nil
	}
	return strconv.ParseBool(disabled)
}

// ModeToAnnotation converts a CCO operator mode to a CCO secret annotation
// or errors if the mode is not one that converts to a secret annotation.
func ModeToAnnotation(operatorMode operatorv1.CloudCredentialsMode) (string, error) {
	switch operatorMode {
	case operatorv1.CloudCredentialsModeMint:
		return constants.MintAnnotation, nil
	case operatorv1.CloudCredentialsModePassthrough:
		return constants.PassthroughAnnotation, nil
	default:
		return "", fmt.Errorf("no annotation for operator mode: %s", operatorMode)
	}
}

func IsValidMode(operatorMode operatorv1.CloudCredentialsMode) bool {
	switch operatorMode {
	case operatorv1.CloudCredentialsModeDefault,
		operatorv1.CloudCredentialsModeManual,
		operatorv1.CloudCredentialsModeMint,
		operatorv1.CloudCredentialsModePassthrough:
		return true
	default:
		return false
	}
}
