package utils

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
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
	infra, err := GetInfrastructure(c)
	if err != nil {
		logger.WithError(err).Error("error loading Infrastructure config 'cluster'")
		return "", err
	}
	logger.Debugf("Loading infrastructure name: %s", infra.Status.InfrastructureName)
	return infra.Status.InfrastructureName, nil
}

// LoadInfrastructureRegion loads the AWS region the cluster is installed to.
func LoadInfrastructureRegion(c client.Client, logger log.FieldLogger) (string, error) {
	infra, err := GetInfrastructure(c)
	if err != nil {
		logger.WithError(err).Error("error loading Infrastructure region")
		return "", err
	}
	if infra.Status.PlatformStatus == nil {
		// Older clusters may have an Infrastructure object without the PlatformStatus fields.
		// Send back an empty region and the AWS client will use default settings.
		// The permissions simulation will also simply not fill out the region for simulations.
		// TODO: Once the oldest supported version of OpenShift includes the new migration operator,
		// we can remove this legacy handling and know that PlatformStatus/Region is set
		// https://github.com/openshift/cloud-credential-operator/pull/195#discussion_r432089284
		return "", nil
	}
	return infra.Status.PlatformStatus.AWS.Region, nil
}

// GetInfrastructure will return the cluster's Infrastructure object.
func GetInfrastructure(c client.Client) (*configv1.Infrastructure, error) {
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
			Name:      constants.CloudCredOperatorConfigMap,
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

func GetLogLevel(kubeClient client.Client, logger log.FieldLogger) (operatorv1.LogLevel, error) {
	conf, err := getOperatorConfiguration(kubeClient, logger)
	if err != nil {
		return "", err
	}

	return conf.Spec.LogLevel, nil
}
func GetOperatorLogLevel(kubeClient client.Client, logger log.FieldLogger) (operatorv1.LogLevel, error) {

	conf, err := getOperatorConfiguration(kubeClient, logger)
	if err != nil {
		return "", err
	}

	return conf.Spec.OperatorLogLevel, nil
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

func getOperatorConfiguration(kubeClient client.Client, logger log.FieldLogger) (*operatorv1.CloudCredential, error) {
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
			return nil, err
		}
		if errors.IsNotFound(err) {
			logger.Debugf("%s CCO operator config does not exist", constants.CloudCredOperatorConfig)
			return nil, err
		}
		return nil, err
	}
	return conf, nil
}

func getOperatorMode(kubeClient client.Client, logger log.FieldLogger) (operatorv1.CloudCredentialsMode, error) {
	conf, err := getOperatorConfiguration(kubeClient, logger)
	if err != nil {
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
		logger.Debugf("%s ConfigMap has no %s key, assuming default behavior", constants.CloudCredOperatorConfigMap, operatorConfigMapDisabledKey)
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

// UpgradeableCheck will set the Upgradeable condition based on the mode CCO is in:
//   Mint/Passthrough: check that the root creds secret exists
//   Manual: check that the CCO's config CR has been annotated properly to signal that the user has performed the pre-upgrade credentials tasks.
// Note: the upgradeable flag can only stop upgrades from 4.x to 4.y, not 4.x.y to 4.x.z.
func UpgradeableCheck(kubeClient client.Client, mode operatorv1.CloudCredentialsMode, rootSecret types.NamespacedName) *configv1.ClusterOperatorStatusCondition {
	upgradeableCondition := &configv1.ClusterOperatorStatusCondition{
		Type: configv1.OperatorUpgradeable,
	}

	clusterVersion := &configv1.ClusterVersion{}
	if err := kubeClient.Get(context.TODO(), types.NamespacedName{Name: "version"}, clusterVersion); err != nil {
		log.Errorf("Failed to get ClusterVersion object while calculating Upgradeable: %s", err)
		upgradeableCondition.Status = configv1.ConditionFalse
		upgradeableCondition.Reason = constants.ErrorDeterminingUpgradeableReason
		upgradeableCondition.Message = fmt.Sprintf("Error getting ClusterVersion while determining upgradability: %s", err)
		return upgradeableCondition
	}

	// Note: semver package wants the version string to start with a "v"
	clusterSemVer := getClusterVersionCompleted(clusterVersion)
	if clusterSemVer == "" {
		// cluster has not successfully completed an installation/upgrade at all
		log.Info("Cluster has not successfully completed an installation/upgrade yet")
		// don't set any condition for this case
		return nil
	}

	if !semver.IsValid(clusterSemVer) {
		upgradeableCondition.Status = configv1.ConditionFalse
		upgradeableCondition.Reason = constants.ErrorDeterminingUpgradeableReason
		upgradeableCondition.Message = fmt.Sprintf("Unable to decode cluster version: %s", clusterSemVer)
		return upgradeableCondition
	}

	clusterSemVer = semver.MajorMinor(clusterSemVer)

	// If the cluster admin has set the annotation, then bypass the Upgradeable calculation below and assume
	// the user knows what they are doing.
	operatorConfig := &operatorv1.CloudCredential{}
	operatorConfigKey := types.NamespacedName{
		Name: constants.CloudCredOperatorConfig,
	}
	if err := kubeClient.Get(context.Background(), operatorConfigKey, operatorConfig); err != nil {
		log.WithError(err).Error("unexpected error checking for CloudCredential config annotation")
		upgradeableCondition.Status = configv1.ConditionFalse
		upgradeableCondition.Reason = constants.ErrorDeterminingUpgradeableReason
		upgradeableCondition.Message = fmt.Sprintf("Error determining if cluster can be upgraded: %s", err)
		return upgradeableCondition
	}

	upgradeableTo := operatorConfig.Annotations[constants.UpgradeableAnnotation]

	if !strings.HasPrefix(upgradeableTo, "v") {
		upgradeableTo = "v" + upgradeableTo
	}

	upgradeableTo = semver.MajorMinor(upgradeableTo)

	if semver.Compare(upgradeableTo, clusterSemVer) == 1 {
		log.Info("Found annotation indicating upradeability, assuming upgradeable")
		return nil
	}

	// Check for upgradeability based on mode

	if mode == operatorv1.CloudCredentialsModeManual {

		// No matter what, if the annotation is missing/too low, we are Upgradeable=False when in Manual mode
		upgradeableCondition.Status = configv1.ConditionFalse
		upgradeableCondition.Reason = constants.MissingUpgradeableAnnotationReason
		upgradeableCondition.Message = fmt.Sprintf("Upgradeable annotation %s on cloudcredential.operator.openshift.io/cluster object needs updating before upgrade."+
			" See Manually Creating IAM documentation for instructions on preparing a cluster for upgrade.", constants.UpgradeableAnnotation)
		return upgradeableCondition
	}

	// if in mint or passthrough (basically non-Manual), make sure the root cred secret exists, if not it must be restored prior to upgrade.
	secret := &corev1.Secret{}

	err := kubeClient.Get(context.Background(), rootSecret, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			log.WithField("secret", rootSecret).Info("parent cred secret must be restored prior to upgrade, marking upgradeable=false")
			upgradeableCondition.Status = configv1.ConditionFalse
			upgradeableCondition.Reason = constants.MissingRootCredentialUpgradeableReason
			upgradeableCondition.Message = fmt.Sprintf("Parent credentials secret must be restored prior to upgrade: %s/%s",
				rootSecret.Namespace, rootSecret.Name)
			return upgradeableCondition
		}

		log.WithError(err).Error("unexpected error looking up parent secret, marking upgradeable=false")
		// If we can't figure out if you're upgradeable, you're not upgradeable:
		upgradeableCondition.Status = configv1.ConditionFalse
		upgradeableCondition.Reason = constants.ErrorDeterminingUpgradeableReason
		upgradeableCondition.Message = fmt.Sprintf("Error determining if cluster can be upgraded: %s", err)
		return upgradeableCondition
	}

	// Only return non-default conditions as the status controller will set defaults
	return nil
}

func getClusterVersionCompleted(clusterVersion *configv1.ClusterVersion) string {
	versionFound := ""

	// get the most recently completed version
	for _, version := range clusterVersion.Status.History {
		if version.State == configv1.CompletedUpdate {

			if versionFound == "" {
				versionFound = "v" + version.Version
				continue
			}

			// get the greater of the two version
			versionFound = semver.Max("v"+version.Version, versionFound)
		}
	}

	return versionFound
}

// FindClusterOperatorCondition iterates all conditions on a ClusterOperator looking for the
// specified condition type. If none exists nil will be returned.
func FindClusterOperatorCondition(conditions []configv1.ClusterOperatorStatusCondition, conditionType configv1.ClusterStatusConditionType) *configv1.ClusterOperatorStatusCondition {
	for i, condition := range conditions {
		if condition.Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}

// UpdateStatus updates the status of the credentials request
func UpdateStatus(client client.Client, origCR, newCR *minterv1.CredentialsRequest, logger log.FieldLogger) error {
	logger.Debug("updating credentials request status")

	// Update Credentials Request status if changed:
	if !reflect.DeepEqual(newCR.Status, origCR.Status) {
		logger.Infof("status has changed, updating")
		err := client.Status().Update(context.TODO(), newCR)
		if err != nil {
			logger.WithError(err).Error("error updating credentials request")
			return err
		}
	} else {
		logger.Debugf("status unchanged")
	}

	return nil
}
