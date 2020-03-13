package utils

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilrand "k8s.io/apimachinery/pkg/util/rand"

	"sigs.k8s.io/controller-runtime/pkg/client"

	log "github.com/sirupsen/logrus"

	configv1 "github.com/openshift/api/config/v1"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
)

const (
	awsCredsSecretIDKey     = "aws_access_key_id"
	awsCredsSecretAccessKey = "aws_secret_access_key"
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
