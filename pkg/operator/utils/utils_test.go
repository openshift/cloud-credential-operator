package utils

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/pointer"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	schemeutil "github.com/openshift/cloud-credential-operator/pkg/util"
)

func TestGenerateName(t *testing.T) {
	tests := []struct {
		name                 string
		infraName            string
		infraNameMaxLen      int
		credentialName       string
		credentialNameMaxLen int
		expectedPrefix       string
		expectedError        bool
	}{
		{
			name:                 "no truncation",
			infraName:            "thisIsTheInfraName",
			infraNameMaxLen:      100,
			credentialName:       "thisIsTheCredentialName",
			credentialNameMaxLen: 100,
			expectedPrefix:       "thisIsTheInfraName-thisIsTheCredentialName",
		},
		{
			name:                 "12-11-5", // 30 total characters (service account id limit)
			infraName:            "thisIsTheInfraName",
			infraNameMaxLen:      12,
			credentialName:       "thisIsTheCredentialName",
			credentialNameMaxLen: 11,
			expectedPrefix:       "thisIsTheInf-thisIsTheCr",
		},
		{
			name:            "error on empty credentialName",
			infraName:       "thisIsTheInfraName",
			infraNameMaxLen: 100,
			expectedError:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			generatedName, err := GenerateUniqueNameWithFieldLimits(test.infraName, test.infraNameMaxLen, test.credentialName, test.credentialNameMaxLen)
			if test.expectedError {
				assert.Error(t, err, "Expected error returned")
			} else {
				assert.NoError(t, err, "Error not expected")

				assert.Regexp(t, regexp.MustCompile("^"+test.expectedPrefix), generatedName)

				//										infraName + '-' + credName + '-' + <random 5>
				assert.True(t, len(generatedName) <= test.infraNameMaxLen+1+test.credentialNameMaxLen+1+5, "generate name has unexpected length")
			}
		})
	}
}

func TestUpgradeableCheck(t *testing.T) {
	schemeutil.SetupScheme(scheme.Scheme)

	tests := []struct {
		name                  string
		mode                  operatorv1.CloudCredentialsMode
		clusterVersionMissing bool
		clusterVersion        *string
		upgradeableAnnotation *string
		expectedCondition     *configv1.ClusterOperatorStatusCondition
		extraRuntimeObjects   []runtime.Object
		rootSecretNameParam   types.NamespacedName
	}{
		{
			name:                  "clusterVersion error (missing)",
			mode:                  operatorv1.CloudCredentialsModeDefault,
			clusterVersionMissing: true,
			expectedCondition: &configv1.ClusterOperatorStatusCondition{
				Status: configv1.ConditionFalse,
				Reason: constants.ErrorDeterminingUpgradeableReason,
			},
		},
		{
			name:                  "upgradeable manual",
			mode:                  operatorv1.CloudCredentialsModeManual,
			clusterVersion:        pointer.StringPtr("4.6.0-1"),
			upgradeableAnnotation: pointer.StringPtr("4.7"),
		},
		{
			name:           "not upgradeable manual",
			mode:           operatorv1.CloudCredentialsModeManual,
			clusterVersion: pointer.StringPtr("4.6.0-1"),
			expectedCondition: &configv1.ClusterOperatorStatusCondition{
				Status: configv1.ConditionFalse,
				Reason: constants.MissingUpgradeableAnnotationReason,
			},
		},
		{
			name: "clusterVersion has no history",
			mode: operatorv1.CloudCredentialsModeDefault,
			// no condition expected as Upgradeable will assume cluster is new/installing
		},
		{
			name:           "clusterVersion has bad version",
			mode:           operatorv1.CloudCredentialsModeDefault,
			clusterVersion: pointer.StringPtr("not a semver version"),
			expectedCondition: &configv1.ClusterOperatorStatusCondition{
				Status: configv1.ConditionFalse,
				Reason: constants.ErrorDeterminingUpgradeableReason,
			},
		},
		{
			name:                "default mode with root secret",
			clusterVersion:      pointer.StringPtr("4.6.0"),
			mode:                operatorv1.CloudCredentialsModeDefault,
			rootSecretNameParam: types.NamespacedName{Name: constants.AWSCloudCredSecretName, Namespace: constants.CloudCredSecretNamespace},
			extraRuntimeObjects: []runtime.Object{
				testRootSecret(constants.AWSCloudCredSecretName),
			},
		},
		{
			name:                "default mode without root secret",
			clusterVersion:      pointer.StringPtr("4.6.0"),
			mode:                operatorv1.CloudCredentialsModeDefault,
			rootSecretNameParam: types.NamespacedName{Name: constants.AWSCloudCredSecretName, Namespace: constants.CloudCredSecretNamespace},
			expectedCondition: &configv1.ClusterOperatorStatusCondition{
				Status: configv1.ConditionFalse,
				Reason: constants.MissingRootCredentialUpgradeableReason,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			// Setup
			runtimeObjects := []runtime.Object{}

			if !test.clusterVersionMissing {
				clusterVersion := &configv1.ClusterVersion{
					ObjectMeta: metav1.ObjectMeta{
						Name: "version",
					},
				}
				if test.clusterVersion != nil {
					clusterVersion.Status.History = []configv1.UpdateHistory{
						{
							State:   configv1.CompletedUpdate,
							Version: *test.clusterVersion,
						},
					}
				}

				runtimeObjects = append(runtimeObjects, clusterVersion)
			}

			clusterOperator := &operatorv1.CloudCredential{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Spec: operatorv1.CloudCredentialSpec{
					CredentialsMode: test.mode,
				},
			}
			runtimeObjects = append(runtimeObjects, clusterOperator)

			if test.upgradeableAnnotation != nil {
				clusterOperator.Annotations = map[string]string{
					constants.UpgradeableAnnotation: *test.upgradeableAnnotation,
				}
			}
			runtimeObjects = append(runtimeObjects, test.extraRuntimeObjects...)
			fakeKubeClient := fake.NewClientBuilder().WithRuntimeObjects(runtimeObjects...).Build()

			// Test
			returnedCondition := UpgradeableCheck(fakeKubeClient, test.mode, test.rootSecretNameParam)

			// Assert
			if test.expectedCondition != nil {
				require.NotNil(t, returnedCondition, "expecting condition to compare against, but received no condition")

				assert.Equal(t, configv1.OperatorUpgradeable, returnedCondition.Type, "unexpected type on returned condition")

				assert.Equal(t, test.expectedCondition.Status, returnedCondition.Status, "unexpected status on returned condition")

				assert.Equal(t, test.expectedCondition.Reason, returnedCondition.Reason, "unexpected reason on condition")
			} else {
				assert.Nil(t, returnedCondition, "did not expect a condition to be returned (default return) and received one")
			}

			assert.True(t, true)
		})
	}
}

func testRootSecret(name string) *corev1.Secret {
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: constants.CloudCredSecretNamespace,
		},
	}
	return sec
}

func TestVersionFinding(t *testing.T) {
	tests := []struct {
		name            string
		expectedVersion string
		history         []configv1.UpdateHistory
	}{
		{
			name:            "single version",
			expectedVersion: "v4.6.3",
			history: []configv1.UpdateHistory{
				{
					State:   configv1.CompletedUpdate,
					Version: "4.6.3",
				},
			},
		},
		{
			name:            "find latest version",
			expectedVersion: "v4.6.3",
			history: []configv1.UpdateHistory{
				{
					State:   configv1.CompletedUpdate,
					Version: "4.6.3",
				},
				{
					State:   configv1.CompletedUpdate,
					Version: "4.5.3",
				},
			},
		},
		{
			name:            "ignore incomplete version",
			expectedVersion: "v4.6.3",
			history: []configv1.UpdateHistory{
				{
					State:   configv1.CompletedUpdate,
					Version: "4.6.3",
				},
				{
					State:   configv1.PartialUpdate,
					Version: "4.7.3",
				},
			},
		},
		{
			name:            "no history",
			expectedVersion: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			// Setup
			clusterVersion := &configv1.ClusterVersion{
				Status: configv1.ClusterVersionStatus{
					History: test.history,
				},
			}

			// Run
			returnedVersion := getClusterVersionCompleted(clusterVersion)

			// Assert
			assert.Equal(t, test.expectedVersion, returnedVersion)
		})
	}
}
