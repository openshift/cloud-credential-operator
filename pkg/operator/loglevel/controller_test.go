package loglevel

import (
	"context"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/openshift/api/operator/v1"
	logLevelUtils "github.com/openshift/library-go/pkg/operator/loglevel"

	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
)

const (
	testCRName    = "cluster"
	testNamespace = "openshift-cloud-credential-operator"
)

type ExpectedCondition struct {
	klogLevel   operatorv1.LogLevel
	logrusLevel log.Level
}

func TestLogLevelCloudCredentialReconcile(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	tests := []struct {
		name               string
		existing           []runtime.Object
		expectedConditions ExpectedCondition
	}{
		{
			name: "set debug log level",
			existing: []runtime.Object{
				testOperatorConfig(operatorv1.Debug, operatorv1.Debug),
			},
			expectedConditions: ExpectedCondition{
				logrusLevel: log.DebugLevel,
				klogLevel:   operatorv1.Debug,
			},
		}, {
			name: "set normal log level",
			existing: []runtime.Object{
				testOperatorConfig(operatorv1.Normal, operatorv1.Normal),
			},
			expectedConditions: ExpectedCondition{
				logrusLevel: log.InfoLevel,
				klogLevel:   operatorv1.Normal,
			},
		}, {
			name: "ensure max loglevel is chosen",
			existing: []runtime.Object{
				testOperatorConfig(operatorv1.TraceAll, operatorv1.Normal),
			},
			expectedConditions: ExpectedCondition{
				logrusLevel: log.TraceLevel,
				klogLevel:   operatorv1.TraceAll,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithRuntimeObjects(test.existing...).Build()
			rccc := &ReconcileCloudCredentialConfig{
				Client: fakeClient,
			}

			_, err := rccc.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      constants.CloudCredOperatorConfig,
					Namespace: testNamespace,
				},
			})

			require.NoError(t, err, "Unexpected error: %v", err)

			klogLevel, _ := logLevelUtils.GetLogLevel()
			logrusLevel := log.GetLevel()

			// Check levels
			assert.Equal(t, test.expectedConditions.klogLevel, klogLevel)
			assert.Equal(t, test.expectedConditions.logrusLevel, logrusLevel)
		})
	}
}

func testOperatorConfig(logLevel, operatorLogLevel operatorv1.LogLevel) *operatorv1.CloudCredential {
	conf := &operatorv1.CloudCredential{
		ObjectMeta: metav1.ObjectMeta{
			Name: constants.CloudCredOperatorConfig,
		},
		Spec: operatorv1.CloudCredentialSpec{
			CredentialsMode: operatorv1.CloudCredentialsModeDefault,
			OperatorSpec: operatorv1.OperatorSpec{
				LogLevel:         logLevel,
				OperatorLogLevel: operatorLogLevel,
			},
		},
	}

	return conf
}
