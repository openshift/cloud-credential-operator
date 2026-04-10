/*
Copyright 2018 The OpenShift Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package podidentity

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	clientgotesting "k8s.io/client-go/testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/golang/mock/gomock"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	fakeclientgo "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	configv1 "github.com/openshift/api/config/v1"
	schemeutils "github.com/openshift/cloud-credential-operator/pkg/util"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func TestPodIdentityWebhookController(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	getDeployment := func(c kubernetes.Interface, name, namespace string) (*appsv1.Deployment, error) {
		return c.AppsV1().Deployments(namespace).Get(context.TODO(), name, v1.GetOptions{})
	}

	getPDB := func(c kubernetes.Interface, name, namespace string) (*policyv1.PodDisruptionBudget, error) {
		return c.PolicyV1().PodDisruptionBudgets(namespace).Get(context.TODO(), name, v1.GetOptions{})
	}

	getWebhook := func(c kubernetes.Interface, name string) (*admissionv1.MutatingWebhookConfiguration, error) {
		return c.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(context.TODO(), name, v1.GetOptions{})
	}

	t.Setenv("AWS_POD_IDENTITY_WEBHOOK_IMAGE", "aws_identity_image")
	t.Setenv("AZURE_POD_IDENTITY_WEBHOOK_IMAGE", "azure_identity_image")

	tests := []struct {
		name             string
		existing         []runtime.Object
		expectErr        bool
		expectedReplicas int32
		expectPDB        bool
		podIdentityType  PodIdentityManifestSource
	}{
		{
			name: "Cluster infrastructure topology is SingleReplica",
			existing: []runtime.Object{
				&configv1.Infrastructure{
					ObjectMeta: v1.ObjectMeta{
						Name: "cluster",
					},
					Status: configv1.InfrastructureStatus{
						InfrastructureTopology: configv1.SingleReplicaTopologyMode,
					},
				}},
			expectErr:        false,
			expectedReplicas: 1,
			expectPDB:        false,
			podIdentityType:  AwsPodIdentity{},
		},
		{
			name: "Cluster infrastructure topology is HighlyAvailable",
			existing: []runtime.Object{
				&configv1.Infrastructure{
					ObjectMeta: v1.ObjectMeta{
						Name: "cluster",
					},
					Status: configv1.InfrastructureStatus{
						InfrastructureTopology: configv1.HighlyAvailableTopologyMode,
					},
				}},
			expectErr:        false,
			expectedReplicas: 2,
			expectPDB:        true,
			podIdentityType:  AwsPodIdentity{},
		},
		{
			name: "Cluster infrastructure object has no infrastructure topology set",
			existing: []runtime.Object{
				&configv1.Infrastructure{
					ObjectMeta: v1.ObjectMeta{
						Name: "cluster",
					},
					Status: configv1.InfrastructureStatus{},
				}},
			expectErr:        false,
			expectedReplicas: 2,
			expectPDB:        true,
			podIdentityType:  AwsPodIdentity{},
		},
		{
			name:            "Cluster infrastructure object doesn't exist",
			expectErr:       true, // gates deployment assertions — reconciliation fails internally
			podIdentityType: AwsPodIdentity{},
		},
		{
			name: "Azure platform",
			existing: []runtime.Object{
				&configv1.Infrastructure{
					ObjectMeta: v1.ObjectMeta{
						Name: "cluster",
					},
					Status: configv1.InfrastructureStatus{
						InfrastructureTopology: configv1.HighlyAvailableTopologyMode,
					},
				}},
			expectErr:        false,
			expectedReplicas: 2,
			expectPDB:        true,
			podIdentityType:  AzurePodIdentity{},
		},
		{
			name: "AWS platform: Cluster infrastructure object has no AWS region set",
			existing: []runtime.Object{
				&configv1.Infrastructure{
					ObjectMeta: v1.ObjectMeta{
						Name: "cluster",
					},
					Status: configv1.InfrastructureStatus{
						PlatformStatus: &configv1.PlatformStatus{
							AWS: &configv1.AWSPlatformStatus{
								Region: "",
							},
						},
					},
				}},
			expectErr:        false,
			expectedReplicas: 2,
			expectPDB:        true,
			podIdentityType:  AwsPodIdentity{},
		},
		{
			name: "AWS platform: Cluster infrastructure object has AWS region",
			existing: []runtime.Object{
				&configv1.Infrastructure{
					ObjectMeta: v1.ObjectMeta{
						Name: "cluster",
					},
					Status: configv1.InfrastructureStatus{
						PlatformStatus: &configv1.PlatformStatus{
							AWS: &configv1.AWSPlatformStatus{
								Region: "us-west-1",
							},
						},
					},
				}},
			expectErr:        false,
			expectedReplicas: 2,
			expectPDB:        true,
			podIdentityType:  AwsPodIdentity{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			logger := log.WithField("controller", "podidentitywebhookcontrollertest")
			fakeClient := fake.NewClientBuilder().WithRuntimeObjects(test.existing...).Build()
			fakeClientset := fakeclientgo.NewSimpleClientset()
			r := &staticResourceReconciler{
				client:          fakeClient,
				clientset:       fakeClientset,
				logger:          logger,
				eventRecorder:   events.NewInMemoryRecorder("", clock.RealClock{}),
				cache:           resourceapply.NewResourceCache(),
				conditions:      []configv1.ClusterOperatorStatusCondition{},
				imagePullSpec:   test.podIdentityType.GetImagePullSpec(),
				podIdentityType: test.podIdentityType,
			}

			res, err := r.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "testName",
					Namespace: "testNamespace",
				},
			})

			// Reconcile returns nil even on error so that controller-runtime
			// honors RequeueAfter instead of applying exponential backoff.
			require.NoError(t, err)

			if test.expectErr {
				assert.True(t, res.RequeueAfter > 0,
					"RequeueAfter should be set when reconciliation fails internally")
			}

			if !test.expectErr {
				// expectErr gates deployment assertions — when true, reconciliation
				// failed internally so no deployment was created to inspect.
				expectedImage := fmt.Sprintf("%s_identity_image", test.podIdentityType.Name())
				assert.Equal(t, r.imagePullSpec, expectedImage)

				podIdentityWebhookDeployment, err := getDeployment(fakeClientset, "pod-identity-webhook", "openshift-cloud-credential-operator")
				assert.Nil(t, err)
				assert.NotNil(t, podIdentityWebhookDeployment, "did not find expected pod-identity-webhook Deployment")

				if test.expectedReplicas != 0 {
					assert.Equal(t, *podIdentityWebhookDeployment.Spec.Replicas, test.expectedReplicas, "found unexpected pod-identity-webhook deployment replicas")
				}

				assert.Equal(t, podIdentityWebhookDeployment.Spec.Template.Spec.Containers[0].Image, expectedImage, "container image matches expected one")

				// Test ApplyDeploymentSubstitutionsInPlace()
				switch test.podIdentityType {
				case AwsPodIdentity{}:
					infra, ok := test.existing[0].(*configv1.Infrastructure)
					if !ok || infra.Status.PlatformStatus == nil || infra.Status.PlatformStatus.AWS == nil {
						// skip
						break
					}

					expectedRegion := infra.Status.PlatformStatus.AWS.Region
					if expectedRegion == "" {
						expectedRegion = "us-east-1"
					}

					matchesRegionFlag := false
					for _, arg := range podIdentityWebhookDeployment.Spec.Template.Spec.Containers[0].Command {
						if strings.Contains(arg, "--aws-default-region") && arg == fmt.Sprintf("--aws-default-region=%s", expectedRegion) {
							matchesRegionFlag = true
							break
						}
					}

					assert.Equal(t, matchesRegionFlag, true, "cmd", podIdentityWebhookDeployment.Spec.Template.Spec.Containers[0].Command)
				}

				podDisruptionBudget, err := getPDB(fakeClientset, "pod-identity-webhook", "openshift-cloud-credential-operator")
				if test.expectPDB {
					assert.Nil(t, err)
					assert.NotEqual(t, podDisruptionBudget.Kind, "", "did not find expected pod-identity-webhook PodDisruptionBudget")
				} else {
					assert.NotNil(t, err)
					assert.Equal(t, podDisruptionBudget.Kind, "", "found unexpected pod-identity-webhook PodDisruptionBudget")
				}

				webhook, err := getWebhook(fakeClientset, "pod-identity-webhook")
				assert.NotNil(t, webhook, "did not find expected pod-identity-webhook webhook config")
				assert.Contains(t, webhook.Webhooks[0].Name, test.podIdentityType.Name())
			}
		})
	}
}

func TestPodIdentityShouldDeploy(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)

	azureCredsSecretName := "azure-credentials"
	tests := []struct {
		name            string
		existing        []runtime.Object
		expectedResult  bool
		expectErr       bool
		podIdentityType PodIdentityManifestSource
	}{{
		name: "Azure secret with credentials exists",
		existing: []runtime.Object{
			&corev1.Secret{
				ObjectMeta: v1.ObjectMeta{
					Name:      azureCredsSecretName,
					Namespace: operatorNamespace,
				},
				Data: map[string][]byte{
					azureTenantIdKey: {},
				},
			}},
		podIdentityType: AzurePodIdentity{},
		expectedResult:  true,
		expectErr:       false,
	},
		{
			name: "Azure secret with credentials without tenant id",
			existing: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Name:      azureCredsSecretName,
						Namespace: operatorNamespace,
					},
					Data: map[string][]byte{},
				}},
			podIdentityType: AzurePodIdentity{},
			expectedResult:  false,
			expectErr:       false,
		},
		{
			name:            "Azure no secret with credentials",
			existing:        []runtime.Object{},
			podIdentityType: AzurePodIdentity{},
			expectedResult:  false,
			expectErr:       false,
		},
		{
			name: "Azure fails to get secret and error is not NotFound",
			existing: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: v1.ObjectMeta{
						Name:      azureCredsSecretName,
						Namespace: operatorNamespace,
					},
					Data: map[string][]byte{},
				}},
			podIdentityType: AzurePodIdentity{},
			expectedResult:  false,
			expectErr:       true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClientset := fakeclientgo.NewSimpleClientset(test.existing...)
			if test.expectErr {
				fakeClientset.PrependReactor("get", "secrets", func(action clientgotesting.Action) (handled bool, ret runtime.Object, err error) {
					return true, &corev1.Secret{}, fmt.Errorf("error getting secret")
				})
			}

			result, err := test.podIdentityType.ShouldBeDeployed(context.TODO(), fakeClientset, operatorNamespace)
			if err != nil && !test.expectErr {
				require.NoError(t, err, "Unexpected error: %v", err)
			}
			if err == nil && test.expectErr {
				t.Errorf("Expected error but got none")
			}
			assert.Equal(t, result, test.expectedResult)
		})
	}
}

func TestReconcileConditions(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)
	t.Setenv("AWS_POD_IDENTITY_WEBHOOK_IMAGE", "aws_identity_image")

	tests := []struct {
		name             string
		existing         []runtime.Object
		deployment       *appsv1.Deployment
		staleConditions  []configv1.ClusterOperatorStatusCondition
		degradedSince    time.Time
		expectErr        bool
		expectConditions func(t *testing.T, conditions []configv1.ClusterOperatorStatusCondition)
	}{
		{
			name:     "error while deployment progressing - Progressing reported, Degraded debounced",
			existing: []runtime.Object{}, // no infra object → ReconcileResources fails
			deployment: &appsv1.Deployment{
				ObjectMeta: v1.ObjectMeta{
					Name:       podIdentityWebhookDeploymentName,
					Namespace:  operatorNamespace,
					Generation: 2,
				},
				Spec:   appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
				Status: appsv1.DeploymentStatus{ObservedGeneration: 1},
			},
			// degradedSince is zero → first failure, grace period not elapsed
			expectErr: false, // Reconcile returns nil; error is logged and requeued
			expectConditions: func(t *testing.T, conditions []configv1.ClusterOperatorStatusCondition) {
				assertConditionStatus(t, conditions, configv1.OperatorProgressing, conditionStatusPtr(configv1.ConditionTrue))
				// Degraded should NOT be reported yet — within grace period
				assertConditionStatus(t, conditions, configv1.OperatorDegraded, nil)
			},
		},
		{
			name:     "error after grace period - reports Degraded",
			existing: []runtime.Object{}, // no infra object → ReconcileResources fails
			deployment: &appsv1.Deployment{
				ObjectMeta: v1.ObjectMeta{
					Name:       podIdentityWebhookDeploymentName,
					Namespace:  operatorNamespace,
					Generation: 2,
				},
				Spec:   appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
				Status: appsv1.DeploymentStatus{ObservedGeneration: 1},
			},
			// Simulate failure that started 10 minutes ago → past grace period
			degradedSince: time.Now().Add(-10 * time.Minute),
			expectErr:     false, // Reconcile returns nil; error is logged and requeued
			expectConditions: func(t *testing.T, conditions []configv1.ClusterOperatorStatusCondition) {
				assertConditionStatus(t, conditions, configv1.OperatorProgressing, conditionStatusPtr(configv1.ConditionTrue))
				assertConditionStatus(t, conditions, configv1.OperatorDegraded, conditionStatusPtr(configv1.ConditionTrue))
			},
		},
		{
			name:     "error while deployment not progressing after grace period - Degraded and Available=False",
			existing: []runtime.Object{}, // no infra object → ReconcileResources fails
			deployment: &appsv1.Deployment{
				ObjectMeta: v1.ObjectMeta{
					Name:       podIdentityWebhookDeploymentName,
					Namespace:  operatorNamespace,
					Generation: 1,
				},
				Spec: appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration: 1,
					AvailableReplicas:  0,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
					},
				},
			},
			degradedSince: time.Now().Add(-10 * time.Minute),
			expectErr:     false, // Reconcile returns nil; error is logged and requeued
			expectConditions: func(t *testing.T, conditions []configv1.ClusterOperatorStatusCondition) {
				assertConditionStatus(t, conditions, configv1.OperatorAvailable, conditionStatusPtr(configv1.ConditionFalse))
				assertConditionStatus(t, conditions, configv1.OperatorDegraded, conditionStatusPtr(configv1.ConditionTrue))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithRuntimeObjects(test.existing...).Build()
			var fakeClientset *fakeclientgo.Clientset
			if test.deployment != nil {
				fakeClientset = fakeclientgo.NewSimpleClientset(test.deployment)
			} else {
				fakeClientset = fakeclientgo.NewSimpleClientset()
			}

			r := &staticResourceReconciler{
				client:          fakeClient,
				clientset:       fakeClientset,
				logger:          log.WithField("controller", "test"),
				eventRecorder:   events.NewInMemoryRecorder("", clock.RealClock{}),
				cache:           resourceapply.NewResourceCache(),
				imagePullSpec:   "aws_identity_image",
				podIdentityType: AwsPodIdentity{},
				conditions:      test.staleConditions,
				degradedSince:   test.degradedSince,
			}

			res, err := r.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "test", Namespace: "test"},
			})

			if test.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				// Internal errors are swallowed; RequeueAfter should be set
				assert.True(t, res.RequeueAfter > 0,
					"RequeueAfter should be set when internal reconciliation error is swallowed")
			}
			test.expectConditions(t, r.conditions)
		})
	}
}

func TestIsDeploymentProgressing(t *testing.T) {
	tests := []struct {
		name           string
		deployment     *appsv1.Deployment
		expectProgress bool
	}{
		{
			name: "generation mismatch - progressing",
			deployment: &appsv1.Deployment{
				ObjectMeta: v1.ObjectMeta{Generation: 2},
				Spec:       appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
				Status:     appsv1.DeploymentStatus{ObservedGeneration: 1},
			},
			expectProgress: true,
		},
		{
			name: "rollout complete - not progressing",
			deployment: &appsv1.Deployment{
				ObjectMeta: v1.ObjectMeta{Generation: 1},
				Spec:       appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration: 1,
					AvailableReplicas:  2,
					UpdatedReplicas:    2,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
					},
				},
			},
			expectProgress: false,
		},
		{
			name: "rollout complete with unavailable replica (node reboot) - not progressing",
			deployment: &appsv1.Deployment{
				ObjectMeta: v1.ObjectMeta{Generation: 1},
				Spec:       appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration:  1,
					AvailableReplicas:   1,
					UnavailableReplicas: 1,
					UpdatedReplicas:     2,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
					},
				},
			},
			expectProgress: false,
		},
		{
			name: "unavailable replicas during rollout - progressing",
			deployment: &appsv1.Deployment{
				ObjectMeta: v1.ObjectMeta{Generation: 1},
				Spec:       appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration:  1,
					AvailableReplicas:   1,
					UnavailableReplicas: 1,
					UpdatedReplicas:     1,
				},
			},
			expectProgress: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			progressing, _ := isDeploymentProgressing(test.deployment)
			assert.Equal(t, test.expectProgress, progressing)
		})
	}

	t.Run("nil Replicas pointer - treats as 1 expected", func(t *testing.T) {
		// When Spec.Replicas is nil, Kubernetes defaults to 1.
		// isDeploymentProgressing should handle this without panicking.
		deployment := &appsv1.Deployment{
			ObjectMeta: v1.ObjectMeta{Generation: 1},
			Spec:       appsv1.DeploymentSpec{Replicas: nil}, // nil = default 1
			Status: appsv1.DeploymentStatus{
				ObservedGeneration: 1,
				AvailableReplicas:  1,
				UpdatedReplicas:    1,
				Conditions: []appsv1.DeploymentCondition{
					{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
				},
			},
		}
		progressing, _ := isDeploymentProgressing(deployment)
		assert.False(t, progressing, "should not be progressing when available replicas match default")
	})

	t.Run("nil Replicas with zero available - progressing", func(t *testing.T) {
		deployment := &appsv1.Deployment{
			ObjectMeta: v1.ObjectMeta{Generation: 1},
			Spec:       appsv1.DeploymentSpec{Replicas: nil},
			Status: appsv1.DeploymentStatus{
				ObservedGeneration:  1,
				AvailableReplicas:   0,
				UnavailableReplicas: 1,
			},
		}
		progressing, _ := isDeploymentProgressing(deployment)
		assert.True(t, progressing, "should be progressing when no replicas available with nil spec")
	})
}

func TestDeploymentConditionsViaReconcile(t *testing.T) {
	// Exercise Reconcile directly instead of restating its condition logic.
	// The fake clientset is seeded with a deployment in the desired state,
	// and an Infrastructure object is provided so ReconcileResources succeeds.
	schemeutils.SetupScheme(scheme.Scheme)
	t.Setenv("AWS_POD_IDENTITY_WEBHOOK_IMAGE", "aws_identity_image")

	infraObj := &configv1.Infrastructure{
		ObjectMeta: v1.ObjectMeta{Name: "cluster"},
		Status: configv1.InfrastructureStatus{
			InfrastructureTopology: configv1.HighlyAvailableTopologyMode,
		},
	}

	tests := []struct {
		name              string
		deployment        *appsv1.Deployment
		expectErr         bool
		expectAvailable   *configv1.ConditionStatus
		expectProgressing *configv1.ConditionStatus
		expectDegraded    *configv1.ConditionStatus
	}{
		{
			// During a normal rollout, old replicas are still serving while new
			// ones roll out. The deployment is progressing but available.
			name: "success - deployment progressing with available replicas reports Progressing=True",
			deployment: &appsv1.Deployment{
				ObjectMeta: v1.ObjectMeta{
					Name:       podIdentityWebhookDeploymentName,
					Namespace:  operatorNamespace,
					Generation: 2,
				},
				Spec: appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration: 1,
					AvailableReplicas:  1, // old replica still serving
				},
			},
			expectProgressing: conditionStatusPtr(configv1.ConditionTrue),
			// Available is not set by the handler (replicas > 0), defaults to True
		},
		{
			name: "success - deployment not progressing, zero replicas reports Available=False",
			deployment: &appsv1.Deployment{
				ObjectMeta: v1.ObjectMeta{
					Name:       podIdentityWebhookDeploymentName,
					Namespace:  operatorNamespace,
					Generation: 1,
				},
				Spec: appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration: 1,
					AvailableReplicas:  0,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
					},
				},
			},
			expectAvailable: conditionStatusPtr(configv1.ConditionFalse),
		},
		{
			// Available and Progressing are independent. Zero replicas means
			// Available=False regardless of progressing state.
			name: "progressing deployment with zero replicas - both Progressing and Available=False emitted",
			deployment: &appsv1.Deployment{
				ObjectMeta: v1.ObjectMeta{
					Name:       podIdentityWebhookDeploymentName,
					Namespace:  operatorNamespace,
					Generation: 2,
				},
				Spec: appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration:  1,
					AvailableReplicas:   0,
					UnavailableReplicas: 2,
				},
			},
			expectProgressing: conditionStatusPtr(configv1.ConditionTrue),
			expectAvailable:   conditionStatusPtr(configv1.ConditionFalse),
		},
		{
			name: "success - deployment healthy reports no abnormal conditions",
			deployment: &appsv1.Deployment{
				ObjectMeta: v1.ObjectMeta{
					Name:       podIdentityWebhookDeploymentName,
					Namespace:  operatorNamespace,
					Generation: 1,
				},
				Spec: appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration: 1,
					AvailableReplicas:  2,
					UpdatedReplicas:    2,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().WithRuntimeObjects(infraObj).Build()
			fakeClientset := fakeclientgo.NewSimpleClientset(test.deployment)

			r := &staticResourceReconciler{
				client:          fakeClient,
				clientset:       fakeClientset,
				logger:          log.WithField("controller", "test"),
				eventRecorder:   events.NewInMemoryRecorder("", clock.RealClock{}),
				cache:           resourceapply.NewResourceCache(),
				imagePullSpec:   "aws_identity_image",
				podIdentityType: AwsPodIdentity{},
				conditions:      []configv1.ClusterOperatorStatusCondition{},
			}

			res, err := r.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "test", Namespace: "test"},
			})

			if test.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Successful reconciles have empty Result; failed ones set RequeueAfter
			if !test.expectErr {
				assert.Zero(t, res.RequeueAfter,
					"RequeueAfter should not be set on successful reconcile")
			}

			assertConditionStatus(t, r.conditions, configv1.OperatorAvailable, test.expectAvailable)
			assertConditionStatus(t, r.conditions, configv1.OperatorProgressing, test.expectProgressing)
			assertConditionStatus(t, r.conditions, configv1.OperatorDegraded, test.expectDegraded)
		})
	}
}

func TestDeploymentFetchedFromAPI(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)
	t.Setenv("AWS_POD_IDENTITY_WEBHOOK_IMAGE", "aws_identity_image")

	t.Run("progressing deployment fetched from API", func(t *testing.T) {
		// Deployment in the API: generation=2, observedGeneration=1 → progressing
		deployment := &appsv1.Deployment{
			ObjectMeta: v1.ObjectMeta{
				Name:       podIdentityWebhookDeploymentName,
				Namespace:  operatorNamespace,
				Generation: 2,
			},
			Spec:   appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
			Status: appsv1.DeploymentStatus{ObservedGeneration: 1},
		}

		// No infra object → ReconcileResources will fail
		fakeClient := fake.NewClientBuilder().Build()
		fakeClientset := fakeclientgo.NewSimpleClientset(deployment)

		r := &staticResourceReconciler{
			client:          fakeClient,
			clientset:       fakeClientset,
			logger:          log.WithField("controller", "test"),
			eventRecorder:   events.NewInMemoryRecorder("", clock.RealClock{}),
			cache:           resourceapply.NewResourceCache(),
			imagePullSpec:   "aws_identity_image",
			podIdentityType: AwsPodIdentity{},
			conditions:      []configv1.ClusterOperatorStatusCondition{},
		}

		res, err := r.Reconcile(context.TODO(), reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "test", Namespace: "test"},
		})
		assert.NoError(t, err) // Reconcile returns nil; error is logged and requeued
		assert.True(t, res.RequeueAfter > 0,
			"RequeueAfter should be set when internal reconciliation error is swallowed")

		// Conditions should reflect the progressing deployment fetched from the API
		assertConditionStatus(t, r.conditions, configv1.OperatorProgressing, conditionStatusPtr(configv1.ConditionTrue))
	})

	t.Run("deployment not found - reports Available=False", func(t *testing.T) {
		// No deployment in the fake clientset → Get returns 404
		fakeClient := fake.NewClientBuilder().Build()
		fakeClientset := fakeclientgo.NewSimpleClientset()

		r := &staticResourceReconciler{
			client:          fakeClient,
			clientset:       fakeClientset,
			logger:          log.WithField("controller", "test"),
			eventRecorder:   events.NewInMemoryRecorder("", clock.RealClock{}),
			cache:           resourceapply.NewResourceCache(),
			imagePullSpec:   "aws_identity_image",
			podIdentityType: AwsPodIdentity{},
			conditions:      []configv1.ClusterOperatorStatusCondition{},
		}

		res, err := r.Reconcile(context.TODO(), reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "test", Namespace: "test"},
		})
		assert.NoError(t, err) // Reconcile returns nil; error is logged and requeued
		assert.True(t, res.RequeueAfter > 0,
			"RequeueAfter should be set when internal reconciliation error is swallowed")

		// Deployment does not exist — webhook is non-functional
		assertConditionStatus(t, r.conditions, configv1.OperatorProgressing, nil)
		assertConditionStatus(t, r.conditions, configv1.OperatorAvailable, conditionStatusPtr(configv1.ConditionFalse))
	})
}

func TestStaleConditionsFullyReplaced(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)
	t.Setenv("AWS_POD_IDENTITY_WEBHOOK_IMAGE", "aws_identity_image")

	// Progressing deployment seeded in fake clientset
	deployment := &appsv1.Deployment{
		ObjectMeta: v1.ObjectMeta{
			Name:       podIdentityWebhookDeploymentName,
			Namespace:  operatorNamespace,
			Generation: 2,
		},
		Spec:   appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 1},
	}

	// No infra object → ReconcileResources will fail
	fakeClient := fake.NewClientBuilder().Build()
	fakeClientset := fakeclientgo.NewSimpleClientset(deployment)

	// Pre-populate with a stale Upgradeable=False condition
	staleConditions := []configv1.ClusterOperatorStatusCondition{
		{Type: configv1.OperatorUpgradeable, Status: configv1.ConditionFalse, Reason: "StaleReason", Message: "stale"},
	}

	r := &staticResourceReconciler{
		client:          fakeClient,
		clientset:       fakeClientset,
		logger:          log.WithField("controller", "test"),
		eventRecorder:   events.NewInMemoryRecorder("", clock.RealClock{}),
		cache:           resourceapply.NewResourceCache(),
		imagePullSpec:   "aws_identity_image",
		podIdentityType: AwsPodIdentity{},
		conditions:      staleConditions,
	}

	_, err := r.Reconcile(context.TODO(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test", Namespace: "test"},
	})
	assert.NoError(t, err) // Reconcile returns nil; error is logged and requeued

	// The stale Upgradeable=False condition should be gone
	assertConditionStatus(t, r.conditions, configv1.OperatorUpgradeable, nil)
	// Deployment-derived conditions should be present
	assertConditionStatus(t, r.conditions, configv1.OperatorProgressing, conditionStatusPtr(configv1.ConditionTrue))
	// Degraded is debounced — not reported on first failure (within grace period)
	assertConditionStatus(t, r.conditions, configv1.OperatorDegraded, nil)
}

func TestDegradedSinceClearedOnSuccess(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)
	t.Setenv("AWS_POD_IDENTITY_WEBHOOK_IMAGE", "aws_identity_image")

	infraObj := &configv1.Infrastructure{
		ObjectMeta: v1.ObjectMeta{Name: "cluster"},
		Status: configv1.InfrastructureStatus{
			InfrastructureTopology: configv1.HighlyAvailableTopologyMode,
		},
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: v1.ObjectMeta{
			Name:       podIdentityWebhookDeploymentName,
			Namespace:  operatorNamespace,
			Generation: 1,
		},
		Spec: appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration: 1,
			AvailableReplicas:  2,
			UpdatedReplicas:    2,
			Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithRuntimeObjects(infraObj).Build()
	fakeClientset := fakeclientgo.NewSimpleClientset(deployment)

	r := &staticResourceReconciler{
		client:          fakeClient,
		clientset:       fakeClientset,
		logger:          log.WithField("controller", "test"),
		eventRecorder:   events.NewInMemoryRecorder("", clock.RealClock{}),
		cache:           resourceapply.NewResourceCache(),
		imagePullSpec:   "aws_identity_image",
		podIdentityType: AwsPodIdentity{},
		conditions:      []configv1.ClusterOperatorStatusCondition{},
		degradedSince:   time.Now().Add(-10 * time.Minute), // was failing for 10 minutes
	}

	_, err := r.Reconcile(context.TODO(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test", Namespace: "test"},
	})
	assert.NoError(t, err)

	// degradedSince should be cleared after successful reconciliation
	assert.True(t, r.degradedSince.IsZero(), "degradedSince should be reset to zero on success")
	// No Degraded condition should be set
	assertConditionStatus(t, r.conditions, configv1.OperatorDegraded, nil)
}

func TestPartialAvailabilityKeepsAvailableTrue(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)
	t.Setenv("AWS_POD_IDENTITY_WEBHOOK_IMAGE", "aws_identity_image")

	// Deployment with 1 of 2 replicas available, not progressing (NewReplicaSetAvailable)
	deployment := &appsv1.Deployment{
		ObjectMeta: v1.ObjectMeta{
			Name:       podIdentityWebhookDeploymentName,
			Namespace:  operatorNamespace,
			Generation: 1,
		},
		Spec: appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration: 1,
			AvailableReplicas:  1,
			UpdatedReplicas:    2,
			Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
			},
		},
	}

	infraObj := &configv1.Infrastructure{
		ObjectMeta: v1.ObjectMeta{Name: "cluster"},
		Status: configv1.InfrastructureStatus{
			InfrastructureTopology: configv1.HighlyAvailableTopologyMode,
		},
	}

	fakeClient := fake.NewClientBuilder().WithRuntimeObjects(infraObj).Build()
	fakeClientset := fakeclientgo.NewSimpleClientset(deployment)

	r := &staticResourceReconciler{
		client:          fakeClient,
		clientset:       fakeClientset,
		logger:          log.WithField("controller", "test"),
		eventRecorder:   events.NewInMemoryRecorder("", clock.RealClock{}),
		cache:           resourceapply.NewResourceCache(),
		imagePullSpec:   "aws_identity_image",
		podIdentityType: AwsPodIdentity{},
		conditions:      []configv1.ClusterOperatorStatusCondition{},
	}

	_, err := r.Reconcile(context.TODO(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test", Namespace: "test"},
	})
	assert.NoError(t, err)

	// With AvailableReplicas > 0, Available=False should NOT be set
	assertConditionStatus(t, r.conditions, configv1.OperatorAvailable, nil)
}

func TestDegradedSinceSeededOnPodRestart(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)
	t.Setenv("AWS_POD_IDENTITY_WEBHOOK_IMAGE", "aws_identity_image")

	// When the CCO pod restarts, a new staticResourceReconciler is created with
	// degradedSince at zero. seedDegradedSince reads the published ClusterOperator
	// Degraded condition to recover the timestamp, so the grace period is not
	// re-granted for a persistent failure.

	// Deployment: healthy (so deploymentConditions reports nothing special)
	deployment := &appsv1.Deployment{
		ObjectMeta: v1.ObjectMeta{
			Name:       podIdentityWebhookDeploymentName,
			Namespace:  operatorNamespace,
			Generation: 1,
		},
		Spec: appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration: 1,
			AvailableReplicas:  2,
			UpdatedReplicas:    2,
			Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
			},
		},
	}

	// ClusterOperator with Degraded=True, transition time 10 minutes ago
	// (simulates state published before the restart)
	tenMinutesAgo := v1.Time{Time: time.Now().Add(-10 * time.Minute)}
	co := &configv1.ClusterOperator{
		ObjectMeta: v1.ObjectMeta{
			Name: "cloud-credential",
		},
		Status: configv1.ClusterOperatorStatus{
			Conditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:               configv1.OperatorDegraded,
					Status:             configv1.ConditionTrue,
					Reason:             "StaticResourceReconcileFailed",
					LastTransitionTime: tenMinutesAgo,
				},
			},
		},
	}

	// No infra object → ReconcileResources will fail, simulating a persistent error
	fakeClient := fake.NewClientBuilder().
		WithStatusSubresource(co).
		WithRuntimeObjects(co).Build()
	fakeClientset := fakeclientgo.NewSimpleClientset(deployment)

	// Simulate "before restart": reconciler has been failing for 10 minutes
	r1 := &staticResourceReconciler{
		client:          fakeClient,
		clientset:       fakeClientset,
		logger:          log.WithField("controller", "test"),
		eventRecorder:   events.NewInMemoryRecorder("", clock.RealClock{}),
		cache:           resourceapply.NewResourceCache(),
		imagePullSpec:   "aws_identity_image",
		podIdentityType: AwsPodIdentity{},
		conditions:      []configv1.ClusterOperatorStatusCondition{},
		degradedSince:   time.Now().Add(-10 * time.Minute),
	}

	_, err := r1.Reconcile(context.TODO(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test", Namespace: "test"},
	})
	assert.NoError(t, err)

	// Before "restart": Degraded should be reported (10 min > 5 min grace)
	assertConditionStatus(t, r1.conditions, configv1.OperatorDegraded, conditionStatusPtr(configv1.ConditionTrue))

	// Simulate "after restart": new reconciler with zero degradedSince.
	// seedDegradedSince should read the ClusterOperator's Degraded=True condition
	// and recover the transition time.
	r2 := &staticResourceReconciler{
		client:          fakeClient,
		clientset:       fakeClientset,
		logger:          log.WithField("controller", "test"),
		eventRecorder:   events.NewInMemoryRecorder("", clock.RealClock{}),
		cache:           resourceapply.NewResourceCache(),
		imagePullSpec:   "aws_identity_image",
		podIdentityType: AwsPodIdentity{},
		conditions:      []configv1.ClusterOperatorStatusCondition{},
		// degradedSince is zero — simulates fresh start after pod restart
	}

	_, err = r2.Reconcile(context.TODO(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "test", Namespace: "test"},
	})
	assert.NoError(t, err)

	// After "restart": seedDegradedSince recovered the Degraded transition time
	// from the ClusterOperator, so the grace period is already elapsed (10 min > 5 min).
	// Degraded should be reported immediately.
	assertConditionStatus(t, r2.conditions, configv1.OperatorDegraded, conditionStatusPtr(configv1.ConditionTrue))
	assert.False(t, r2.degradedSince.IsZero(),
		"degradedSince should be seeded from ClusterOperator")
	assert.True(t, r2.degradedSince.Before(time.Now().Add(-9*time.Minute)),
		"degradedSince should be seeded from the ClusterOperator's Degraded transition time, not time.Now()")
}

func TestSeedDegradedSinceFallbacks(t *testing.T) {
	schemeutils.SetupScheme(scheme.Scheme)
	t.Setenv("AWS_POD_IDENTITY_WEBHOOK_IMAGE", "aws_identity_image")

	deployment := &appsv1.Deployment{
		ObjectMeta: v1.ObjectMeta{
			Name:       podIdentityWebhookDeploymentName,
			Namespace:  operatorNamespace,
			Generation: 1,
		},
		Spec: appsv1.DeploymentSpec{Replicas: int32Ptr(2)},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration: 1,
			AvailableReplicas:  2,
			UpdatedReplicas:    2,
			Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
			},
		},
	}

	t.Run("ClusterOperator Degraded=False - grace period starts fresh", func(t *testing.T) {
		// ClusterOperator exists but Degraded is False — seedDegradedSince
		// should fall back to time.Now(), starting the grace period fresh.
		co := &configv1.ClusterOperator{
			ObjectMeta: v1.ObjectMeta{Name: "cloud-credential"},
			Status: configv1.ClusterOperatorStatus{
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{
						Type:   configv1.OperatorDegraded,
						Status: configv1.ConditionFalse,
						Reason: "AsExpected",
					},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(co).
			WithRuntimeObjects(co).Build()
		fakeClientset := fakeclientgo.NewSimpleClientset(deployment)

		r := &staticResourceReconciler{
			client:          fakeClient,
			clientset:       fakeClientset,
			logger:          log.WithField("controller", "test"),
			eventRecorder:   events.NewInMemoryRecorder("", clock.RealClock{}),
			cache:           resourceapply.NewResourceCache(),
			imagePullSpec:   "aws_identity_image",
			podIdentityType: AwsPodIdentity{},
			conditions:      []configv1.ClusterOperatorStatusCondition{},
		}

		_, err := r.Reconcile(context.TODO(), reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "test", Namespace: "test"},
		})
		assert.NoError(t, err)

		// Grace period should start fresh — Degraded NOT reported
		assertConditionStatus(t, r.conditions, configv1.OperatorDegraded, nil)
		assert.False(t, r.degradedSince.IsZero(),
			"degradedSince should be set")
		assert.True(t, time.Since(r.degradedSince) < 5*time.Second,
			"degradedSince should be recent (from time.Now()), not from a past condition")
	})

	t.Run("ClusterOperator Degraded suppressed during upgrade - grace period skipped", func(t *testing.T) {
		// ClusterOperator has Degraded=False with Reason=UpgradeInProgress — this
		// means degraded was suppressed during an upgrade. On pod restart,
		// seedDegradedSince should recognize this and skip the grace period.
		co := &configv1.ClusterOperator{
			ObjectMeta: v1.ObjectMeta{Name: "cloud-credential"},
			Status: configv1.ClusterOperatorStatus{
				Conditions: []configv1.ClusterOperatorStatusCondition{
					{
						Type:   configv1.OperatorDegraded,
						Status: configv1.ConditionFalse,
						Reason: "UpgradeInProgress",
					},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithStatusSubresource(co).
			WithRuntimeObjects(co).Build()
		fakeClientset := fakeclientgo.NewSimpleClientset(deployment)

		r := &staticResourceReconciler{
			client:          fakeClient,
			clientset:       fakeClientset,
			logger:          log.WithField("controller", "test"),
			eventRecorder:   events.NewInMemoryRecorder("", clock.RealClock{}),
			cache:           resourceapply.NewResourceCache(),
			imagePullSpec:   "aws_identity_image",
			podIdentityType: AwsPodIdentity{},
			conditions:      []configv1.ClusterOperatorStatusCondition{},
		}

		_, err := r.Reconcile(context.TODO(), reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "test", Namespace: "test"},
		})
		assert.NoError(t, err)

		// Grace period should be skipped — Degraded IS reported immediately
		assertConditionStatus(t, r.conditions, configv1.OperatorDegraded, conditionStatusPtr(configv1.ConditionTrue))
		assert.False(t, r.degradedSince.IsZero(),
			"degradedSince should be set")
		assert.True(t, time.Since(r.degradedSince) >= degradedGracePeriod,
			"degradedSince should be at least gracePeriod in the past to skip the grace window")
	})

	t.Run("ClusterOperator not found - grace period starts fresh", func(t *testing.T) {
		// No ClusterOperator at all — seedDegradedSince should fall back to
		// time.Now(), starting the grace period fresh.
		fakeClient := fake.NewClientBuilder().Build()
		fakeClientset := fakeclientgo.NewSimpleClientset(deployment)

		r := &staticResourceReconciler{
			client:          fakeClient,
			clientset:       fakeClientset,
			logger:          log.WithField("controller", "test"),
			eventRecorder:   events.NewInMemoryRecorder("", clock.RealClock{}),
			cache:           resourceapply.NewResourceCache(),
			imagePullSpec:   "aws_identity_image",
			podIdentityType: AwsPodIdentity{},
			conditions:      []configv1.ClusterOperatorStatusCondition{},
		}

		_, err := r.Reconcile(context.TODO(), reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "test", Namespace: "test"},
		})
		assert.NoError(t, err)

		// Grace period should start fresh — Degraded NOT reported
		assertConditionStatus(t, r.conditions, configv1.OperatorDegraded, nil)
		assert.False(t, r.degradedSince.IsZero(),
			"degradedSince should be set")
		assert.True(t, time.Since(r.degradedSince) < 5*time.Second,
			"degradedSince should be recent (from time.Now()), not from a past condition")
	})
}

func assertConditionStatus(t *testing.T, conditions []configv1.ClusterOperatorStatusCondition, condType configv1.ClusterStatusConditionType, expected *configv1.ConditionStatus) {
	t.Helper()
	var found *configv1.ClusterOperatorStatusCondition
	for i := range conditions {
		if conditions[i].Type == condType {
			found = &conditions[i]
			break
		}
	}
	if expected == nil {
		assert.Nil(t, found, "expected no %s condition but found one", condType)
	} else {
		if assert.NotNil(t, found, "expected %s condition but not found", condType) {
			assert.Equal(t, *expected, found.Status, "unexpected %s status", condType)
		}
	}
}

func int32Ptr(i int32) *int32 {
	return &i
}

func conditionStatusPtr(s configv1.ConditionStatus) *configv1.ConditionStatus {
	return &s
}
