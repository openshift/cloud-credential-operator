/*
Copyright 2023 The OpenShift Authors.

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

package credentialsrequest

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	configv1 "github.com/openshift/api/config/v1"
	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgofake "k8s.io/client-go/kubernetes/fake"
	clientgotesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestReconcileSecretMissingLabel_Reconcile(t *testing.T) {
	// we unconditionally send the SSA request, since it's easy and trivial to make the logic correct.
	// the server determines if a mutation needs to occur. so, we expect the patch to be sent in every case
	tests := []struct {
		name      string
		existing  []runtime.Object
		expectErr bool
		expected  []*clientgotesting.PatchActionImpl
	}{
		{
			name: "already labeled, nothing to do",
			existing: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testSecretName,
						Namespace: testSecretNamespace,
						Annotations: map[string]string{
							minterv1.AnnotationCredentialsRequest: "whatever",
						},
						Labels: map[string]string{
							minterv1.LabelCredentialsRequest: minterv1.LabelCredentialsRequestValue,
						},
					},
				},
			},
			expectErr: false,
			expected: []*clientgotesting.PatchActionImpl{{
				PatchType:  types.ApplyPatchType,
				ActionImpl: clientgotesting.ActionImpl{Namespace: "myproject", Verb: "patch", Resource: corev1.SchemeGroupVersion.WithResource("secrets")},
				Name:       "test-secret",
				Patch:      []uint8(`{"kind":"Secret","apiVersion":"v1","metadata":{"name":"test-secret","namespace":"myproject","labels":{"cloudcredential.openshift.io/credentials-request":"true"}}}`),
			}},
		},
		{
			name: "no label, but no annotation, so nothing to do",
			existing: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testSecretName,
						Namespace: testSecretNamespace,
					},
				},
			},
			expectErr: false,
			expected: []*clientgotesting.PatchActionImpl{{
				PatchType:  types.ApplyPatchType,
				ActionImpl: clientgotesting.ActionImpl{Namespace: "myproject", Verb: "patch", Resource: corev1.SchemeGroupVersion.WithResource("secrets")},
				Name:       "test-secret",
				Patch:      []uint8(`{"kind":"Secret","apiVersion":"v1","metadata":{"name":"test-secret","namespace":"myproject","labels":{"cloudcredential.openshift.io/credentials-request":"true"}}}`),
			}},
		},
		{
			name: "annotation but missing label, should be labeled",
			existing: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testSecretName,
						Namespace: testSecretNamespace,
						Annotations: map[string]string{
							minterv1.AnnotationCredentialsRequest: "whatever",
						},
					},
				},
			},
			expectErr: false,
			expected: []*clientgotesting.PatchActionImpl{{
				PatchType:  types.ApplyPatchType,
				ActionImpl: clientgotesting.ActionImpl{Namespace: "myproject", Verb: "patch", Resource: corev1.SchemeGroupVersion.WithResource("secrets")},
				Name:       "test-secret",
				Patch:      []uint8(`{"kind":"Secret","apiVersion":"v1","metadata":{"name":"test-secret","namespace":"myproject","labels":{"cloudcredential.openshift.io/credentials-request":"true"}}}`),
			}},
		},
		{
			name: "annotation but bad label value, should be labeled",
			existing: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testSecretName,
						Namespace: testSecretNamespace,
						Annotations: map[string]string{
							minterv1.AnnotationCredentialsRequest: "whatever",
						},
						Labels: map[string]string{
							minterv1.LabelCredentialsRequest: "wrong",
						},
					},
				},
			},
			expectErr: false,
			expected: []*clientgotesting.PatchActionImpl{{
				PatchType:  types.ApplyPatchType,
				ActionImpl: clientgotesting.ActionImpl{Namespace: "myproject", Verb: "patch", Resource: corev1.SchemeGroupVersion.WithResource("secrets")},
				Name:       "test-secret",
				Patch:      []uint8(`{"kind":"Secret","apiVersion":"v1","metadata":{"name":"test-secret","namespace":"myproject","labels":{"cloudcredential.openshift.io/credentials-request":"true"}}}`),
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithRuntimeObjects(test.existing...).Build()

			var actions []*clientgotesting.PatchActionImpl
			fakeMutatingClient := clientgofake.NewSimpleClientset(test.existing...)
			fakeMutatingClient.PrependReactor("*", "secrets", func(action clientgotesting.Action) (handled bool, ret runtime.Object, err error) {
				impl, ok := action.(clientgotesting.PatchActionImpl)
				if !ok {
					return false, nil, nil
				}
				actions = append(actions, &impl)
				return false, nil, nil
			})

			rcr := ReconcileSecretMissingLabel{
				cachedClient:   fakeClient,
				mutatingClient: fakeMutatingClient.CoreV1(),
			}

			_, err := rcr.Reconcile(context.TODO(), reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      testSecretName,
					Namespace: testSecretNamespace,
				},
			})

			if err != nil && !test.expectErr {
				require.NoError(t, err, "Unexpected error: %v", err)
			}
			if err == nil && test.expectErr {
				t.Errorf("Expected error but got none")
			}

			if diff := cmp.Diff(actions, test.expected); diff != "" {
				t.Errorf("incorrect actions: %v", diff)
			}
		})
	}
}

func TestReconcileSecretMissingLabel_GetConditions(t *testing.T) {
	tests := []struct {
		name      string
		existing  []runtime.Object
		expectErr bool
		// Expected conditions on the credentials cluster operator:
		expectedCOConditions []configv1.ClusterOperatorStatusCondition
	}{
		{
			name:                 "no secrets, no condition",
			existing:             []runtime.Object{},
			expectErr:            false,
			expectedCOConditions: []configv1.ClusterOperatorStatusCondition{},
		},
		{
			name: "no secrets missing labels, no condition",
			existing: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testSecretName,
						Namespace: testSecretNamespace,
						Annotations: map[string]string{
							minterv1.AnnotationCredentialsRequest: "whatever",
						},
						Labels: map[string]string{
							minterv1.LabelCredentialsRequest: minterv1.LabelCredentialsRequestValue,
						},
					},
				},
			},
			expectErr:            false,
			expectedCOConditions: []configv1.ClusterOperatorStatusCondition{},
		},
		{
			name: "secrets missing labels, progressing condition",
			existing: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testSecretName,
						Namespace: testSecretNamespace,
						Annotations: map[string]string{
							minterv1.AnnotationCredentialsRequest: "whatever",
						},
					},
				},
			},
			expectErr: false,
			expectedCOConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorProgressing,
					Status:  configv1.ConditionTrue,
					Reason:  "LabelsMissing",
					Message: "1 secrets created for CredentialsRequests have not been labelled",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithRuntimeObjects(test.existing...).Build()

			rcr := ReconcileSecretMissingLabel{
				cachedClient:   fakeClient,
				mutatingClient: nil,
			}

			conditions, err := rcr.GetConditions(logrus.StandardLogger())

			if err != nil && !test.expectErr {
				require.NoError(t, err, "Unexpected error: %v", err)
			}
			if err == nil && test.expectErr {
				t.Errorf("Expected error but got none")
			}

			if diff := cmp.Diff(conditions, test.expectedCOConditions); diff != "" {
				t.Errorf("incorrect conditions: %v", diff)
			}
		})
	}
}
