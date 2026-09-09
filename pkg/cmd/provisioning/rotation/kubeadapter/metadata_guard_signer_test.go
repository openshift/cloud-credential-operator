package kubeadapter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/rotation"
)

func TestStrictSecretMetadataClientRequestsOnlyPartialObjectMetadata(t *testing.T) {
	wantUID := types.UID("8bd50c04-9718-4ef0-8af5-9181e7db48b2")
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/namespaces/openshift-kube-apiserver-operator/secrets/next-bound-service-account-signing-key" {
			t.Errorf("request path = %q", request.URL.Path)
		}
		if got := request.Header.Get("Accept"); got != partialObjectMetadataAccept {
			t.Errorf("Accept header = %q, want %q", got, partialObjectMetadataAccept)
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(&metav1.PartialObjectMetadata{
			TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"},
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       kubeAPIServerOperatorNamespace,
				Name:            nextSignerSecretName,
				UID:             wantUID,
				ResourceVersion: "17",
			},
		})
	}))
	defer server.Close()

	client := strictMetadataClientForServer(t, server)
	metadata, err := client.Get(context.Background(), kubeAPIServerOperatorNamespace, nextSignerSecretName)
	if err != nil {
		t.Fatalf("Get() returned unexpected error: %v", err)
	}
	if metadata.UID != wantUID || metadata.ResourceVersion != "17" {
		t.Fatalf("Get() = %#v", metadata)
	}
}

func TestStrictSecretMetadataClientRejectsFullSecretFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(&corev1.Secret{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
			ObjectMeta: metav1.ObjectMeta{Namespace: kubeAPIServerOperatorNamespace, Name: nextSignerSecretName},
			Data:       map[string][]byte{"private-key": []byte("must-not-be-accepted")},
		})
	}))
	defer server.Close()

	_, err := strictMetadataClientForServer(t, server).Get(context.Background(), kubeAPIServerOperatorNamespace, nextSignerSecretName)
	if err == nil || (!strings.Contains(err.Error(), "unknown field") && !strings.Contains(err.Error(), "instead of")) {
		t.Fatalf("Get() error = %v, want strict full-object rejection", err)
	}
}

func strictMetadataClientForServer(t *testing.T, server *httptest.Server) *strictSecretMetadataClient {
	t.Helper()
	clientset, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatalf("build Kubernetes client: %v", err)
	}
	return &strictSecretMetadataClient{restClient: clientset.CoreV1().RESTClient()}
}

func TestRotationGuardPreservesCompletionHistoryAcrossLaterOwnership(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	adapter := &Adapter{kube: client}
	first := rotation.RotationGuardReference{ScopeID: strings.Repeat("a", 64), OperationID: strings.Repeat("b", 64)}
	second := rotation.RotationGuardReference{ScopeID: first.ScopeID, OperationID: strings.Repeat("c", 64)}

	if outcome, err := adapter.AcquireRotationGuard(ctx, first); err != nil || outcome != rotation.EffectSubmitted {
		t.Fatalf("AcquireRotationGuard(first) = %q, %v", outcome, err)
	}
	if observation, err := adapter.ObserveRotationGuard(ctx, first); err != nil || observation.Status != rotation.RotationGuardHeld {
		t.Fatalf("ObserveRotationGuard(first held) = %#v, %v", observation, err)
	}
	if outcome, err := adapter.ReleaseRotationGuard(ctx, first); err != nil || outcome != rotation.EffectSubmitted {
		t.Fatalf("ReleaseRotationGuard(first) = %q, %v", outcome, err)
	}
	if outcome, err := adapter.AcquireRotationGuard(ctx, second); err != nil || outcome != rotation.EffectSubmitted {
		t.Fatalf("AcquireRotationGuard(second) = %q, %v", outcome, err)
	}
	firstObservation, err := adapter.ObserveRotationGuard(ctx, first)
	if err != nil || firstObservation.Status != rotation.RotationGuardCompleted {
		t.Fatalf("ObserveRotationGuard(first completed) = %#v, %v", firstObservation, err)
	}
	secondObservation, err := adapter.ObserveRotationGuard(ctx, second)
	if err != nil || secondObservation.Status != rotation.RotationGuardHeld {
		t.Fatalf("ObserveRotationGuard(second held) = %#v, %v", secondObservation, err)
	}
}

func TestAcquireRotationGuardUsesResourceVersionCAS(t *testing.T) {
	ctx := context.Background()
	guard := rotation.RotationGuardReference{ScopeID: strings.Repeat("a", 64), OperationID: strings.Repeat("b", 64)}
	configMap := newGuardConfigMap(guardState{SchemaVersion: guardSchemaVersion, ScopeID: guard.ScopeID})
	configMap.ResourceVersion = "17"
	client := fake.NewSimpleClientset(configMap)
	var submittedResourceVersion string
	client.Fake.PrependReactor("update", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
		submitted := action.(k8stesting.UpdateAction).GetObject().(*corev1.ConfigMap)
		submittedResourceVersion = submitted.ResourceVersion
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, guardConfigMapName, errors.New("concurrent owner"))
	})
	adapter := &Adapter{kube: client}

	outcome, err := adapter.AcquireRotationGuard(ctx, guard)
	if outcome != rotation.EffectNotApplied || !apierrors.IsConflict(err) {
		t.Fatalf("AcquireRotationGuard() = %q, %v; want definitive conflict", outcome, err)
	}
	if submittedResourceVersion != "17" {
		t.Fatalf("submitted resourceVersion = %q, want 17", submittedResourceVersion)
	}
	observed, err := adapter.ObserveRotationGuard(ctx, guard)
	if err != nil || observed.Status != rotation.RotationGuardNotFound {
		t.Fatalf("guard after rejected CAS = %#v, %v", observed, err)
	}
}

func TestRequestReplacementUsesUIDAndResourceVersionPreconditions(t *testing.T) {
	guard := rotation.RotationGuardReference{ScopeID: strings.Repeat("a", 64), OperationID: strings.Repeat("b", 64)}
	client := fake.NewSimpleClientset(
		newGuardConfigMap(guardState{SchemaVersion: guardSchemaVersion, ScopeID: guard.ScopeID, ActiveOperationID: guard.OperationID}),
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: kubeAPIServerOperatorNamespace, Name: nextSignerSecretName}},
	)
	var deleteOptions metav1.DeleteOptions
	client.Fake.PrependReactor("delete", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		deleteOptions = action.(k8stesting.DeleteAction).GetDeleteOptions()
		return false, nil, nil
	})
	adapter := &Adapter{kube: client}
	reference := rotation.SignerObjectReference{UID: "old-signer-uid", ResourceVersion: "31"}

	outcome, err := adapter.RequestReplacement(context.Background(), guard, reference)
	if err != nil || outcome != rotation.EffectSubmitted {
		t.Fatalf("RequestReplacement() = %q, %v", outcome, err)
	}
	if deleteOptions.Preconditions == nil || deleteOptions.Preconditions.UID == nil || deleteOptions.Preconditions.ResourceVersion == nil {
		t.Fatalf("delete preconditions = %#v", deleteOptions.Preconditions)
	}
	if string(*deleteOptions.Preconditions.UID) != reference.UID || *deleteOptions.Preconditions.ResourceVersion != reference.ResourceVersion {
		t.Fatalf("delete preconditions = %#v, want UID %q and RV %q", deleteOptions.Preconditions, reference.UID, reference.ResourceVersion)
	}
}

func TestRequestReplacementClassifiesDefinitiveAndAmbiguousFailures(t *testing.T) {
	guard := rotation.RotationGuardReference{ScopeID: strings.Repeat("a", 64), OperationID: strings.Repeat("b", 64)}
	reference := rotation.SignerObjectReference{UID: "old-signer-uid", ResourceVersion: "31"}
	for _, test := range []struct {
		name        string
		deleteError error
		wantOutcome rotation.EffectOutcome
	}{
		{
			name:        "precondition conflict",
			deleteError: apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, nextSignerSecretName, errors.New("UID changed")),
			wantOutcome: rotation.EffectNotApplied,
		},
		{
			name:        "connection lost",
			deleteError: errors.New("connection lost after request submission"),
			wantOutcome: rotation.EffectUnknown,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewSimpleClientset(newGuardConfigMap(guardState{
				SchemaVersion: guardSchemaVersion, ScopeID: guard.ScopeID, ActiveOperationID: guard.OperationID,
			}))
			client.Fake.PrependReactor("delete", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, test.deleteError
			})
			adapter := &Adapter{kube: client}
			outcome, err := adapter.RequestReplacement(context.Background(), guard, reference)
			if outcome != test.wantOutcome || !errors.Is(err, test.deleteError) {
				t.Fatalf("RequestReplacement() = %q, %v", outcome, err)
			}
		})
	}
}

func TestObservePublicSignerBundleReturnsEveryNamedEntry(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       kubeAPIServerNamespace,
			Name:            publicSignerCMName,
			UID:             types.UID("public-config-map-uid"),
			ResourceVersion: "22",
		},
		Data: map[string]string{
			"service-account-002.pub": "second",
			"service-account-001.pub": "first",
		},
	})
	adapter := &Adapter{kube: client}

	observed, err := adapter.ObservePublicSignerBundle(context.Background(), nil)
	if err != nil {
		t.Fatalf("ObservePublicSignerBundle() returned unexpected error: %v", err)
	}
	if observed.ConfigMapUID != "public-config-map-uid" || observed.ConfigMapResourceVersion != "22" || len(observed.Signers) != 2 {
		t.Fatalf("ObservePublicSignerBundle() = %#v", observed)
	}
	if observed.Signers[0].Name != "service-account-001.pub" || string(observed.Signers[0].PublicKeyPEM) != "first" ||
		observed.Signers[1].Name != "service-account-002.pub" || string(observed.Signers[1].PublicKeyPEM) != "second" {
		t.Fatalf("signer entries = %#v", observed.Signers)
	}
}
