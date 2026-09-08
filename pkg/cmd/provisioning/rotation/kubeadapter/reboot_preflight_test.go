package kubeadapter

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/jwks"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/rotation"
)

func TestPreflightUsesClusterIDAndChecksEveryRequiredAccess(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: cloudCredentialOperatorNamespace}},
		readyNode("master-0", "master-boot"),
		readyNode("worker-0", "worker-boot"),
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       kubeAPIServerNamespace,
				Name:            publicSignerCMName,
				UID:             types.UID("public-cm-uid"),
				ResourceVersion: "8",
			},
			Data: map[string]string{"service-account-001.pub": "public"},
		},
	)
	master, err := client.CoreV1().Nodes().Get(context.Background(), "master-0", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	master.Labels = map[string]string{"node-role.kubernetes.io/master": ""}
	if _, err := client.CoreV1().Nodes().Update(context.Background(), master, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	client.Fake.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview).DeepCopy()
		review.Status.Allowed = true
		return true, review, nil
	})
	resources := newMemoryResourceClient(
		stableMachineConfigPool("master", 1),
		stableMachineConfigPool("worker", 1),
		testKubeAPIServer(7),
	)
	clusterID := configv1.ClusterID("a58a4337-2d99-41ed-b009-33b62d854224")
	metadata := &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
		Namespace:       kubeAPIServerOperatorNamespace,
		Name:            nextSignerSecretName,
		UID:             types.UID("next-signer-uid"),
		ResourceVersion: "9",
	}}
	adapter := newAdapter(
		client,
		staticClusterVersionGetter{version: &configv1.ClusterVersion{Spec: configv1.ClusterVersionSpec{ClusterID: clusterID}}},
		staticClusterOperatorLister{operators: stableClusterOperators()},
		resources,
		staticSecretMetadataGetter{metadata: metadata},
		testOptions(),
	)

	preflight, err := adapter.Preflight(context.Background())
	if err != nil {
		t.Fatalf("Preflight() returned unexpected error: %v", err)
	}
	if preflight.ClusterIdentity != string(clusterID) {
		t.Fatalf("cluster identity = %q, want %q", preflight.ClusterIdentity, clusterID)
	}
	accessChecks := 0
	for _, action := range client.Actions() {
		if action.Matches("create", "selfsubjectaccessreviews") {
			accessChecks++
		}
	}
	if accessChecks != len(preflightAccess) {
		t.Fatalf("SelfSubjectAccessReview calls = %d, want %d", accessChecks, len(preflightAccess))
	}
}

func TestPreflightFailsClosedWhenRequiredAccessIsDenied(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.Fake.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview).DeepCopy()
		review.Status.Allowed = false
		review.Status.Reason = "policy denied"
		return true, review, nil
	})
	adapter := newAdapter(
		client,
		staticClusterVersionGetter{},
		staticClusterOperatorLister{},
		newMemoryResourceClient(),
		staticSecretMetadataGetter{},
		testOptions(),
	)

	_, err := adapter.Preflight(context.Background())
	if err == nil || !strings.Contains(err.Error(), "policy denied") {
		t.Fatalf("Preflight() error = %v, want access denial", err)
	}
}

func TestMachineConfigPoolStabilityRejectsUpdatingPool(t *testing.T) {
	pool := stableMachineConfigPool("worker", 2)
	_ = unstructured.SetNestedSlice(pool.Object, []any{
		map[string]any{"type": "Updated", "status": "False"},
		map[string]any{"type": "Updating", "status": "True"},
		map[string]any{"type": "Degraded", "status": "False"},
	}, "status", "conditions")
	stable, err := machineConfigPoolStable(pool)
	if err != nil {
		t.Fatalf("machineConfigPoolStable() returned unexpected error: %v", err)
	}
	if stable {
		t.Fatal("machineConfigPoolStable() = true for an updating pool")
	}
}

func TestPrepareRebootRejectsNodeOutsideStableMCOManagement(t *testing.T) {
	ctx := context.Background()
	guard := testGuardReference()
	node := readyNode("unmanaged-0", "boot-before")
	node.Annotations = nil
	client := fake.NewSimpleClientset(
		newGuardConfigMap(guardState{SchemaVersion: guardSchemaVersion, ScopeID: guard.ScopeID, ActiveOperationID: guard.OperationID}),
		node,
	)
	adapter := &Adapter{
		kube: client,
		resources: newMemoryResourceClient(
			stableMachineConfigPool("master", 0),
			stableMachineConfigPool("worker", 1),
		),
	}

	_, err := adapter.PrepareReboot(ctx, guard, "replacement-key-id")
	if err == nil || !strings.Contains(err.Error(), "not stably managed") {
		t.Fatalf("PrepareReboot() error = %v, want unmanaged-node rejection", err)
	}
}

func TestPrepareRebootSupportsCustomPoolThatInheritsWorkerMachineConfigs(t *testing.T) {
	ctx := context.Background()
	guard := testGuardReference()
	node := readyNode("worker-infra-0", "boot-before")
	delete(node.Labels, "node-role.kubernetes.io/worker")
	node.Labels["node-role.kubernetes.io/infra"] = ""
	node.Annotations[nodeCurrentConfigAnnotation] = "rendered-infra-old"
	node.Annotations[nodeDesiredConfigAnnotation] = "rendered-infra-old"
	client := fake.NewSimpleClientset(
		newGuardConfigMap(guardState{SchemaVersion: guardSchemaVersion, ScopeID: guard.ScopeID, ActiveOperationID: guard.OperationID}),
		node,
	)
	infraPool := stableMachineConfigPool("infra", 1)
	_ = unstructured.SetNestedMap(infraPool.Object, map[string]any{
		"matchExpressions": []any{map[string]any{
			"key":      "machineconfiguration.openshift.io/role",
			"operator": "In",
			"values":   []any{"worker", "infra"},
		}},
	}, "spec", "machineConfigSelector")
	adapter := &Adapter{
		kube: client,
		resources: newMemoryResourceClient(
			stableMachineConfigPool("master", 0),
			stableMachineConfigPool("worker", 0),
			infraPool,
		),
	}

	plan, err := adapter.PrepareReboot(ctx, guard, "replacement-key-id")
	if err != nil {
		t.Fatalf("PrepareReboot() returned unexpected error: %v", err)
	}
	want := rotation.RebootPlan{
		Targets:   []string{"worker"},
		Baselines: []rotation.NodeRebootBaseline{{Target: "worker", Node: node.Name, BootID: "boot-before"}},
	}
	if !reflect.DeepEqual(plan, want) {
		t.Fatalf("PrepareReboot() = %#v, want %#v", plan, want)
	}
}

func TestPrepareRebootRejectsCustomPoolThatDoesNotInheritTargetMachineConfigs(t *testing.T) {
	ctx := context.Background()
	guard := testGuardReference()
	node := readyNode("worker-infra-0", "boot-before")
	delete(node.Labels, "node-role.kubernetes.io/worker")
	node.Labels["node-role.kubernetes.io/infra"] = ""
	node.Annotations[nodeCurrentConfigAnnotation] = "rendered-infra-old"
	node.Annotations[nodeDesiredConfigAnnotation] = "rendered-infra-old"
	client := fake.NewSimpleClientset(
		newGuardConfigMap(guardState{SchemaVersion: guardSchemaVersion, ScopeID: guard.ScopeID, ActiveOperationID: guard.OperationID}),
		node,
	)
	adapter := &Adapter{
		kube: client,
		resources: newMemoryResourceClient(
			stableMachineConfigPool("master", 0),
			stableMachineConfigPool("worker", 0),
			stableMachineConfigPool("infra", 1),
		),
	}

	_, err := adapter.PrepareReboot(ctx, guard, "replacement-key-id")
	if err == nil || !strings.Contains(err.Error(), "matches 0 supported reboot targets") {
		t.Fatalf("PrepareReboot() error = %v, want unsupported custom-pool rejection", err)
	}
}

func TestPrepareRebootUsesEffectiveMasterPoolForSingleNodeCluster(t *testing.T) {
	ctx := context.Background()
	guard := testGuardReference()
	node := readyNode("master-0", "boot-before")
	node.Labels["node-role.kubernetes.io/worker"] = ""
	client := fake.NewSimpleClientset(
		newGuardConfigMap(guardState{SchemaVersion: guardSchemaVersion, ScopeID: guard.ScopeID, ActiveOperationID: guard.OperationID}),
		node,
	)
	adapter := &Adapter{
		kube: client,
		resources: newMemoryResourceClient(
			stableMachineConfigPool("master", 1),
			stableMachineConfigPool("worker", 0),
		),
	}

	plan, err := adapter.PrepareReboot(ctx, guard, "replacement-key-id")
	if err != nil {
		t.Fatalf("PrepareReboot() returned unexpected error: %v", err)
	}
	if !reflect.DeepEqual(plan.Targets, []string{"master"}) || len(plan.Baselines) != 1 || plan.Baselines[0].Target != "master" {
		t.Fatalf("PrepareReboot() = %#v, want only the effective master target", plan)
	}
}

func TestPrepareRebootRejectsArbiterPoolBeforeMutation(t *testing.T) {
	ctx := context.Background()
	guard := testGuardReference()
	node := readyNode("arbiter-0", "boot-before")
	node.Labels = map[string]string{"node-role.kubernetes.io/arbiter": ""}
	node.Annotations[nodeCurrentConfigAnnotation] = "rendered-arbiter-old"
	node.Annotations[nodeDesiredConfigAnnotation] = "rendered-arbiter-old"
	client := fake.NewSimpleClientset(
		newGuardConfigMap(guardState{SchemaVersion: guardSchemaVersion, ScopeID: guard.ScopeID, ActiveOperationID: guard.OperationID}),
		node,
	)
	resources := newMemoryResourceClient(
		stableMachineConfigPool("master", 0),
		stableMachineConfigPool("worker", 0),
		stableMachineConfigPool("arbiter", 1),
	)
	adapter := &Adapter{kube: client, resources: resources}

	_, err := adapter.PrepareReboot(ctx, guard, "replacement-key-id")
	if err == nil || !strings.Contains(err.Error(), "exactly one of master or worker is required") {
		t.Fatalf("PrepareReboot() error = %v, want arbiter topology rejection", err)
	}
	for _, target := range []string{"master", "worker"} {
		creates, updates := resources.actionCount(machineConfigGVR, rebootMachineConfigName(target))
		if creates != 0 || updates != 0 {
			t.Fatalf("%s MachineConfig mutated during failed planning: create/update=%d/%d", target, creates, updates)
		}
	}
}

func TestPrepareRebootRejectsReservedMachineConfigCollisionBeforeMutation(t *testing.T) {
	ctx := context.Background()
	guard := testGuardReference()
	client := fake.NewSimpleClientset(
		newGuardConfigMap(guardState{SchemaVersion: guardSchemaVersion, ScopeID: guard.ScopeID, ActiveOperationID: guard.OperationID}),
		readyNode("master-0", "boot-before"),
	)
	collision := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "machineconfiguration.openshift.io/v1",
		"kind":       "MachineConfig",
		"metadata":   map[string]any{"name": rebootMachineConfigMaster},
		"spec":       map[string]any{},
	}}
	resources := newMemoryResourceClient(
		stableMachineConfigPool("master", 1),
		stableMachineConfigPool("worker", 0),
		collision,
	)
	adapter := &Adapter{kube: client, resources: resources}

	_, err := adapter.PrepareReboot(ctx, guard, "replacement-key-id")
	if err == nil || !strings.Contains(err.Error(), "without expected rotation ownership") {
		t.Fatalf("PrepareReboot() error = %v, want reserved-name collision rejection", err)
	}
	creates, updates := resources.actionCount(machineConfigGVR, rebootMachineConfigMaster)
	if creates != 0 || updates != 0 {
		t.Fatalf("reserved MachineConfig mutated during failed planning: create/update=%d/%d", creates, updates)
	}
}

func TestWaitUntilReturnsPromptlyWhenContextIsCancelled(t *testing.T) {
	adapter := &Adapter{options: Options{PollInterval: time.Hour}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	err := adapter.waitUntil(ctx, func(context.Context) (bool, error) { return false, nil })
	if err != context.Canceled {
		t.Fatalf("waitUntil() error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("waitUntil() took %s after cancellation", elapsed)
	}
}

func TestRequestRebootRecordsIntentBeforeMachineConfigsAndResumesMissingTarget(t *testing.T) {
	ctx := context.Background()
	guard := testGuardReference()
	intent := testRebootIntent()
	client := fake.NewSimpleClientset(testObjectsForRebootIntent(guard, intent)...)
	resources := newMemoryResourceClient(
		stableMachineConfigPool("master", 1),
		stableMachineConfigPool("worker", 1),
	)
	workerKey := machineConfigGVR.String() + "/" + rebootMachineConfigWorker
	resources.failCreateOnce[workerKey] = apierrors.NewServiceUnavailable("worker create interrupted")
	resources.beforeCreate = func(resource schema.GroupVersionResource, _ *unstructured.Unstructured) error {
		if resource != machineConfigGVR {
			return nil
		}
		_, err := client.CoreV1().ConfigMaps(cloudCredentialOperatorNamespace).Get(ctx, rebootRecordName(intent.ID), metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("MachineConfig mutation ran before canonical record: %w", err)
		}
		return nil
	}
	adapter := &Adapter{kube: client, resources: resources}

	outcome, err := adapter.RequestReboot(ctx, guard, intent)
	if outcome != rotation.EffectUnknown || err == nil {
		t.Fatalf("first RequestReboot() = %q, %v; want unknown partial outcome", outcome, err)
	}
	record, err := client.CoreV1().ConfigMaps(cloudCredentialOperatorNamespace).Get(ctx, rebootRecordName(intent.ID), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("canonical reboot record was not durable: %v", err)
	}
	if record.Immutable == nil || !*record.Immutable {
		t.Fatalf("canonical reboot record immutable = %#v", record.Immutable)
	}
	if _, err := resources.Get(ctx, machineConfigGVR, rebootMachineConfigMaster, metav1.GetOptions{}); err != nil {
		t.Fatalf("master reboot request was not durable: %v", err)
	}
	if _, err := resources.Get(ctx, machineConfigGVR, rebootMachineConfigWorker, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("worker reboot request error = %v, want NotFound after interrupted create", err)
	}

	outcome, err = adapter.RequestReboot(ctx, guard, intent)
	if err != nil || outcome != rotation.EffectSubmitted {
		t.Fatalf("resumed RequestReboot() = %q, %v", outcome, err)
	}
	outcome, err = adapter.RequestReboot(ctx, guard, intent)
	if err != nil || outcome != rotation.EffectSubmitted {
		t.Fatalf("idempotent RequestReboot() = %q, %v", outcome, err)
	}
	masterCreates, masterUpdates := resources.actionCount(machineConfigGVR, rebootMachineConfigMaster)
	workerCreates, workerUpdates := resources.actionCount(machineConfigGVR, rebootMachineConfigWorker)
	if masterCreates != 1 || masterUpdates != 0 || workerCreates != 2 || workerUpdates != 0 {
		t.Fatalf("MachineConfig mutations: master create/update=%d/%d worker=%d/%d", masterCreates, masterUpdates, workerCreates, workerUpdates)
	}
}

func TestRequestRebootPreservesAmbiguousRecordCreateOutcome(t *testing.T) {
	ctx := context.Background()
	guard := testGuardReference()
	intent := testSingleTargetRebootIntent()
	client := fake.NewSimpleClientset(testObjectsForRebootIntent(guard, intent)...)
	connectionLost := errors.New("connection lost after request submission")
	client.Fake.PrependReactor("create", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
		created := action.(k8stesting.CreateAction).GetObject().(*corev1.ConfigMap)
		if created.Name == rebootRecordName(intent.ID) {
			return true, nil, connectionLost
		}
		return false, nil, nil
	})
	adapter := &Adapter{kube: client, resources: newMemoryResourceClient(
		stableMachineConfigPool("master", 1),
		stableMachineConfigPool("worker", 0),
	)}

	outcome, err := adapter.RequestReboot(ctx, guard, intent)
	if outcome != rotation.EffectUnknown || !errors.Is(err, connectionLost) {
		t.Fatalf("RequestReboot() = %q, %v; want EffectUnknown with connection loss", outcome, err)
	}
}

func TestRequestRebootRevalidatesPlanBeforeRecordingCanonicalIntent(t *testing.T) {
	ctx := context.Background()
	guard := testGuardReference()
	intent := testSingleTargetRebootIntent()
	node := readyNode(intent.Baselines[0].Node, "boot-changed-after-checkpoint")
	client := fake.NewSimpleClientset(
		newGuardConfigMap(guardState{SchemaVersion: guardSchemaVersion, ScopeID: guard.ScopeID, ActiveOperationID: guard.OperationID}),
		node,
	)
	resources := newMemoryResourceClient(
		stableMachineConfigPool("master", 1),
		stableMachineConfigPool("worker", 0),
	)
	adapter := &Adapter{kube: client, resources: resources}

	outcome, err := adapter.RequestReboot(ctx, guard, intent)
	if outcome != rotation.EffectNotApplied || err == nil || !strings.Contains(err.Error(), "differs from the checkpointed intent") {
		t.Fatalf("RequestReboot() = %q, %v; want stale-plan rejection", outcome, err)
	}
	if _, err := client.CoreV1().ConfigMaps(cloudCredentialOperatorNamespace).Get(ctx, rebootRecordName(intent.ID), metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("canonical reboot record error = %v, want NotFound", err)
	}
	creates, updates := resources.actionCount(machineConfigGVR, rebootMachineConfigMaster)
	if creates != 0 || updates != 0 {
		t.Fatalf("MachineConfig mutated for stale plan: create/update=%d/%d", creates, updates)
	}
}

func TestRequestRebootFailsClosedOnSameOperationMachineConfigDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*unstructured.Unstructured)
	}{
		{
			name: "tampered marker",
			mutate: func(machineConfig *unstructured.Unstructured) {
				_ = unstructured.SetNestedSlice(machineConfig.Object, []any{map[string]any{
					"path": rebootMarkerPath, "mode": int64(0644), "overwrite": true,
					"contents": map[string]any{"source": "data:,tampered"},
				}}, "spec", "config", "storage", "files")
			},
		},
		{
			name: "extra file",
			mutate: func(machineConfig *unstructured.Unstructured) {
				files, _, _ := unstructured.NestedSlice(machineConfig.Object, "spec", "config", "storage", "files")
				files = append(files, map[string]any{
					"path": "/etc/unexpected", "mode": int64(0644), "overwrite": true,
					"contents": map[string]any{"source": "data:,unexpected"},
				})
				_ = unstructured.SetNestedSlice(machineConfig.Object, files, "spec", "config", "storage", "files")
			},
		},
		{
			name: "extra spec field",
			mutate: func(machineConfig *unstructured.Unstructured) {
				_ = unstructured.SetNestedStringSlice(machineConfig.Object, []string{"debug"}, "spec", "kernelArguments")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			guard := testGuardReference()
			intent := testSingleTargetRebootIntent()
			client := fake.NewSimpleClientset(testObjectsForRebootIntent(guard, intent)...)
			resources := newMemoryResourceClient(
				stableMachineConfigPool("master", 1),
				stableMachineConfigPool("worker", 0),
			)
			adapter := &Adapter{kube: client, resources: resources}
			if outcome, err := adapter.RequestReboot(ctx, guard, intent); err != nil || outcome != rotation.EffectSubmitted {
				t.Fatalf("initial RequestReboot() = %q, %v", outcome, err)
			}
			machineConfig, err := resources.Get(ctx, machineConfigGVR, rebootMachineConfigMaster, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(machineConfig)
			resources.put(machineConfigGVR, machineConfig)

			outcome, err := adapter.RequestReboot(ctx, guard, intent)
			if outcome != rotation.EffectUnknown || err == nil || !strings.Contains(err.Error(), "exact reboot specification") {
				t.Fatalf("drifted RequestReboot() = %q, %v", outcome, err)
			}
			_, updates := resources.actionCount(machineConfigGVR, rebootMachineConfigMaster)
			if updates != 0 {
				t.Fatalf("drifted MachineConfig was updated %d times; want fail closed", updates)
			}
		})
	}
}

func TestObserveRebootRequiresBootIDChangeAndAppliedRenderedMarker(t *testing.T) {
	ctx := context.Background()
	guard := testGuardReference()
	intent := testSingleTargetRebootIntent()
	node := readyNode("master-0", intent.Baselines[0].BootID)
	client := fake.NewSimpleClientset(
		newGuardConfigMap(guardState{SchemaVersion: guardSchemaVersion, ScopeID: guard.ScopeID, ActiveOperationID: guard.OperationID}),
		node,
	)
	resources := newMemoryResourceClient(
		stableMachineConfigPool("master", 1),
		stableMachineConfigPool("worker", 0),
		&unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "machineconfiguration.openshift.io/v1",
			"kind":       "MachineConfig",
			"metadata":   map[string]any{"name": "rendered-master-new"},
			"spec":       map[string]any{"config": map[string]any{}},
		}},
	)
	adapter := &Adapter{kube: client, resources: resources}
	if outcome, err := adapter.RequestReboot(ctx, guard, intent); err != nil || outcome != rotation.EffectSubmitted {
		t.Fatalf("RequestReboot() = %q, %v", outcome, err)
	}

	observation, err := adapter.ObserveReboot(ctx, guard, intent.ID)
	if err != nil || observation.Status != rotation.RebootInProgress {
		t.Fatalf("observation before reboot = %#v, %v", observation, err)
	}
	current, err := client.CoreV1().Nodes().Get(ctx, node.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	current.Status.NodeInfo.BootID = "master-boot-after"
	current.Annotations[nodeCurrentConfigAnnotation] = "rendered-master-new"
	current.Annotations[nodeDesiredConfigAnnotation] = "rendered-master-new"
	if _, err := client.CoreV1().Nodes().UpdateStatus(ctx, current, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update node boot ID: %v", err)
	}
	observation, err = adapter.ObserveReboot(ctx, guard, intent.ID)
	if err != nil || observation.Status != rotation.RebootInProgress {
		t.Fatalf("observation without rendered marker = %#v, %v", observation, err)
	}
	selectorLabels, err := machineConfigSelectorLabels(stableMachineConfigPool("master", 1))
	if err != nil {
		t.Fatal(err)
	}
	resources.put(machineConfigGVR, desiredRebootMachineConfig(nil, "rendered-master-new", "master", intent.ID, selectorLabels))
	observation, err = adapter.ObserveReboot(ctx, guard, intent.ID)
	if err != nil || observation.Status != rotation.RebootComplete {
		t.Fatalf("completed observation = %#v, %v", observation, err)
	}
	if observation.CanonicalIntent == nil || !reflect.DeepEqual(*observation.CanonicalIntent, intent) {
		t.Fatalf("canonical intent = %#v, want %#v", observation.CanonicalIntent, intent)
	}
}

func TestObserveRebootTreatsDeletedBaselineNodeAsComplete(t *testing.T) {
	ctx := context.Background()
	guard := testGuardReference()
	intent := testSingleTargetRebootIntent()
	originalNode := readyNode("master-0", intent.Baselines[0].BootID)
	client := fake.NewSimpleClientset(
		newGuardConfigMap(guardState{SchemaVersion: guardSchemaVersion, ScopeID: guard.ScopeID, ActiveOperationID: guard.OperationID}),
		originalNode,
	)
	resources := newMemoryResourceClient(
		stableMachineConfigPool("master", 1),
		stableMachineConfigPool("worker", 0),
	)
	adapter := newAdapter(
		client,
		staticClusterVersionGetter{},
		staticClusterOperatorLister{operators: stableClusterOperators()},
		resources,
		staticSecretMetadataGetter{},
		testOptions(),
	)
	if outcome, err := adapter.RequestReboot(ctx, guard, intent); err != nil || outcome != rotation.EffectSubmitted {
		t.Fatalf("RequestReboot() = %q, %v", outcome, err)
	}
	if err := client.CoreV1().Nodes().Delete(ctx, originalNode.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete baseline node: %v", err)
	}
	replacementNode := readyNode("master-replacement", "replacement-boot")
	replacementNode.Annotations[nodeCurrentConfigAnnotation] = "rendered-master-replacement"
	replacementNode.Annotations[nodeDesiredConfigAnnotation] = "rendered-master-replacement"
	if _, err := client.CoreV1().Nodes().Create(ctx, replacementNode, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create replacement node: %v", err)
	}
	masterPool := stableMachineConfigPool("master", 1)
	_ = unstructured.SetNestedField(masterPool.Object, "rendered-master-replacement", "spec", "configuration", "name")
	_ = unstructured.SetNestedField(masterPool.Object, "rendered-master-replacement", "status", "configuration", "name")
	resources.put(machineConfigPoolGVR, masterPool)
	selectorLabels, err := machineConfigSelectorLabels(stableMachineConfigPool("master", 1))
	if err != nil {
		t.Fatal(err)
	}
	resources.put(machineConfigGVR, desiredRebootMachineConfig(nil, "rendered-master-replacement", "master", intent.ID, selectorLabels))

	observation, err := adapter.ObserveReboot(ctx, guard, intent.ID)
	if err != nil || observation.Status != rotation.RebootComplete {
		t.Fatalf("ObserveReboot() after baseline node deletion = %#v, %v", observation, err)
	}
	if err := adapter.WaitForPostRebootStable(ctx, guard, intent); err != nil {
		t.Fatalf("WaitForPostRebootStable() after baseline node replacement: %v", err)
	}
}

func TestWaitForSignerRolloutRequiresEveryCurrentRevision(t *testing.T) {
	ctx := context.Background()
	guard := testGuardReference()
	publicKey := testPublicKeyPEM(t)
	set, err := jwks.NewSigner(publicKey)
	if err != nil {
		t.Fatalf("build test signer: %v", err)
	}
	entryName := "service-account-002.pub"
	client := fake.NewSimpleClientset(
		newGuardConfigMap(guardState{SchemaVersion: guardSchemaVersion, ScopeID: guard.ScopeID, ActiveOperationID: guard.OperationID}),
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: kubeAPIServerNamespace, Name: publicSignerCMName}, Data: map[string]string{entryName: string(publicKey)}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: kubeAPIServerNamespace, Name: publicSignerCMName + "-7"}, Data: map[string]string{entryName: string(publicKey)}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: kubeAPIServerNamespace, Name: publicSignerCMName + "-8"}, Data: map[string]string{entryName: string(publicKey)}},
	)
	adapter := newAdapter(
		client,
		staticClusterVersionGetter{},
		staticClusterOperatorLister{operators: stableClusterOperators()},
		newMemoryResourceClient(testKubeAPIServer(7, 8)),
		staticSecretMetadataGetter{},
		testOptions(),
	)
	if err := adapter.WaitForSignerRollout(ctx, guard, set.Keys[0].KeyID); err != nil {
		t.Fatalf("WaitForSignerRollout() returned unexpected error: %v", err)
	}
}

func TestReconcileSignerRolloutCheckpointRequiresCurrentStability(t *testing.T) {
	ctx := context.Background()
	guard := testGuardReference()
	clusterID := configv1.ClusterID("a58a4337-2d99-41ed-b009-33b62d854224")
	client := fake.NewSimpleClientset(
		newGuardConfigMap(guardState{SchemaVersion: guardSchemaVersion, ScopeID: guard.ScopeID, ActiveOperationID: guard.OperationID}),
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: kubeAPIServerNamespace, Name: publicSignerCMName},
			Data:       map[string]string{"service-account-001.pub": string(testPublicKeyPEM(t))},
		},
	)
	adapter := newAdapter(
		client,
		staticClusterVersionGetter{version: &configv1.ClusterVersion{Spec: configv1.ClusterVersionSpec{ClusterID: clusterID}}},
		staticClusterOperatorLister{operators: stableClusterOperators()},
		newMemoryResourceClient(),
		staticSecretMetadataGetter{},
		testOptions(),
	)
	expectation := rotation.ClusterExpectation{
		Phase:           rotation.PhaseSignerRolloutStable,
		ClusterIdentity: string(clusterID),
		RotationGuard:   guard,
		ReplacementSigner: &rotation.ReplacementSignerEvidence{
			Entry: rotation.PublicSignerBaselineEntry{KeyID: "replacement-key-not-published"},
		},
	}

	err := adapter.Reconcile(ctx, guard, expectation)
	if err == nil || !strings.Contains(err.Error(), "cluster is not currently stable") {
		t.Fatalf("Reconcile() error = %v, want stale signer-rollout checkpoint rejection", err)
	}
}

func testGuardReference() rotation.RotationGuardReference {
	return rotation.RotationGuardReference{ScopeID: strings.Repeat("a", 64), OperationID: strings.Repeat("b", 64)}
}

func testRebootIntent() rotation.RebootIntent {
	return rotation.RebootIntent{
		ID:      "signer-rotation-" + strings.Repeat("c", 64),
		Targets: []string{"master", "worker"},
		Baselines: []rotation.NodeRebootBaseline{
			{Target: "master", Node: "master-0", BootID: "master-boot-before"},
			{Target: "worker", Node: "worker-0", BootID: "worker-boot-before"},
		},
	}
}

func testSingleTargetRebootIntent() rotation.RebootIntent {
	return rotation.RebootIntent{
		ID:        "signer-rotation-" + strings.Repeat("d", 64),
		Targets:   []string{"master"},
		Baselines: []rotation.NodeRebootBaseline{{Target: "master", Node: "master-0", BootID: "master-boot-before"}},
	}
}

func testObjectsForRebootIntent(guard rotation.RotationGuardReference, intent rotation.RebootIntent) []runtime.Object {
	objects := []runtime.Object{newGuardConfigMap(guardState{
		SchemaVersion: guardSchemaVersion, ScopeID: guard.ScopeID, ActiveOperationID: guard.OperationID,
	})}
	for _, baseline := range intent.Baselines {
		node := readyNode(baseline.Node, baseline.BootID)
		node.Labels = map[string]string{"node-role.kubernetes.io/" + baseline.Target: ""}
		node.Annotations[nodeCurrentConfigAnnotation] = "rendered-" + baseline.Target + "-old"
		node.Annotations[nodeDesiredConfigAnnotation] = "rendered-" + baseline.Target + "-old"
		objects = append(objects, node)
	}
	return objects
}

func readyNode(name, bootID string) *corev1.Node {
	role := testNodeRole(name)
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"node-role.kubernetes.io/" + role: "",
			},
			Annotations: map[string]string{
				nodeCurrentConfigAnnotation: "rendered-" + role + "-old",
				nodeDesiredConfigAnnotation: "rendered-" + role + "-old",
			},
		},
		Status: corev1.NodeStatus{
			NodeInfo:   corev1.NodeSystemInfo{BootID: bootID},
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		},
	}
}

func testPublicKeyPEM(t *testing.T) []byte {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal RSA public key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
