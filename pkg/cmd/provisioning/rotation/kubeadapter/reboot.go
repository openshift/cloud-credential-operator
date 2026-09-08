package kubeadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/rotation"
)

const (
	rebootRecordSchemaVersion = 1
	rebootRecordDataKey       = "intent.json"
	rebootRecordNamePrefix    = "cco-signer-key-rotation-reboot-"
	maxRebootRecordDataBytes  = 900 * 1024

	rebootMachineConfigMaster = "95-cco-signer-key-rotation-reboot-master"
	rebootMachineConfigWorker = "95-cco-signer-key-rotation-reboot-worker"
	rebootMarkerPath          = "/etc/kubernetes/cco-signer-key-rotation-reboot-id"

	managedAnnotation        = "cloudcredential.openshift.io/signer-rotation-managed"
	rebootIDAnnotation       = "cloudcredential.openshift.io/signer-rotation-reboot-id"
	rebootTargetAnnotation   = "cloudcredential.openshift.io/signer-rotation-reboot-target"
	rebootScopeAnnotation    = "cloudcredential.openshift.io/signer-rotation-scope-id"
	guardOperationAnnotation = "cloudcredential.openshift.io/signer-rotation-operation-id"

	nodeCurrentConfigAnnotation = "machineconfiguration.openshift.io/currentConfig"
	nodeDesiredConfigAnnotation = "machineconfiguration.openshift.io/desiredConfig"
)

type rebootRecord struct {
	SchemaVersion int                   `json:"schemaVersion"`
	ScopeID       string                `json:"scopeID"`
	OperationID   string                `json:"operationID"`
	Intent        rotation.RebootIntent `json:"intent"`
}

type rebootPoolSelection struct {
	pool                  *unstructured.Unstructured
	nodeSelector          labels.Selector
	machineConfigSelector labels.Selector
	currentConfig         string
}

func (a *Adapter) PrepareReboot(ctx context.Context, guard rotation.RotationGuardReference, replacementKeyID string) (rotation.RebootPlan, error) {
	if err := a.requireGuardHeld(ctx, guard); err != nil {
		return rotation.RebootPlan{}, err
	}
	if strings.TrimSpace(replacementKeyID) == "" || strings.TrimSpace(replacementKeyID) != replacementKeyID {
		return rotation.RebootPlan{}, fmt.Errorf("replacement signer key ID must not be empty or contain surrounding whitespace")
	}
	return a.prepareRebootPlan(ctx)
}

func (a *Adapter) prepareRebootPlan(ctx context.Context) (rotation.RebootPlan, error) {
	pools, err := a.resources.List(ctx, machineConfigPoolGVR, metav1.ListOptions{})
	if err != nil {
		return rotation.RebootPlan{}, fmt.Errorf("list MachineConfigPools before reboot: %w", err)
	}
	poolSelections := make([]rebootPoolSelection, 0, len(pools.Items))
	for i := range pools.Items {
		pool := &pools.Items[i]
		stable, err := machineConfigPoolStable(pool)
		if err != nil {
			return rotation.RebootPlan{}, err
		}
		if !stable {
			return rotation.RebootPlan{}, fmt.Errorf("MachineConfigPool %q is not stable before reboot", pool.GetName())
		}
		selection, err := newRebootPoolSelection(pool)
		if err != nil {
			return rotation.RebootPlan{}, err
		}
		poolSelections = append(poolSelections, selection)
	}
	targetMachineConfigLabels, targetSelectorLabels, err := rebootTargetMachineConfigLabels(pools)
	if err != nil {
		return rotation.RebootPlan{}, err
	}

	nodes, err := a.kube.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return rotation.RebootPlan{}, fmt.Errorf("list nodes before reboot: %w", err)
	}
	if len(nodes.Items) == 0 {
		return rotation.RebootPlan{}, fmt.Errorf("cluster has no nodes to reboot")
	}
	targets := make(map[string]struct{}, 2)
	baselines := make([]rotation.NodeRebootBaseline, 0, len(nodes.Items))
	observedPoolCounts := make(map[string]int64, len(poolSelections))
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if !nodeReady(node) {
			return rotation.RebootPlan{}, fmt.Errorf("node %q is not Ready before reboot", node.Name)
		}
		if strings.TrimSpace(node.Status.NodeInfo.BootID) == "" {
			return rotation.RebootPlan{}, fmt.Errorf("node %q has no boot ID", node.Name)
		}
		currentConfig := node.Annotations[nodeCurrentConfigAnnotation]
		desiredConfig := node.Annotations[nodeDesiredConfigAnnotation]
		if currentConfig == "" || desiredConfig == "" || currentConfig != desiredConfig {
			return rotation.RebootPlan{}, fmt.Errorf("node %q is not stably managed by the Machine Config Operator", node.Name)
		}
		pool, err := effectiveMachineConfigPoolForNode(node, currentConfig, poolSelections)
		if err != nil {
			return rotation.RebootPlan{}, err
		}
		target, err := rebootTargetForPool(node.Name, pool, targetMachineConfigLabels)
		if err != nil {
			return rotation.RebootPlan{}, err
		}
		observedPoolCounts[pool.pool.GetName()]++
		targets[target] = struct{}{}
		baselines = append(baselines, rotation.NodeRebootBaseline{Target: target, Node: node.Name, BootID: node.Status.NodeInfo.BootID})
	}
	for _, pool := range poolSelections {
		expectedCount, ok := nestedInteger(pool.pool, "status", "machineCount")
		if !ok {
			return rotation.RebootPlan{}, fmt.Errorf("MachineConfigPool %q has no machine count", pool.pool.GetName())
		}
		if observedPoolCounts[pool.pool.GetName()] != expectedCount {
			return rotation.RebootPlan{}, fmt.Errorf("MachineConfigPool %q reports %d nodes but %d were resolved from the stable node snapshot", pool.pool.GetName(), expectedCount, observedPoolCounts[pool.pool.GetName()])
		}
	}

	orderedTargets := make([]string, 0, len(targets))
	for target := range targets {
		orderedTargets = append(orderedTargets, target)
	}
	slices.Sort(orderedTargets)
	slices.SortFunc(baselines, func(left, right rotation.NodeRebootBaseline) int {
		if comparison := strings.Compare(left.Target, right.Target); comparison != 0 {
			return comparison
		}
		return strings.Compare(left.Node, right.Node)
	})
	for _, target := range orderedTargets {
		if err := a.validateExistingRebootMachineConfig(ctx, target, targetSelectorLabels[target]); err != nil {
			return rotation.RebootPlan{}, err
		}
	}
	return rotation.RebootPlan{Targets: orderedTargets, Baselines: baselines}, nil
}

func (a *Adapter) ObserveReboot(ctx context.Context, guard rotation.RotationGuardReference, operationID string) (rotation.RebootObservation, error) {
	if err := a.requireGuardHeld(ctx, guard); err != nil {
		return rotation.RebootObservation{}, err
	}
	if err := validateRebootID(operationID); err != nil {
		return rotation.RebootObservation{}, err
	}
	configMap, err := a.kube.CoreV1().ConfigMaps(cloudCredentialOperatorNamespace).Get(ctx, rebootRecordName(operationID), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return rotation.RebootObservation{Status: rotation.RebootNotStarted}, nil
	}
	if err != nil {
		return rotation.RebootObservation{}, fmt.Errorf("read canonical reboot record: %w", err)
	}
	record, err := decodeRebootRecord(configMap, guard, operationID)
	if err != nil {
		return rotation.RebootObservation{}, err
	}
	intent := cloneRebootIntent(record.Intent)
	observation := rotation.RebootObservation{Status: rotation.RebootInProgress, CanonicalIntent: &intent}

	for _, target := range intent.Targets {
		machineConfig, err := a.resources.Get(ctx, machineConfigGVR, rebootMachineConfigName(target), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return observation, nil
		}
		if err != nil {
			return rotation.RebootObservation{}, fmt.Errorf("read reboot MachineConfig for target %q: %w", target, err)
		}
		pool, err := a.resources.Get(ctx, machineConfigPoolGVR, target, metav1.GetOptions{})
		if err != nil {
			return rotation.RebootObservation{}, fmt.Errorf("read MachineConfigPool %q during reboot observation: %w", target, err)
		}
		selectorLabels, err := machineConfigSelectorLabels(pool)
		if err != nil {
			return rotation.RebootObservation{}, err
		}
		if err := validateRebootMachineConfig(machineConfig, target, intent.ID, selectorLabels); err != nil {
			return rotation.RebootObservation{}, err
		}
	}

	renderedConfigs := make(map[string]*unstructured.Unstructured)
	for _, baseline := range intent.Baselines {
		node, err := a.kube.CoreV1().Nodes().Get(ctx, baseline.Node, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			// Node replacement or removal proves the pre-intent instance is no
			// longer running. This matches the OpenShift node-reboot waiter and
			// keeps an immutable baseline from becoming an unrecoverable dead end.
			continue
		}
		if err != nil {
			return rotation.RebootObservation{}, fmt.Errorf("read reboot node %q: %w", baseline.Node, err)
		}
		if node.Status.NodeInfo.BootID == "" {
			return rotation.RebootObservation{}, fmt.Errorf("reboot node %q has no boot ID", baseline.Node)
		}
		if node.Status.NodeInfo.BootID == baseline.BootID {
			return observation, nil
		}
		currentConfig := node.Annotations[nodeCurrentConfigAnnotation]
		desiredConfig := node.Annotations[nodeDesiredConfigAnnotation]
		if currentConfig == "" || currentConfig != desiredConfig {
			return observation, nil
		}
		rendered := renderedConfigs[currentConfig]
		if rendered == nil {
			rendered, err = a.resources.Get(ctx, machineConfigGVR, currentConfig, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return observation, nil
			}
			if err != nil {
				return rotation.RebootObservation{}, fmt.Errorf("read node %q current MachineConfig %q: %w", baseline.Node, currentConfig, err)
			}
			renderedConfigs[currentConfig] = rendered
		}
		if !machineConfigHasRebootMarker(rendered, intent.ID) {
			return observation, nil
		}
	}

	observation.Status = rotation.RebootComplete
	return observation, nil
}

func (a *Adapter) RequestReboot(ctx context.Context, guard rotation.RotationGuardReference, intent rotation.RebootIntent) (rotation.EffectOutcome, error) {
	if err := a.requireGuardHeld(ctx, guard); err != nil {
		return rotation.EffectNotApplied, err
	}
	if err := validateRebootIntent(intent); err != nil {
		return rotation.EffectNotApplied, err
	}
	recordApplied, recordOutcome, err := a.ensureRebootRecord(ctx, guard, intent)
	if err != nil {
		return recordOutcome, err
	}
	if !recordApplied {
		return rotation.EffectUnknown, fmt.Errorf("canonical reboot record is not observable")
	}

	targets := append([]string(nil), intent.Targets...)
	slices.Sort(targets)
	for _, target := range targets {
		if err := a.requireGuardHeld(ctx, guard); err != nil {
			return rotation.EffectUnknown, fmt.Errorf("reconcile reboot target %q after recording canonical intent: %w", target, err)
		}
		if _, err := a.ensureRebootMachineConfig(ctx, target, intent.ID); err != nil {
			return rotation.EffectUnknown, fmt.Errorf("reconcile reboot target %q: %w", target, err)
		}
	}
	return rotation.EffectSubmitted, nil
}

func (a *Adapter) WaitForReboot(ctx context.Context, guard rotation.RotationGuardReference, intent rotation.RebootIntent) error {
	if err := validateRebootIntent(intent); err != nil {
		return err
	}
	return a.waitUntil(ctx, func(ctx context.Context) (bool, error) {
		observation, err := a.ObserveReboot(ctx, guard, intent.ID)
		if err != nil {
			return false, err
		}
		if observation.Status == rotation.RebootNotStarted || observation.CanonicalIntent == nil {
			return false, fmt.Errorf("canonical reboot record %q disappeared while waiting", intent.ID)
		}
		if !reflect.DeepEqual(*observation.CanonicalIntent, intent) {
			return false, fmt.Errorf("canonical reboot record %q differs from the requested intent", intent.ID)
		}
		if observation.Status == rotation.RebootComplete {
			return true, nil
		}
		healthy, err := a.affectedMachineConfigPoolsHealthy(ctx, intent)
		if err != nil {
			return false, err
		}
		if !healthy {
			return false, fmt.Errorf("an affected MachineConfigPool became paused or degraded during reboot")
		}
		return false, nil
	})
}

func (a *Adapter) WaitForPostRebootStable(ctx context.Context, guard rotation.RotationGuardReference, intent rotation.RebootIntent) error {
	if err := validateRebootIntent(intent); err != nil {
		return err
	}
	return a.waitForContinuousStability(ctx, a.options.StablePeriod, func(ctx context.Context) (bool, error) {
		if err := a.requireGuardHeld(ctx, guard); err != nil {
			return false, err
		}
		return a.postRebootStateStable(ctx, guard, intent)
	})
}

func (a *Adapter) postRebootStateStable(ctx context.Context, guard rotation.RotationGuardReference, intent rotation.RebootIntent) (bool, error) {
	observation, err := a.ObserveReboot(ctx, guard, intent.ID)
	if err != nil {
		return false, err
	}
	if observation.Status != rotation.RebootComplete || observation.CanonicalIntent == nil || !reflect.DeepEqual(*observation.CanonicalIntent, intent) {
		return false, nil
	}
	stable, err := a.affectedMachineConfigPoolsStable(ctx, intent)
	if err != nil || !stable {
		return false, err
	}
	nodesStable, err := a.currentNodesStableForReboot(ctx, intent)
	if err != nil || !nodesStable {
		return false, err
	}
	return a.clusterOperatorsStable(ctx)
}

func (a *Adapter) currentNodesStableForReboot(ctx context.Context, intent rotation.RebootIntent) (bool, error) {
	pools, err := a.resources.List(ctx, machineConfigPoolGVR, metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("list MachineConfigPools for post-reboot node validation: %w", err)
	}
	targetMachineConfigLabels, _, err := rebootTargetMachineConfigLabels(pools)
	if err != nil {
		return false, err
	}
	poolSelections := make([]rebootPoolSelection, 0, len(pools.Items))
	for i := range pools.Items {
		selection, err := newRebootPoolSelection(&pools.Items[i])
		if err != nil {
			return false, err
		}
		poolSelections = append(poolSelections, selection)
	}
	nodes, err := a.kube.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("list post-reboot nodes: %w", err)
	}
	if len(nodes.Items) == 0 {
		return false, nil
	}
	targets := make(map[string]struct{}, len(intent.Targets))
	for _, target := range intent.Targets {
		targets[target] = struct{}{}
	}
	renderedConfigs := make(map[string]*unstructured.Unstructured)
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if !nodeReady(node) {
			return false, nil
		}
		currentConfig := node.Annotations[nodeCurrentConfigAnnotation]
		desiredConfig := node.Annotations[nodeDesiredConfigAnnotation]
		if currentConfig == "" || currentConfig != desiredConfig {
			return false, nil
		}
		pool, err := effectiveMachineConfigPoolForNode(node, currentConfig, poolSelections)
		if err != nil {
			return false, err
		}
		target, err := rebootTargetForPool(node.Name, pool, targetMachineConfigLabels)
		if err != nil {
			return false, err
		}
		if _, expected := targets[target]; !expected {
			return false, fmt.Errorf("post-reboot node %q belongs to target %q outside the canonical intent", node.Name, target)
		}
		rendered := renderedConfigs[currentConfig]
		if rendered == nil {
			rendered, err = a.resources.Get(ctx, machineConfigGVR, currentConfig, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return false, nil
			}
			if err != nil {
				return false, fmt.Errorf("read post-reboot node %q current MachineConfig %q: %w", node.Name, currentConfig, err)
			}
			renderedConfigs[currentConfig] = rendered
		}
		if !machineConfigHasRebootMarker(rendered, intent.ID) {
			return false, nil
		}
	}
	return true, nil
}

func (a *Adapter) ensureRebootRecord(ctx context.Context, guard rotation.RotationGuardReference, intent rotation.RebootIntent) (bool, rotation.EffectOutcome, error) {
	client := a.kube.CoreV1().ConfigMaps(cloudCredentialOperatorNamespace)
	name := rebootRecordName(intent.ID)
	current, err := client.Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		record, decodeErr := decodeRebootRecord(current, guard, intent.ID)
		if decodeErr != nil {
			return false, rotation.EffectNotApplied, decodeErr
		}
		if !reflect.DeepEqual(record.Intent, intent) {
			return false, rotation.EffectNotApplied, fmt.Errorf("canonical reboot record %q contains a different intent", name)
		}
		return true, rotation.EffectSubmitted, nil
	}
	if !apierrors.IsNotFound(err) {
		return false, rotation.EffectNotApplied, fmt.Errorf("read canonical reboot record before creation: %w", err)
	}
	currentPlan, err := a.prepareRebootPlan(ctx)
	if err != nil {
		return false, rotation.EffectNotApplied, fmt.Errorf("revalidate reboot plan before recording canonical intent: %w", err)
	}
	if !reflect.DeepEqual(currentPlan.Targets, intent.Targets) || !reflect.DeepEqual(currentPlan.Baselines, intent.Baselines) {
		return false, rotation.EffectNotApplied, fmt.Errorf("current reboot plan differs from the checkpointed intent")
	}

	configMap, err := newRebootRecordConfigMap(guard, intent)
	if err != nil {
		return false, rotation.EffectNotApplied, err
	}
	_, createErr := client.Create(ctx, configMap, metav1.CreateOptions{})
	if createErr == nil {
		return true, rotation.EffectSubmitted, nil
	}
	createOutcome := mutationOutcome(createErr)
	observed, observeErr := client.Get(ctx, name, metav1.GetOptions{})
	if observeErr == nil {
		record, decodeErr := decodeRebootRecord(observed, guard, intent.ID)
		if decodeErr != nil {
			return false, createOutcome, errors.Join(createErr, decodeErr)
		}
		if reflect.DeepEqual(record.Intent, intent) {
			return true, rotation.EffectSubmitted, nil
		}
		return false, createOutcome, errors.Join(createErr, fmt.Errorf("canonical reboot record %q contains a different intent", name))
	}
	return false, createOutcome, errors.Join(createErr, observeErr)
}

func newRebootRecordConfigMap(guard rotation.RotationGuardReference, intent rotation.RebootIntent) (*corev1.ConfigMap, error) {
	record := rebootRecord{SchemaVersion: rebootRecordSchemaVersion, ScopeID: guard.ScopeID, OperationID: guard.OperationID, Intent: cloneRebootIntent(intent)}
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encode canonical reboot record: %w", err)
	}
	if len(encoded) > maxRebootRecordDataBytes {
		return nil, fmt.Errorf("canonical reboot record is too large: %d bytes", len(encoded))
	}
	immutable := true
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: cloudCredentialOperatorNamespace,
			Name:      rebootRecordName(intent.ID),
			Labels:    map[string]string{managedByLabelKey: managedByLabelValue},
			Annotations: map[string]string{
				managedAnnotation:        "true",
				rebootScopeAnnotation:    guard.ScopeID,
				guardOperationAnnotation: guard.OperationID,
				rebootIDAnnotation:       intent.ID,
			},
		},
		Immutable: &immutable,
		Data:      map[string]string{rebootRecordDataKey: string(encoded)},
	}, nil
}

func decodeRebootRecord(configMap *corev1.ConfigMap, guard rotation.RotationGuardReference, operationID string) (rebootRecord, error) {
	var record rebootRecord
	if configMap == nil || configMap.Namespace != cloudCredentialOperatorNamespace || configMap.Name != rebootRecordName(operationID) {
		return record, fmt.Errorf("unexpected canonical reboot record identity")
	}
	if configMap.DeletionTimestamp != nil {
		return record, fmt.Errorf("canonical reboot record %q is being deleted", configMap.Name)
	}
	if configMap.Immutable == nil || !*configMap.Immutable {
		return record, fmt.Errorf("canonical reboot record %q is not immutable", configMap.Name)
	}
	if len(configMap.BinaryData) != 0 || len(configMap.Data) != 1 {
		return record, fmt.Errorf("canonical reboot record %q has unexpected data fields", configMap.Name)
	}
	raw, exists := configMap.Data[rebootRecordDataKey]
	if !exists {
		return record, fmt.Errorf("canonical reboot record %q is missing %q", configMap.Name, rebootRecordDataKey)
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, fmt.Errorf("decode canonical reboot record %q: %w", configMap.Name, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return record, fmt.Errorf("decode canonical reboot record %q: %w", configMap.Name, err)
	}
	if record.SchemaVersion != rebootRecordSchemaVersion {
		return record, fmt.Errorf("unsupported canonical reboot record schema version %d", record.SchemaVersion)
	}
	if record.ScopeID != guard.ScopeID || record.OperationID != guard.OperationID || record.Intent.ID != operationID {
		return record, fmt.Errorf("canonical reboot record %q is bound to different rotation evidence", configMap.Name)
	}
	if err := validateRebootIntent(record.Intent); err != nil {
		return record, fmt.Errorf("invalid canonical reboot record %q: %w", configMap.Name, err)
	}
	return record, nil
}

func (a *Adapter) ensureRebootMachineConfig(ctx context.Context, target, rebootID string) (bool, error) {
	pool, err := a.resources.Get(ctx, machineConfigPoolGVR, target, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("read MachineConfigPool %q: %w", target, err)
	}
	selectorLabels, err := machineConfigSelectorLabels(pool)
	if err != nil {
		return false, err
	}
	name := rebootMachineConfigName(target)
	current, err := a.resources.Get(ctx, machineConfigGVR, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		desired := desiredRebootMachineConfig(nil, name, target, rebootID, selectorLabels)
		_, createErr := a.resources.Create(ctx, machineConfigGVR, desired, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(createErr) {
			return a.ensureRebootMachineConfig(ctx, target, rebootID)
		}
		return createErr == nil, createErr
	}
	if err != nil {
		return false, fmt.Errorf("read reboot MachineConfig %q: %w", name, err)
	}
	currentID, err := validateManagedRebootMachineConfig(current, target, selectorLabels)
	if err != nil {
		return false, err
	}
	if currentID == rebootID {
		return false, nil
	}
	desired := desiredRebootMachineConfig(current, name, target, rebootID, selectorLabels)
	_, updateErr := a.resources.Update(ctx, machineConfigGVR, desired, metav1.UpdateOptions{})
	return updateErr == nil, updateErr
}

func (a *Adapter) validateExistingRebootMachineConfig(ctx context.Context, target string, selectorLabels map[string]string) error {
	name := rebootMachineConfigName(target)
	current, err := a.resources.Get(ctx, machineConfigGVR, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read reserved reboot MachineConfig %q during preflight: %w", name, err)
	}
	if _, err := validateManagedRebootMachineConfig(current, target, selectorLabels); err != nil {
		return fmt.Errorf("validate reserved reboot MachineConfig %q during preflight: %w", name, err)
	}
	return nil
}

func validateManagedRebootMachineConfig(machineConfig *unstructured.Unstructured, target string, selectorLabels map[string]string) (string, error) {
	name := rebootMachineConfigName(target)
	if machineConfig.GetAnnotations()[managedAnnotation] != "true" || machineConfig.GetAnnotations()[rebootTargetAnnotation] != target {
		return "", fmt.Errorf("MachineConfig %q exists without expected rotation ownership", name)
	}
	currentID := machineConfig.GetAnnotations()[rebootIDAnnotation]
	if err := validateRebootID(currentID); err != nil {
		return "", fmt.Errorf("MachineConfig %q has invalid prior reboot identity: %w", name, err)
	}
	if err := validateRebootMachineConfig(machineConfig, target, currentID, selectorLabels); err != nil {
		return "", err
	}
	return currentID, nil
}

func desiredRebootMachineConfig(current *unstructured.Unstructured, name, target, rebootID string, selectorLabels map[string]string) *unstructured.Unstructured {
	object := &unstructured.Unstructured{}
	if current != nil {
		object = current.DeepCopy()
	}
	object.SetAPIVersion("machineconfiguration.openshift.io/v1")
	object.SetKind("MachineConfig")
	object.SetName(name)
	labelsCopy := make(map[string]string, len(selectorLabels)+1)
	for key, value := range selectorLabels {
		labelsCopy[key] = value
	}
	labelsCopy[managedByLabelKey] = managedByLabelValue
	object.SetLabels(labelsCopy)
	object.SetAnnotations(map[string]string{
		managedAnnotation:      "true",
		rebootIDAnnotation:     rebootID,
		rebootTargetAnnotation: target,
	})
	object.Object["spec"] = map[string]any{
		"config": map[string]any{
			"ignition": map[string]any{"version": "3.1.0"},
			"storage": map[string]any{
				"files": []any{map[string]any{
					"path":      rebootMarkerPath,
					"mode":      int64(0644),
					"overwrite": true,
					"contents": map[string]any{
						"source": rebootMarkerSource(rebootID),
					},
				}},
			},
		},
	}
	return object
}

func validateRebootMachineConfig(machineConfig *unstructured.Unstructured, target, rebootID string, selectorLabels map[string]string) error {
	expected := desiredRebootMachineConfig(nil, rebootMachineConfigName(target), target, rebootID, selectorLabels)
	if machineConfig.GetAPIVersion() != expected.GetAPIVersion() || machineConfig.GetKind() != expected.GetKind() || machineConfig.GetName() != expected.GetName() {
		return fmt.Errorf("MachineConfig %q has an unexpected identity for reboot target %q", machineConfig.GetName(), target)
	}
	if !reflect.DeepEqual(machineConfig.GetLabels(), expected.GetLabels()) || !reflect.DeepEqual(machineConfig.GetAnnotations(), expected.GetAnnotations()) {
		return fmt.Errorf("MachineConfig %q does not contain the exact reboot ownership metadata", machineConfig.GetName())
	}
	if !reflect.DeepEqual(machineConfig.Object["spec"], expected.Object["spec"]) {
		return fmt.Errorf("MachineConfig %q does not contain the exact reboot specification", machineConfig.GetName())
	}
	return nil
}

func machineConfigHasRebootMarker(machineConfig *unstructured.Unstructured, rebootID string) bool {
	files, found, err := unstructured.NestedSlice(machineConfig.Object, "spec", "config", "storage", "files")
	if err != nil || !found {
		return false
	}
	for _, item := range files {
		file, ok := item.(map[string]any)
		if !ok || file["path"] != rebootMarkerPath {
			continue
		}
		contents, ok := file["contents"].(map[string]any)
		return ok && contents["source"] == rebootMarkerSource(rebootID)
	}
	return false
}

func machineConfigSelectorLabels(pool *unstructured.Unstructured) (map[string]string, error) {
	selector, found, err := unstructured.NestedMap(pool.Object, "spec", "machineConfigSelector")
	if err != nil || !found {
		return nil, fmt.Errorf("MachineConfigPool %q has no machineConfigSelector", pool.GetName())
	}
	if expressions, exists := selector["matchExpressions"]; exists {
		if items, ok := expressions.([]any); !ok || len(items) != 0 {
			return nil, fmt.Errorf("MachineConfigPool %q uses unsupported machineConfigSelector matchExpressions", pool.GetName())
		}
	}
	labelsValue, exists := selector["matchLabels"]
	if !exists {
		return nil, fmt.Errorf("MachineConfigPool %q has no machineConfigSelector matchLabels", pool.GetName())
	}
	labelsMap, ok := labelsValue.(map[string]any)
	if !ok || len(labelsMap) == 0 {
		return nil, fmt.Errorf("MachineConfigPool %q has invalid machineConfigSelector matchLabels", pool.GetName())
	}
	result := make(map[string]string, len(labelsMap))
	for key, value := range labelsMap {
		text, ok := value.(string)
		if !ok || key == "" || text == "" {
			return nil, fmt.Errorf("MachineConfigPool %q has invalid machineConfigSelector matchLabels", pool.GetName())
		}
		result[key] = text
	}
	return result, nil
}

func machineConfigPoolLabelSelector(pool *unstructured.Unstructured, field string) (labels.Selector, error) {
	selectorMap, found, err := unstructured.NestedMap(pool.Object, "spec", field)
	if err != nil || !found {
		return nil, fmt.Errorf("MachineConfigPool %q has no %s", pool.GetName(), field)
	}
	encoded, err := json.Marshal(selectorMap)
	if err != nil {
		return nil, fmt.Errorf("encode MachineConfigPool %q %s: %w", pool.GetName(), field, err)
	}
	var selectorSpec metav1.LabelSelector
	if err := json.Unmarshal(encoded, &selectorSpec); err != nil {
		return nil, fmt.Errorf("decode MachineConfigPool %q %s: %w", pool.GetName(), field, err)
	}
	selector, err := metav1.LabelSelectorAsSelector(&selectorSpec)
	if err != nil {
		return nil, fmt.Errorf("parse MachineConfigPool %q %s: %w", pool.GetName(), field, err)
	}
	if selector.Empty() {
		return nil, fmt.Errorf("MachineConfigPool %q has an empty %s", pool.GetName(), field)
	}
	return selector, nil
}

func newRebootPoolSelection(pool *unstructured.Unstructured) (rebootPoolSelection, error) {
	nodeSelector, err := machineConfigPoolLabelSelector(pool, "nodeSelector")
	if err != nil {
		return rebootPoolSelection{}, err
	}
	machineConfigSelector, err := machineConfigPoolLabelSelector(pool, "machineConfigSelector")
	if err != nil {
		return rebootPoolSelection{}, err
	}
	currentConfig, found, err := unstructured.NestedString(pool.Object, "status", "configuration", "name")
	if err != nil || !found || currentConfig == "" {
		return rebootPoolSelection{}, fmt.Errorf("MachineConfigPool %q has no current rendered configuration", pool.GetName())
	}
	return rebootPoolSelection{
		pool:                  pool.DeepCopy(),
		nodeSelector:          nodeSelector,
		machineConfigSelector: machineConfigSelector,
		currentConfig:         currentConfig,
	}, nil
}

func rebootTargetMachineConfigLabels(pools *unstructured.UnstructuredList) (map[string]labels.Set, map[string]map[string]string, error) {
	basePools := make(map[string]*unstructured.Unstructured, 2)
	for i := range pools.Items {
		pool := &pools.Items[i]
		if pool.GetName() == "master" || pool.GetName() == "worker" {
			basePools[pool.GetName()] = pool
		}
	}
	machineConfigLabels := make(map[string]labels.Set, 2)
	selectorLabelsByTarget := make(map[string]map[string]string, 2)
	for _, target := range []string{"master", "worker"} {
		pool := basePools[target]
		if pool == nil {
			return nil, nil, fmt.Errorf("required MachineConfigPool %q was not found", target)
		}
		selectorLabels, err := machineConfigSelectorLabels(pool)
		if err != nil {
			return nil, nil, err
		}
		selectorLabelsByTarget[target] = selectorLabels
		labelsForTarget := labels.Set{}
		for key, value := range selectorLabels {
			labelsForTarget[key] = value
		}
		labelsForTarget[managedByLabelKey] = managedByLabelValue
		machineConfigLabels[target] = labelsForTarget
	}
	return machineConfigLabels, selectorLabelsByTarget, nil
}

func effectiveMachineConfigPoolForNode(node *corev1.Node, currentConfig string, pools []rebootPoolSelection) (rebootPoolSelection, error) {
	matches := make([]rebootPoolSelection, 0, 1)
	for _, pool := range pools {
		if pool.currentConfig == currentConfig && pool.nodeSelector.Matches(labels.Set(node.Labels)) {
			matches = append(matches, pool)
		}
	}
	if len(matches) != 1 {
		names := make([]string, 0, len(matches))
		for _, match := range matches {
			names = append(names, match.pool.GetName())
		}
		slices.Sort(names)
		return rebootPoolSelection{}, fmt.Errorf("node %q with current MachineConfig %q resolves to %d MachineConfigPools %v; exactly one is required", node.Name, currentConfig, len(matches), names)
	}
	return matches[0], nil
}

func rebootTargetForPool(nodeName string, pool rebootPoolSelection, targetMachineConfigLabels map[string]labels.Set) (string, error) {
	matches := make([]string, 0, 2)
	for _, target := range []string{"master", "worker"} {
		if pool.machineConfigSelector.Matches(targetMachineConfigLabels[target]) {
			matches = append(matches, target)
		}
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("node %q is managed by MachineConfigPool %q, whose machineConfigSelector matches %d supported reboot targets %v; exactly one of master or worker is required", nodeName, pool.pool.GetName(), len(matches), matches)
	}
	return matches[0], nil
}

func (a *Adapter) affectedMachineConfigPoolsHealthy(ctx context.Context, intent rotation.RebootIntent) (bool, error) {
	pools, err := a.affectedMachineConfigPools(ctx, intent)
	if err != nil {
		return false, err
	}
	for _, pool := range pools {
		paused, _, err := unstructured.NestedBool(pool.Object, "spec", "paused")
		if err != nil {
			return false, err
		}
		degraded, ok := nestedInteger(pool, "status", "degradedMachineCount")
		if paused || !ok || degraded != 0 {
			return false, nil
		}
		conditions, found, err := unstructuredSlice(pool, "status", "conditions")
		if err != nil || !found || conditionStatus(conditions, "Degraded") != string(corev1.ConditionFalse) {
			return false, err
		}
	}
	return true, nil
}

func (a *Adapter) affectedMachineConfigPoolsStable(ctx context.Context, intent rotation.RebootIntent) (bool, error) {
	pools, err := a.affectedMachineConfigPools(ctx, intent)
	if err != nil {
		return false, err
	}
	for _, pool := range pools {
		stable, err := machineConfigPoolStable(pool)
		if err != nil || !stable {
			return false, err
		}
	}
	return true, nil
}

func (a *Adapter) affectedMachineConfigPools(ctx context.Context, intent rotation.RebootIntent) ([]*unstructured.Unstructured, error) {
	machineConfigLabels := make([]labels.Set, 0, len(intent.Targets))
	for _, target := range intent.Targets {
		machineConfig, err := a.resources.Get(ctx, machineConfigGVR, rebootMachineConfigName(target), metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("read reboot MachineConfig for target %q: %w", target, err)
		}
		machineConfigLabels = append(machineConfigLabels, labels.Set(machineConfig.GetLabels()))
	}
	pools, err := a.resources.List(ctx, machineConfigPoolGVR, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list affected MachineConfigPools: %w", err)
	}
	affected := make([]*unstructured.Unstructured, 0, len(pools.Items))
	for i := range pools.Items {
		pool := &pools.Items[i]
		selector, err := machineConfigPoolLabelSelector(pool, "machineConfigSelector")
		if err != nil {
			return nil, err
		}
		for _, machineLabels := range machineConfigLabels {
			if selector.Matches(machineLabels) {
				affected = append(affected, pool.DeepCopy())
				break
			}
		}
	}
	if len(affected) == 0 {
		return nil, fmt.Errorf("no MachineConfigPool selects the reboot MachineConfigs")
	}
	return affected, nil
}

func validateRebootIntent(intent rotation.RebootIntent) error {
	if err := validateRebootID(intent.ID); err != nil {
		return err
	}
	if len(intent.Targets) == 0 || len(intent.Baselines) == 0 {
		return fmt.Errorf("reboot intent must include targets and node baselines")
	}
	targets := make(map[string]struct{}, len(intent.Targets))
	for _, target := range intent.Targets {
		if target != "master" && target != "worker" {
			return fmt.Errorf("unsupported reboot target %q", target)
		}
		if _, duplicate := targets[target]; duplicate {
			return fmt.Errorf("duplicate reboot target %q", target)
		}
		targets[target] = struct{}{}
	}
	counts := make(map[string]int, len(targets))
	nodes := make(map[string]struct{}, len(intent.Baselines))
	for _, baseline := range intent.Baselines {
		if _, exists := targets[baseline.Target]; !exists || baseline.Node == "" || baseline.BootID == "" {
			return fmt.Errorf("invalid reboot baseline for node %q", baseline.Node)
		}
		if _, duplicate := nodes[baseline.Node]; duplicate {
			return fmt.Errorf("duplicate reboot baseline for node %q", baseline.Node)
		}
		nodes[baseline.Node] = struct{}{}
		counts[baseline.Target]++
	}
	for target := range targets {
		if counts[target] == 0 {
			return fmt.Errorf("reboot target %q has no node baseline", target)
		}
	}
	return nil
}

func validateRebootID(operationID string) error {
	const prefix = "signer-rotation-"
	if !strings.HasPrefix(operationID, prefix) {
		return fmt.Errorf("invalid reboot operation ID")
	}
	if err := validateSHA256(strings.TrimPrefix(operationID, prefix)); err != nil {
		return fmt.Errorf("invalid reboot operation ID: %w", err)
	}
	return nil
}

func rebootRecordName(operationID string) string {
	return rebootRecordNamePrefix + strings.TrimPrefix(operationID, "signer-rotation-")
}

func rebootMachineConfigName(target string) string {
	if target == "master" {
		return rebootMachineConfigMaster
	}
	return rebootMachineConfigWorker
}

func rebootMarkerSource(rebootID string) string {
	return "data:," + url.PathEscape(rebootID+"\n")
}

func cloneRebootIntent(intent rotation.RebootIntent) rotation.RebootIntent {
	return rotation.RebootIntent{
		ID:        intent.ID,
		Targets:   append([]string(nil), intent.Targets...),
		Baselines: append([]rotation.NodeRebootBaseline(nil), intent.Baselines...),
	}
}

func nodeReady(node *corev1.Node) bool {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}
