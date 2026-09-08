package kubeadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/rotation"
)

const (
	guardConfigMapName = "cco-signer-key-rotation-guard"
	guardStateDataKey  = "state.json"
	guardSchemaVersion = 1

	managedByLabelKey   = "app.kubernetes.io/managed-by"
	managedByLabelValue = "cloud-credential-operator"
)

type guardState struct {
	SchemaVersion         int      `json:"schemaVersion"`
	ScopeID               string   `json:"scopeID"`
	ActiveOperationID     string   `json:"activeOperationID,omitempty"`
	CompletedOperationIDs []string `json:"completedOperationIDs,omitempty"`
}

func (a *Adapter) ObserveRotationGuard(ctx context.Context, reference rotation.RotationGuardReference) (rotation.RotationGuardObservation, error) {
	if err := validateGuardReference(reference); err != nil {
		return rotation.RotationGuardObservation{}, err
	}
	configMap, err := a.kube.CoreV1().ConfigMaps(cloudCredentialOperatorNamespace).Get(ctx, guardConfigMapName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return rotation.RotationGuardObservation{Status: rotation.RotationGuardNotFound}, nil
	}
	if err != nil {
		return rotation.RotationGuardObservation{}, fmt.Errorf("read signer-rotation guard ConfigMap: %w", err)
	}
	state, err := decodeGuardState(configMap, reference.ScopeID)
	if err != nil {
		return rotation.RotationGuardObservation{}, err
	}
	if slices.Contains(state.CompletedOperationIDs, reference.OperationID) {
		return rotation.RotationGuardObservation{Status: rotation.RotationGuardCompleted, OperationID: reference.OperationID}, nil
	}
	switch state.ActiveOperationID {
	case "":
		return rotation.RotationGuardObservation{Status: rotation.RotationGuardNotFound}, nil
	case reference.OperationID:
		return rotation.RotationGuardObservation{Status: rotation.RotationGuardHeld, OperationID: reference.OperationID}, nil
	default:
		return rotation.RotationGuardObservation{Status: rotation.RotationGuardOwnedByOther, OperationID: state.ActiveOperationID}, nil
	}
}

func (a *Adapter) AcquireRotationGuard(ctx context.Context, reference rotation.RotationGuardReference) (rotation.EffectOutcome, error) {
	if err := validateGuardReference(reference); err != nil {
		return rotation.EffectNotApplied, err
	}
	client := a.kube.CoreV1().ConfigMaps(cloudCredentialOperatorNamespace)
	configMap, err := client.Get(ctx, guardConfigMapName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		state := guardState{SchemaVersion: guardSchemaVersion, ScopeID: reference.ScopeID, ActiveOperationID: reference.OperationID}
		created := newGuardConfigMap(state)
		_, createErr := client.Create(ctx, created, metav1.CreateOptions{})
		return mutationOutcome(createErr), createErr
	}
	if err != nil {
		return rotation.EffectNotApplied, fmt.Errorf("read signer-rotation guard before acquisition: %w", err)
	}
	state, err := decodeGuardState(configMap, reference.ScopeID)
	if err != nil {
		return rotation.EffectNotApplied, err
	}
	if slices.Contains(state.CompletedOperationIDs, reference.OperationID) {
		return rotation.EffectNotApplied, fmt.Errorf("signer-rotation operation %q is already completed", reference.OperationID)
	}
	switch state.ActiveOperationID {
	case reference.OperationID:
		return rotation.EffectSubmitted, nil
	case "":
		state.ActiveOperationID = reference.OperationID
	default:
		return rotation.EffectNotApplied, fmt.Errorf("signer-rotation guard is owned by operation %q", state.ActiveOperationID)
	}
	updated, err := guardConfigMapWithState(configMap, state)
	if err != nil {
		return rotation.EffectNotApplied, err
	}
	_, updateErr := client.Update(ctx, updated, metav1.UpdateOptions{})
	return mutationOutcome(updateErr), updateErr
}

func (a *Adapter) ReleaseRotationGuard(ctx context.Context, reference rotation.RotationGuardReference) (rotation.EffectOutcome, error) {
	if err := validateGuardReference(reference); err != nil {
		return rotation.EffectNotApplied, err
	}
	client := a.kube.CoreV1().ConfigMaps(cloudCredentialOperatorNamespace)
	configMap, err := client.Get(ctx, guardConfigMapName, metav1.GetOptions{})
	if err != nil {
		return rotation.EffectNotApplied, fmt.Errorf("read signer-rotation guard before release: %w", err)
	}
	state, err := decodeGuardState(configMap, reference.ScopeID)
	if err != nil {
		return rotation.EffectNotApplied, err
	}
	if slices.Contains(state.CompletedOperationIDs, reference.OperationID) {
		return rotation.EffectSubmitted, nil
	}
	if state.ActiveOperationID != reference.OperationID {
		if state.ActiveOperationID == "" {
			return rotation.EffectNotApplied, fmt.Errorf("signer-rotation guard is not held")
		}
		return rotation.EffectNotApplied, fmt.Errorf("signer-rotation guard is owned by operation %q", state.ActiveOperationID)
	}

	state.ActiveOperationID = ""
	state.CompletedOperationIDs = append(state.CompletedOperationIDs, reference.OperationID)
	slices.Sort(state.CompletedOperationIDs)
	updated, err := guardConfigMapWithState(configMap, state)
	if err != nil {
		return rotation.EffectNotApplied, err
	}
	_, updateErr := client.Update(ctx, updated, metav1.UpdateOptions{})
	return mutationOutcome(updateErr), updateErr
}

func (a *Adapter) requireGuardHeld(ctx context.Context, reference rotation.RotationGuardReference) error {
	observation, err := a.ObserveRotationGuard(ctx, reference)
	if err != nil {
		return err
	}
	if observation.Status != rotation.RotationGuardHeld {
		return fmt.Errorf("signer-rotation guard operation %q is not held: observed %q", reference.OperationID, observation.Status)
	}
	return nil
}

func newGuardConfigMap(state guardState) *corev1.ConfigMap {
	encoded, err := json.Marshal(state)
	if err != nil {
		panic(err)
	}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: cloudCredentialOperatorNamespace,
			Name:      guardConfigMapName,
			Labels:    map[string]string{managedByLabelKey: managedByLabelValue},
		},
		Data: map[string]string{guardStateDataKey: string(encoded)},
	}
}

func guardConfigMapWithState(current *corev1.ConfigMap, state guardState) (*corev1.ConfigMap, error) {
	encoded, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("encode signer-rotation guard state: %w", err)
	}
	updated := current.DeepCopy()
	updated.Data = map[string]string{guardStateDataKey: string(encoded)}
	if updated.Labels == nil {
		updated.Labels = map[string]string{}
	}
	updated.Labels[managedByLabelKey] = managedByLabelValue
	return updated, nil
}

func decodeGuardState(configMap *corev1.ConfigMap, expectedScopeID string) (guardState, error) {
	var state guardState
	if configMap == nil {
		return state, fmt.Errorf("signer-rotation guard ConfigMap is nil")
	}
	if configMap.Namespace != cloudCredentialOperatorNamespace || configMap.Name != guardConfigMapName {
		return state, fmt.Errorf("unexpected signer-rotation guard ConfigMap %q/%q", configMap.Namespace, configMap.Name)
	}
	if configMap.DeletionTimestamp != nil {
		return state, fmt.Errorf("signer-rotation guard ConfigMap is being deleted")
	}
	if len(configMap.BinaryData) != 0 {
		return state, fmt.Errorf("signer-rotation guard ConfigMap contains unsupported binary data")
	}
	if len(configMap.Data) != 1 {
		return state, fmt.Errorf("signer-rotation guard ConfigMap must contain only %q", guardStateDataKey)
	}
	raw, exists := configMap.Data[guardStateDataKey]
	if !exists {
		return state, fmt.Errorf("signer-rotation guard ConfigMap is missing %q", guardStateDataKey)
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return state, fmt.Errorf("decode signer-rotation guard state: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return state, fmt.Errorf("decode signer-rotation guard state: %w", err)
	}
	if state.SchemaVersion != guardSchemaVersion {
		return state, fmt.Errorf("unsupported signer-rotation guard schema version %d", state.SchemaVersion)
	}
	if err := validateSHA256(state.ScopeID); err != nil {
		return state, fmt.Errorf("invalid signer-rotation guard scope: %w", err)
	}
	if state.ScopeID != expectedScopeID {
		return state, fmt.Errorf("signer-rotation guard scope %q does not match expected scope %q", state.ScopeID, expectedScopeID)
	}
	if state.ActiveOperationID != "" {
		if err := validateSHA256(state.ActiveOperationID); err != nil {
			return state, fmt.Errorf("invalid active signer-rotation operation: %w", err)
		}
	}
	completed := make(map[string]struct{}, len(state.CompletedOperationIDs))
	for _, operationID := range state.CompletedOperationIDs {
		if err := validateSHA256(operationID); err != nil {
			return state, fmt.Errorf("invalid completed signer-rotation operation: %w", err)
		}
		if _, duplicate := completed[operationID]; duplicate {
			return state, fmt.Errorf("duplicate completed signer-rotation operation %q", operationID)
		}
		completed[operationID] = struct{}{}
	}
	if _, completedWhileActive := completed[state.ActiveOperationID]; state.ActiveOperationID != "" && completedWhileActive {
		return state, fmt.Errorf("active signer-rotation operation %q is also completed", state.ActiveOperationID)
	}
	return state, nil
}

func validateGuardReference(reference rotation.RotationGuardReference) error {
	if err := validateSHA256(reference.ScopeID); err != nil {
		return fmt.Errorf("invalid signer-rotation guard scope: %w", err)
	}
	if err := validateSHA256(reference.OperationID); err != nil {
		return fmt.Errorf("invalid signer-rotation guard operation: %w", err)
	}
	return nil
}

func validateSHA256(value string) error {
	if len(value) != 64 {
		return fmt.Errorf("must be 64 lowercase hexadecimal characters")
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return fmt.Errorf("must be 64 lowercase hexadecimal characters")
		}
	}
	return nil
}

func isDefinitiveMutationRejection(err error) bool {
	return apierrors.IsAlreadyExists(err) ||
		apierrors.IsConflict(err) ||
		apierrors.IsInvalid(err) ||
		apierrors.IsBadRequest(err) ||
		apierrors.IsForbidden(err) ||
		apierrors.IsUnauthorized(err) ||
		apierrors.IsNotFound(err) ||
		apierrors.IsMethodNotSupported(err)
}
