package rotation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	rotationGuardScopeDomain     = "signer-rotation-guard-scope-v1"
	rotationGuardOperationDomain = "signer-rotation-guard-operation-v1"
)

type rotationGuardScopePayload struct {
	Domain          string `json:"domain"`
	ClusterIdentity string `json:"clusterIdentity"`
}

type rotationGuardOperationPayload struct {
	Domain                    string                `json:"domain"`
	ClusterIdentity           string                `json:"clusterIdentity"`
	Provider                  Provider              `json:"provider"`
	TargetIdentity            string                `json:"targetIdentity"`
	PreRotationSignerBaseline PublicSignerBaseline  `json:"preRotationSignerBaseline"`
	PreRotationSignerRef      SignerObjectReference `json:"preRotationSignerRef"`
}

func deriveRotationGuardReference(clusterIdentity string, provider Provider, targetIdentity string, baseline PublicSignerBaseline, signerRef SignerObjectReference) (RotationGuardReference, error) {
	if err := validateOpaqueCheckpointValue("cluster identity", clusterIdentity); err != nil {
		return RotationGuardReference{}, err
	}
	if !isSupportedProvider(provider) {
		return RotationGuardReference{}, fmt.Errorf("unsupported rotation provider %q", provider)
	}
	if err := validateOpaqueCheckpointValue("target identity", targetIdentity); err != nil {
		return RotationGuardReference{}, err
	}
	if err := validatePublicSignerBaseline(baseline); err != nil {
		return RotationGuardReference{}, fmt.Errorf("invalid pre-rotation public signer baseline: %w", err)
	}
	if err := validateSignerObjectReference(signerRef); err != nil {
		return RotationGuardReference{}, fmt.Errorf("invalid pre-rotation signer object reference: %w", err)
	}

	scopeID, err := hashRotationGuardPayload(rotationGuardScopePayload{
		Domain:          rotationGuardScopeDomain,
		ClusterIdentity: clusterIdentity,
	})
	if err != nil {
		return RotationGuardReference{}, fmt.Errorf("encode rotation guard scope: %w", err)
	}
	operationID, err := hashRotationGuardPayload(rotationGuardOperationPayload{
		Domain:                    rotationGuardOperationDomain,
		ClusterIdentity:           clusterIdentity,
		Provider:                  provider,
		TargetIdentity:            targetIdentity,
		PreRotationSignerBaseline: clonePublicSignerBaseline(baseline),
		PreRotationSignerRef:      signerRef,
	})
	if err != nil {
		return RotationGuardReference{}, fmt.Errorf("encode rotation guard operation: %w", err)
	}
	return RotationGuardReference{ScopeID: scopeID, OperationID: operationID}, nil
}

func hashRotationGuardPayload(payload any) (string, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validateRotationGuardReference(reference RotationGuardReference) error {
	if err := validateSHA256(reference.ScopeID); err != nil {
		return fmt.Errorf("rotation guard scope ID: %w", err)
	}
	if err := validateSHA256(reference.OperationID); err != nil {
		return fmt.Errorf("rotation guard operation ID: %w", err)
	}
	return nil
}
