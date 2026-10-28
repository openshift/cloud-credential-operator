package rotation

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
)

func buildRebootIntent(clusterIdentity, replacementKeyID string, plan RebootPlan) (RebootIntent, error) {
	targets := append([]string(nil), plan.Targets...)
	slices.Sort(targets)
	baselines := append([]NodeRebootBaseline(nil), plan.Baselines...)
	slices.SortFunc(baselines, func(left, right NodeRebootBaseline) int {
		if comparison := strings.Compare(left.Target, right.Target); comparison != 0 {
			return comparison
		}
		if comparison := strings.Compare(left.Node, right.Node); comparison != 0 {
			return comparison
		}
		return strings.Compare(left.BootID, right.BootID)
	})

	intentID, err := rebootIntentID(clusterIdentity, replacementKeyID)
	if err != nil {
		return RebootIntent{}, err
	}
	intent := RebootIntent{ID: intentID, Targets: targets, Baselines: baselines}
	if err := validateRebootIntent(intent); err != nil {
		return RebootIntent{}, err
	}
	return intent, nil
}

func rebootIntentID(clusterIdentity, replacementKeyID string) (string, error) {
	if err := validateOpaqueCheckpointValue("cluster identity", clusterIdentity); err != nil {
		return "", err
	}
	if err := validateDerivedKeyID(replacementKeyID); err != nil {
		return "", fmt.Errorf("invalid replacement key identity: %w", err)
	}

	digest := sha256.New()
	writePart := func(value string) {
		_, _ = fmt.Fprintf(digest, "%d:%s", len(value), value)
	}
	writePart("signer-rotation-reboot-v1")
	writePart(clusterIdentity)
	writePart(replacementKeyID)
	return fmt.Sprintf("signer-rotation-%x", digest.Sum(nil)), nil
}
