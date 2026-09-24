package rotation

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestOrchestratorRechecksCombinedJWKSBeforePlanningReboot(t *testing.T) {
	harness := newOrchestratorTestHarness(t, PublicationModeDirect)
	cluster := &driftAfterSignerRolloutCluster{
		fakeClusterRotation: harness.cluster,
		publisher:           harness.publisher,
		driftedJWKS:         encodedJWKSForTest(t, testPublicKeyPEM(t)),
	}
	harness.orchestrator.Cluster = cluster

	result, err := harness.orchestrator.Run(context.Background(), RunOptions{
		Provider:        ProviderAWS,
		PublicationMode: PublicationModeDirect,
		OutputDir:       t.TempDir(),
	})
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("Run() error = %v, want ConflictError", err)
	}
	if result.Phase != PhaseCombinedJWKSPublished || result.Complete {
		t.Fatalf("Run() result = %#v, want failure before signer-rollout-stable checkpoint", result)
	}
	if harness.cluster.rebootKeyID != "" || harness.cluster.rebootRequests != 0 {
		t.Fatalf("reboot planning key ID = %q, requests = %d; want no reboot activity", harness.cluster.rebootKeyID, harness.cluster.rebootRequests)
	}
	for _, event := range harness.events {
		if event == "cluster.prepare-reboot" || event == "cluster.request-reboot" || strings.HasPrefix(event, "cluster.observe-reboot:") {
			t.Fatalf("unexpected reboot activity after provider drift: %q", event)
		}
	}
}

type driftAfterSignerRolloutCluster struct {
	*fakeClusterRotation
	publisher   *fakeConditionalJWKSBackend
	driftedJWKS []byte
}

func (cluster *driftAfterSignerRolloutCluster) WaitForSignerRollout(ctx context.Context, guard RotationGuardReference, replacementKeyID string) error {
	if err := cluster.fakeClusterRotation.WaitForSignerRollout(ctx, guard, replacementKeyID); err != nil {
		return err
	}
	cluster.publisher.data = append([]byte(nil), cluster.driftedJWKS...)
	cluster.publisher.revision++
	return nil
}
