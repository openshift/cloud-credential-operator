package rotation

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestOrchestratorRechecksCurrentJWKSBeforeReplacementMutation(t *testing.T) {
	tests := []struct {
		name         string
		readError    error
		wantConflict bool
	}{
		{name: "provider drift", wantConflict: true},
		{name: "provider read failure", readError: errors.New("current JWKS read unavailable")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newOrchestratorTestHarness(t, PublicationModeDirect)
			publisher := &currentRecheckPublisher{
				fakeConditionalJWKSBackend: harness.publisher,
				failReadNumber:             2,
				readError:                  test.readError,
			}
			if test.wantConflict {
				publisher.driftedJWKS = encodedJWKSForTest(t, testPublicKeyPEM(t))
			}
			harness.orchestrator.Publisher = publisher

			result, err := harness.orchestrator.Run(context.Background(), RunOptions{
				Provider:        ProviderAWS,
				PublicationMode: PublicationModeDirect,
				OutputDir:       t.TempDir(),
			})
			if test.wantConflict {
				var conflict *ConflictError
				if !errors.As(err, &conflict) {
					t.Fatalf("Run() error = %v, want ConflictError", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.readError.Error()) {
				t.Fatalf("Run() error = %v, want provider read failure", err)
			}
			if result.Phase != PhaseCurrentJWKSRead || result.Complete {
				t.Fatalf("Run() result = %#v, want failure at current-jwks-read", result)
			}
			if harness.cluster.replacementRequests != 0 {
				t.Fatalf("replacement requests = %d, want zero", harness.cluster.replacementRequests)
			}
			if got := countRotationEvent(harness.events, "cluster.observe-public-signer-bundle"); got != 3 {
				t.Fatalf("public signer bundle observations = %d, want preflight, post-acquisition, and one convergence observation", got)
			}
			if got := countRotationEvent(harness.events, "cluster.request-replacement"); got != 0 {
				t.Fatalf("replacement request events = %d, want zero", got)
			}
		})
	}
}

func TestOrchestratorDoesNotRequireCurrentRecheckWhenSignerAlreadyChanged(t *testing.T) {
	harness := newOrchestratorTestHarness(t, PublicationModeDirect)
	harness.cluster.applyReplacementAt = 2
	publisher := &currentRecheckPublisher{
		fakeConditionalJWKSBackend: harness.publisher,
		failReadNumber:             2,
		readError:                  errors.New("publication predecessor read unavailable"),
	}
	harness.orchestrator.Publisher = publisher

	result, err := harness.orchestrator.Run(context.Background(), RunOptions{
		Provider:        ProviderAWS,
		PublicationMode: PublicationModeDirect,
		OutputDir:       t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "before conditional publication") {
		t.Fatalf("Run() error = %v, want failure at later combined publication", err)
	}
	if result.Phase != PhaseCombinedJWKSBuilt || result.Complete {
		t.Fatalf("Run() result = %#v, want progress through replacement capture without a new mutation", result)
	}
	if harness.cluster.replacementRequests != 0 {
		t.Fatalf("replacement requests = %d, want zero", harness.cluster.replacementRequests)
	}
}

type currentRecheckPublisher struct {
	*fakeConditionalJWKSBackend
	reads          int
	failReadNumber int
	driftedJWKS    []byte
	readError      error
}

func (publisher *currentRecheckPublisher) ReadJWKS(ctx context.Context, target string) (VersionedJWKS, error) {
	publisher.reads++
	if publisher.reads == publisher.failReadNumber {
		if publisher.readError != nil {
			*publisher.events = append(*publisher.events, "publisher.read:error")
			return VersionedJWKS{}, publisher.readError
		}
		publisher.data = append([]byte(nil), publisher.driftedJWKS...)
		publisher.revision++
	}
	return publisher.fakeConditionalJWKSBackend.ReadJWKS(ctx, target)
}

func countRotationEvent(events []string, want string) int {
	count := 0
	for _, event := range events {
		if event == want {
			count++
		}
	}
	return count
}
