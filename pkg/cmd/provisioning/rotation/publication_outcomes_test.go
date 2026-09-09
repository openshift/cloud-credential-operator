package rotation

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPublishDirectRejectsBlankRevisionWithoutPublishing(t *testing.T) {
	predecessor := StoredArtifact{Data: []byte("predecessor")}
	desired := StoredArtifact{Data: []byte("desired")}
	publisher := &safetyPublisher{
		state: VersionedJWKS{Data: append([]byte(nil), predecessor.Data...), Revision: "7"},
		reads: []VersionedJWKS{{Data: predecessor.Data, Revision: " \t"}},
	}
	orchestrator := Orchestrator{Publisher: publisher}

	err := orchestrator.publishDirect(context.Background(), Checkpoint{
		Phase:          PhaseCombinedJWKSBuilt,
		TargetIdentity: "target",
	}, desired, predecessor)
	if err == nil || !strings.Contains(err.Error(), "did not return the revision required for conditional publication") {
		t.Fatalf("publishDirect() error = %v, want missing-revision error", err)
	}
	if publisher.publishCalls != 0 {
		t.Fatalf("conditional publication calls = %d, want zero", publisher.publishCalls)
	}
	if !bytes.Equal(publisher.state.Data, predecessor.Data) {
		t.Fatalf("provider state = %q, want unchanged predecessor %q", publisher.state.Data, predecessor.Data)
	}
}

func TestPublishDirectClassifiesRejectedConditionalPublication(t *testing.T) {
	predecessor := StoredArtifact{Data: []byte("predecessor")}
	desired := StoredArtifact{Data: []byte("desired")}
	checkpoint := Checkpoint{Phase: PhaseCombinedJWKSBuilt, TargetIdentity: "target"}
	publishErr := errors.New("conditional revision no longer matches")

	t.Run("publish error is preserved", func(t *testing.T) {
		publisher := &safetyPublisher{
			state:          VersionedJWKS{Data: append([]byte(nil), predecessor.Data...), Revision: "7"},
			publishOutcome: EffectNotApplied,
			publishErr:     publishErr,
		}
		orchestrator := Orchestrator{Publisher: publisher}

		err := orchestrator.publishDirect(context.Background(), checkpoint, desired, predecessor)
		if !errors.Is(err, publishErr) || !strings.Contains(err.Error(), "was not applied") {
			t.Fatalf("publishDirect() error = %v, want wrapped rejection error", err)
		}
		assertConditionalPublicationDidNotOverwrite(t, publisher, predecessor, 1)
	})

	t.Run("readback error is reported", func(t *testing.T) {
		publisher := &safetyPublisher{
			state:          VersionedJWKS{Data: append([]byte(nil), predecessor.Data...), Revision: "7"},
			failReadNumber: 2,
			publishOutcome: EffectNotApplied,
		}
		orchestrator := Orchestrator{Publisher: publisher}

		err := orchestrator.publishDirect(context.Background(), checkpoint, desired, predecessor)
		if err == nil || !strings.Contains(err.Error(), "read provider JWKS after rejected conditional publication") {
			t.Fatalf("publishDirect() error = %v, want rejected-publication readback error", err)
		}
		assertConditionalPublicationDidNotOverwrite(t, publisher, predecessor, 1)
	})

	t.Run("unexpected readback is a conflict", func(t *testing.T) {
		publisher := &safetyPublisher{
			state: VersionedJWKS{Data: append([]byte(nil), predecessor.Data...), Revision: "7"},
			reads: []VersionedJWKS{
				{Data: predecessor.Data, Revision: "7"},
				{Data: []byte("changed-by-another-writer"), Revision: "8"},
			},
			publishOutcome: EffectNotApplied,
		}
		orchestrator := Orchestrator{Publisher: publisher}

		err := orchestrator.publishDirect(context.Background(), checkpoint, desired, predecessor)
		var conflict *ConflictError
		if !errors.As(err, &conflict) {
			t.Fatalf("publishDirect() error = %v, want ConflictError", err)
		}
		if conflict.Phase != checkpoint.Phase {
			t.Fatalf("ConflictError phase = %q, want %q", conflict.Phase, checkpoint.Phase)
		}
		assertConditionalPublicationDidNotOverwrite(t, publisher, predecessor, 1)
	})
}

func TestPublishDirectTreatsUnconfirmedSubmissionAsUnknown(t *testing.T) {
	predecessor := StoredArtifact{Data: []byte("predecessor")}
	desired := StoredArtifact{Data: []byte("desired")}
	checkpoint := Checkpoint{Phase: PhaseCombinedJWKSBuilt, TargetIdentity: "target"}

	for _, outcome := range []EffectOutcome{EffectUnknown, EffectSubmitted} {
		t.Run(string(outcome), func(t *testing.T) {
			publisher := &safetyPublisher{
				state: VersionedJWKS{Data: append([]byte(nil), predecessor.Data...), Revision: "7"},
				reads: []VersionedJWKS{
					{Data: predecessor.Data, Revision: "7"},
					{Data: []byte("unexpected-readback"), Revision: "8"},
				},
				publishOutcome: outcome,
			}
			orchestrator := Orchestrator{Publisher: publisher}

			err := orchestrator.publishDirect(context.Background(), checkpoint, desired, predecessor)
			var unknown *OutcomeUnknownError
			if !errors.As(err, &unknown) {
				t.Fatalf("publishDirect() error = %v, want OutcomeUnknownError", err)
			}
			if unknown.Phase != checkpoint.Phase || unknown.Operation != "conditionally publish provider JWKS" {
				t.Fatalf("OutcomeUnknownError = %#v, want phase %q and conditional publication operation", unknown, checkpoint.Phase)
			}
			assertConditionalPublicationDidNotOverwrite(t, publisher, predecessor, 1)
		})
	}
}

func TestPublishDirectDoesNotRepeatConfirmedSubmission(t *testing.T) {
	predecessor := StoredArtifact{Data: []byte("predecessor")}
	desired := StoredArtifact{Data: []byte("desired")}
	checkpoint := Checkpoint{Phase: PhaseCombinedJWKSBuilt, TargetIdentity: "target"}

	for _, outcome := range []EffectOutcome{EffectUnknown, EffectSubmitted} {
		t.Run(string(outcome), func(t *testing.T) {
			publisher := &safetyPublisher{
				state:            VersionedJWKS{Data: append([]byte(nil), predecessor.Data...), Revision: "7"},
				publishOutcome:   outcome,
				applyPublication: true,
			}
			orchestrator := Orchestrator{Publisher: publisher}

			if err := orchestrator.publishDirect(context.Background(), checkpoint, desired, predecessor); err != nil {
				t.Fatalf("first publishDirect() error = %v", err)
			}
			if err := orchestrator.publishDirect(context.Background(), checkpoint, desired, predecessor); err != nil {
				t.Fatalf("second publishDirect() error = %v", err)
			}
			if publisher.publishCalls != 1 {
				t.Fatalf("conditional publication calls = %d, want one after confirmed retry", publisher.publishCalls)
			}
			if !bytes.Equal(publisher.state.Data, desired.Data) {
				t.Fatalf("provider state = %q, want desired data %q", publisher.state.Data, desired.Data)
			}
		})
	}
}

func assertConditionalPublicationDidNotOverwrite(t *testing.T, publisher *safetyPublisher, predecessor StoredArtifact, wantCalls int) {
	t.Helper()
	if publisher.publishCalls != wantCalls {
		t.Fatalf("conditional publication calls = %d, want %d", publisher.publishCalls, wantCalls)
	}
	if !bytes.Equal(publisher.state.Data, predecessor.Data) {
		t.Fatalf("provider state = %q, want unchanged predecessor %q", publisher.state.Data, predecessor.Data)
	}
}
