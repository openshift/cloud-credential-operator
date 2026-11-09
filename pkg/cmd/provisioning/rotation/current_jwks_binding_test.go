package rotation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateArtifactRelationshipsBindsCurrentJWKSToPreRotationSignerBaseline(t *testing.T) {
	expectedPublicKey := testPublicKeyPEM(t)
	secondPublicKey := testPublicKeyPEM(t)
	baseline := testSignerBaselineForPublicKeys(t, expectedPublicKey, secondPublicKey)
	matchingCurrent := encodedJWKSForTest(t, expectedPublicKey)
	matchingCombined, err := PrepareJWKSArtifacts(matchingCurrent, secondPublicKey)
	if err != nil {
		t.Fatalf("prepare matching multi-key JWKS: %v", err)
	}
	unrelatedCurrent := encodedJWKSForTest(t, testPublicKeyPEM(t))

	tests := []struct {
		name       string
		checkpoint Checkpoint
		current    []byte
		wantError  string
	}{
		{
			name:       "matching current key",
			checkpoint: Checkpoint{PreRotationSignerBaseline: baseline},
			current:    matchingCurrent,
		},
		{
			name:       "every current key belongs to baseline",
			checkpoint: Checkpoint{PreRotationSignerBaseline: baseline},
			current:    matchingCombined.Combined.Data,
		},
		{
			name:       "unrelated current key",
			checkpoint: Checkpoint{PreRotationSignerBaseline: baseline},
			current:    unrelatedCurrent,
			wantError:  "is not present in the pre-rotation public signer baseline",
		},
		{
			name:       "standalone artifact without preflight identity",
			checkpoint: Checkpoint{},
			current:    unrelatedCurrent,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateArtifactRelationships(test.checkpoint, map[string][]byte{
				ArtifactCurrentJWKS: test.current,
			})
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("validateArtifactRelationships() returned unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("validateArtifactRelationships() error = %v, want error containing %q", err, test.wantError)
			}
		})
	}
}

func TestOrchestratorRejectsCurrentJWKSOutsidePreRotationBaselineBeforeReplacement(t *testing.T) {
	for _, mode := range []PublicationMode{PublicationModeDirect, PublicationModeManual} {
		t.Run(string(mode), func(t *testing.T) {
			initial := safetySigner(testPublicKeyPEM(t), "old-uid", "10")
			replacement := safetySigner(testPublicKeyPEM(t), "new-uid", "11")
			cluster := newSafetyCluster(initial, replacement)
			currentJWKS := encodedJWKSForTest(t, testPublicKeyPEM(t))
			orchestrator := Orchestrator{
				Cluster: cluster,
				Target:  safetyTarget("issuer-target"),
			}
			if mode == PublicationModeDirect {
				orchestrator.Publisher = newSafetyPublisher(currentJWKS)
			}

			outputDir := filepath.Join(t.TempDir(), "rotation")
			options := RunOptions{
				Provider:        ProviderAWS,
				PublicationMode: mode,
				OutputDir:       outputDir,
			}
			if mode == PublicationModeManual {
				result, err := orchestrator.Run(context.Background(), options)
				var pause *PauseError
				if !errors.As(err, &pause) || pause.Reason != PauseForCurrentJWKS || result.Phase != PhaseGuardAcquired {
					t.Fatalf("initial manual Run() result = %#v, error = %v; want current-JWKS pause after preflight", result, err)
				}
				options.Resume = true
				options.Manual.CurrentJWKS = currentJWKS
			}

			result, err := orchestrator.Run(context.Background(), options)
			if err == nil || !strings.Contains(err.Error(), "is not present in the pre-rotation public signer baseline") {
				t.Fatalf("Run() error = %v, want current-JWKS identity mismatch", err)
			}
			if result.Phase != PhaseGuardAcquired || result.Complete {
				t.Fatalf("Run() result = %#v, want failure at guard-acquired", result)
			}
			if cluster.replacementRequests != 0 {
				t.Fatalf("replacement requests = %d, want zero", cluster.replacementRequests)
			}
			if _, err := os.Stat(filepath.Join(outputDir, ArtifactCurrentJWKS)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("mismatched current JWKS was persisted, stat error = %v", err)
			}
		})
	}
}
