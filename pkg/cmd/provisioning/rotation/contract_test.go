package rotation

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const (
	testDigest            = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testReplacementDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testOldKeyID          = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testOtherKeyID        = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
)

func TestCheckpointValidate(t *testing.T) {
	tests := []struct {
		name       string
		checkpoint Checkpoint
		wantError  string
	}{
		{
			name:       "valid direct checkpoint",
			checkpoint: NewCheckpoint(ProviderAWS, PublicationModeDirect, "rotation-output"),
		},
		{
			name: "valid manual checkpoint with public artifacts",
			checkpoint: Checkpoint{
				SchemaVersion:             CheckpointSchemaVersion,
				Provider:                  ProviderAzure,
				PublicationMode:           PublicationModeManual,
				Phase:                     PhaseCombinedJWKSBuilt,
				OutputDir:                 "rotation-output",
				ClusterIdentity:           "cluster-123",
				TargetIdentity:            "azure://account/container/openid/v1/jwks",
				PreRotationSignerBaseline: testSignerBaseline(),
				PreRotationSignerRef:      testSignerObjectReference(),
				RotationGuard:             testRotationGuard(ProviderAzure, "cluster-123", "azure://account/container/openid/v1/jwks", testSignerBaseline(), testSignerObjectReference()),
				ReplacementSigner:         testReplacementSignerEvidence(),
				Artifacts: []ArtifactMetadata{
					{Name: ArtifactReplacementPublicKey, SHA256: testReplacementDigest, KeyIDs: []string{testOtherKeyID}},
					{Name: ArtifactCurrentJWKS, SHA256: testDigest, KeyIDs: []string{testOldKeyID}},
					{Name: ArtifactNewJWKS, SHA256: testDigest, KeyIDs: []string{testOtherKeyID}},
					{Name: ArtifactCombinedJWKS, SHA256: testDigest, KeyIDs: []string{testOldKeyID, testOtherKeyID}},
				},
			},
		},
		{
			name: "unsupported schema",
			checkpoint: Checkpoint{
				SchemaVersion:   CheckpointSchemaVersion + 1,
				Provider:        ProviderAWS,
				PublicationMode: PublicationModeDirect,
				Phase:           PhaseInitialized,
				OutputDir:       "rotation-output",
			},
			wantError: "unsupported rotation checkpoint schema version",
		},
		{
			name: "unsupported provider",
			checkpoint: Checkpoint{
				SchemaVersion:   CheckpointSchemaVersion,
				Provider:        "openstack",
				PublicationMode: PublicationModeDirect,
				Phase:           PhaseInitialized,
				OutputDir:       "rotation-output",
			},
			wantError: "unsupported rotation provider",
		},
		{
			name: "unsupported publication mode",
			checkpoint: Checkpoint{
				SchemaVersion:   CheckpointSchemaVersion,
				Provider:        ProviderGCP,
				PublicationMode: "automatic",
				Phase:           PhaseInitialized,
				OutputDir:       "rotation-output",
			},
			wantError: "unsupported rotation publication mode",
		},
		{
			name: "unsupported phase",
			checkpoint: Checkpoint{
				SchemaVersion:   CheckpointSchemaVersion,
				Provider:        ProviderAWS,
				PublicationMode: PublicationModeDirect,
				Phase:           "final-jwks-published-early",
				OutputDir:       "rotation-output",
			},
			wantError: "unsupported rotation phase",
		},
		{
			name: "missing output directory",
			checkpoint: Checkpoint{
				SchemaVersion:   CheckpointSchemaVersion,
				Provider:        ProviderAWS,
				PublicationMode: PublicationModeDirect,
				Phase:           PhaseInitialized,
			},
			wantError: "rotation output directory must not be empty",
		},
		{
			name: "private key artifact",
			checkpoint: Checkpoint{
				SchemaVersion:   CheckpointSchemaVersion,
				Provider:        ProviderAWS,
				PublicationMode: PublicationModeDirect,
				Phase:           PhaseNextPublicKeyRead,
				OutputDir:       "rotation-output",
				TargetIdentity:  "aws://issuer",
				Artifacts:       []ArtifactMetadata{{Name: "serviceaccount-signer.private"}},
			},
			wantError: "unsupported rotation artifact",
		},
		{
			name: "private key extension",
			checkpoint: Checkpoint{
				SchemaVersion:   CheckpointSchemaVersion,
				Provider:        ProviderAWS,
				PublicationMode: PublicationModeDirect,
				Phase:           PhaseNextPublicKeyRead,
				OutputDir:       "rotation-output",
				TargetIdentity:  "aws://issuer",
				Artifacts:       []ArtifactMetadata{{Name: "signer.key"}},
			},
			wantError: "unsupported rotation artifact",
		},
		{
			name: "artifact outside output directory",
			checkpoint: Checkpoint{
				SchemaVersion:   CheckpointSchemaVersion,
				Provider:        ProviderAWS,
				PublicationMode: PublicationModeDirect,
				Phase:           PhaseCurrentJWKSRead,
				OutputDir:       "rotation-output",
				TargetIdentity:  "aws://issuer",
				Artifacts:       []ArtifactMetadata{{Name: "../jwks.current.json"}},
			},
			wantError: "unsupported rotation artifact",
		},
		{
			name: "windows path outside output directory",
			checkpoint: Checkpoint{
				SchemaVersion:   CheckpointSchemaVersion,
				Provider:        ProviderAWS,
				PublicationMode: PublicationModeDirect,
				Phase:           PhaseCurrentJWKSRead,
				OutputDir:       "rotation-output",
				TargetIdentity:  "aws://issuer",
				Artifacts:       []ArtifactMetadata{{Name: `..\\jwks.current.json`}},
			},
			wantError: "unsupported rotation artifact",
		},
		{
			name: "parent directory artifact",
			checkpoint: Checkpoint{
				SchemaVersion:   CheckpointSchemaVersion,
				Provider:        ProviderAWS,
				PublicationMode: PublicationModeDirect,
				Phase:           PhaseCurrentJWKSRead,
				OutputDir:       "rotation-output",
				TargetIdentity:  "aws://issuer",
				Artifacts:       []ArtifactMetadata{{Name: ".."}},
			},
			wantError: "unsupported rotation artifact",
		},
		{
			name: "unrecognized public artifact",
			checkpoint: Checkpoint{
				SchemaVersion:   CheckpointSchemaVersion,
				Provider:        ProviderAWS,
				PublicationMode: PublicationModeDirect,
				Phase:           PhaseCurrentJWKSRead,
				OutputDir:       "rotation-output",
				TargetIdentity:  "aws://issuer",
				Artifacts:       []ArtifactMetadata{{Name: "signer.pem", SHA256: testDigest}},
			},
			wantError: "unsupported rotation artifact",
		},
		{
			name: "invalid artifact digest",
			checkpoint: Checkpoint{
				SchemaVersion:   CheckpointSchemaVersion,
				Provider:        ProviderAWS,
				PublicationMode: PublicationModeDirect,
				Phase:           PhaseCurrentJWKSRead,
				OutputDir:       "rotation-output",
				TargetIdentity:  "aws://issuer",
				Artifacts:       []ArtifactMetadata{{Name: ArtifactCurrentJWKS, SHA256: "not-a-digest"}},
			},
			wantError: "SHA-256 digest",
		},
		{
			name: "duplicate artifact",
			checkpoint: Checkpoint{
				SchemaVersion:   CheckpointSchemaVersion,
				Provider:        ProviderAWS,
				PublicationMode: PublicationModeDirect,
				Phase:           PhaseCurrentJWKSRead,
				OutputDir:       "rotation-output",
				TargetIdentity:  "aws://issuer",
				Artifacts: []ArtifactMetadata{
					{Name: ArtifactCurrentJWKS, SHA256: testDigest, KeyIDs: []string{"old"}},
					{Name: ArtifactCurrentJWKS, SHA256: testDigest, KeyIDs: []string{"old"}},
				},
			},
			wantError: "duplicate rotation artifact",
		},
		{
			name: "missing cluster identity after preflight",
			checkpoint: Checkpoint{
				SchemaVersion:   CheckpointSchemaVersion,
				Provider:        ProviderGCP,
				PublicationMode: PublicationModeDirect,
				Phase:           PhasePreflightComplete,
				OutputDir:       "rotation-output",
				TargetIdentity:  "gcp://bucket/keys.json",
			},
			wantError: "cluster identity must be recorded",
		},
		{
			name: "missing target after preflight",
			checkpoint: Checkpoint{
				SchemaVersion:   CheckpointSchemaVersion,
				Provider:        ProviderGCP,
				PublicationMode: PublicationModeDirect,
				Phase:           PhasePreflightComplete,
				OutputDir:       "rotation-output",
				ClusterIdentity: "cluster-123",
			},
			wantError: "target identity must be recorded",
		},
		{
			name: "missing pre-rotation public signer baseline after preflight",
			checkpoint: Checkpoint{
				SchemaVersion:   CheckpointSchemaVersion,
				Provider:        ProviderGCP,
				PublicationMode: PublicationModeDirect,
				Phase:           PhasePreflightComplete,
				OutputDir:       "rotation-output",
				ClusterIdentity: "cluster-123",
				TargetIdentity:  "gcp://bucket/keys.json",
			},
			wantError: "public signer baseline must be recorded",
		},
		{
			name: "pre-rotation public signer baseline with invalid entry name",
			checkpoint: Checkpoint{
				SchemaVersion:             CheckpointSchemaVersion,
				Provider:                  ProviderGCP,
				PublicationMode:           PublicationModeDirect,
				Phase:                     PhasePreflightComplete,
				OutputDir:                 "rotation-output",
				ClusterIdentity:           "cluster-123",
				TargetIdentity:            "gcp://bucket/keys.json",
				PreRotationSignerBaseline: testSignerBaselineWithEntry(PublicSignerBaselineEntry{Name: " service-account-001.pub", SHA256: testDigest, KeyID: testOldKeyID}),
				PreRotationSignerRef:      testSignerObjectReference(),
			},
			wantError: "entry name",
		},
		{
			name: "malformed pre-rotation signer key identity",
			checkpoint: Checkpoint{
				SchemaVersion:             CheckpointSchemaVersion,
				Provider:                  ProviderGCP,
				PublicationMode:           PublicationModeDirect,
				Phase:                     PhasePreflightComplete,
				OutputDir:                 "rotation-output",
				ClusterIdentity:           "cluster-123",
				TargetIdentity:            "gcp://bucket/keys.json",
				PreRotationSignerBaseline: testSignerBaselineWithEntry(PublicSignerBaselineEntry{Name: "service-account-001.pub", SHA256: testDigest, KeyID: "not-a-derived-key-id"}),
				PreRotationSignerRef:      testSignerObjectReference(),
			},
			wantError: "base64url-encoded SHA-256",
		},
		{
			name: "identity evidence before preflight",
			checkpoint: Checkpoint{
				SchemaVersion:   CheckpointSchemaVersion,
				Provider:        ProviderGCP,
				PublicationMode: PublicationModeDirect,
				Phase:           PhaseInitialized,
				OutputDir:       "rotation-output",
				ClusterIdentity: "cluster-123",
			},
			wantError: "must not be recorded before preflight",
		},
		{
			name: "missing pre-rotation signer reference after preflight",
			checkpoint: Checkpoint{
				SchemaVersion:             CheckpointSchemaVersion,
				Provider:                  ProviderGCP,
				PublicationMode:           PublicationModeDirect,
				Phase:                     PhasePreflightComplete,
				OutputDir:                 "rotation-output",
				ClusterIdentity:           "cluster-123",
				TargetIdentity:            "gcp://bucket/keys.json",
				PreRotationSignerBaseline: testSignerBaseline(),
			},
			wantError: "signer object reference must be recorded",
		},
		{
			name: "invalid pre-rotation signer UID",
			checkpoint: Checkpoint{
				SchemaVersion:             CheckpointSchemaVersion,
				Provider:                  ProviderGCP,
				PublicationMode:           PublicationModeDirect,
				Phase:                     PhasePreflightComplete,
				OutputDir:                 "rotation-output",
				ClusterIdentity:           "cluster-123",
				TargetIdentity:            "gcp://bucket/keys.json",
				PreRotationSignerBaseline: testSignerBaseline(),
				PreRotationSignerRef: &SignerObjectReference{
					UID:             " signer-uid",
					ResourceVersion: "12345",
				},
			},
			wantError: "signer UID must not contain surrounding whitespace",
		},
		{
			name: "invalid pre-rotation signer resource version",
			checkpoint: Checkpoint{
				SchemaVersion:             CheckpointSchemaVersion,
				Provider:                  ProviderGCP,
				PublicationMode:           PublicationModeDirect,
				Phase:                     PhasePreflightComplete,
				OutputDir:                 "rotation-output",
				ClusterIdentity:           "cluster-123",
				TargetIdentity:            "gcp://bucket/keys.json",
				PreRotationSignerBaseline: testSignerBaseline(),
				PreRotationSignerRef: &SignerObjectReference{
					UID: "signer-uid",
				},
			},
			wantError: "signer resource version must not be empty",
		},
		{
			name: "missing rotation guard after preflight",
			checkpoint: Checkpoint{
				SchemaVersion:             CheckpointSchemaVersion,
				Provider:                  ProviderAWS,
				PublicationMode:           PublicationModeDirect,
				Phase:                     PhasePreflightComplete,
				OutputDir:                 "rotation-output",
				ClusterIdentity:           "cluster-123",
				TargetIdentity:            "aws://issuer",
				PreRotationSignerBaseline: testSignerBaseline(),
				PreRotationSignerRef:      testSignerObjectReference(),
			},
			wantError: "rotation guard reference must be recorded",
		},
		{
			name: "rotation guard does not match preflight evidence",
			checkpoint: Checkpoint{
				SchemaVersion:             CheckpointSchemaVersion,
				Provider:                  ProviderAWS,
				PublicationMode:           PublicationModeDirect,
				Phase:                     PhasePreflightComplete,
				OutputDir:                 "rotation-output",
				ClusterIdentity:           "cluster-123",
				TargetIdentity:            "aws://issuer",
				PreRotationSignerBaseline: testSignerBaseline(),
				PreRotationSignerRef:      testSignerObjectReference(),
				RotationGuard: &RotationGuardReference{
					ScopeID:     strings.Repeat("1", 64),
					OperationID: strings.Repeat("2", 64),
				},
			},
			wantError: "does not match the recorded preflight evidence",
		},
		{
			name: "complete phase missing required artifacts",
			checkpoint: Checkpoint{
				SchemaVersion:             CheckpointSchemaVersion,
				Provider:                  ProviderAWS,
				PublicationMode:           PublicationModeDirect,
				Phase:                     PhaseComplete,
				OutputDir:                 "rotation-output",
				ClusterIdentity:           "cluster-123",
				TargetIdentity:            "aws://issuer",
				PreRotationSignerBaseline: testSignerBaseline(),
				PreRotationSignerRef:      testSignerObjectReference(),
				RotationGuard:             testRotationGuard(ProviderAWS, "cluster-123", "aws://issuer", testSignerBaseline(), testSignerObjectReference()),
				ReplacementSigner:         testReplacementSignerEvidence(),
				RebootIntent:              testNodeRebootIntent(),
			},
			wantError: "requires artifact",
		},
		{
			name: "combined publication missing confirmation",
			checkpoint: Checkpoint{
				SchemaVersion:             CheckpointSchemaVersion,
				Provider:                  ProviderAWS,
				PublicationMode:           PublicationModeManual,
				Phase:                     PhaseCombinedJWKSPublished,
				OutputDir:                 "rotation-output",
				ClusterIdentity:           "cluster-123",
				TargetIdentity:            "aws://issuer",
				PreRotationSignerBaseline: testSignerBaseline(),
				PreRotationSignerRef:      testSignerObjectReference(),
				RotationGuard:             testRotationGuard(ProviderAWS, "cluster-123", "aws://issuer", testSignerBaseline(), testSignerObjectReference()),
				ReplacementSigner:         testReplacementSignerEvidence(),
				Artifacts:                 allTestArtifacts(),
			},
			wantError: "requires publication confirmation",
		},
		{
			name: "publication confirmation digest mismatch",
			checkpoint: Checkpoint{
				SchemaVersion:             CheckpointSchemaVersion,
				Provider:                  ProviderAWS,
				PublicationMode:           PublicationModeManual,
				Phase:                     PhaseCombinedJWKSPublished,
				OutputDir:                 "rotation-output",
				ClusterIdentity:           "cluster-123",
				TargetIdentity:            "aws://issuer",
				PreRotationSignerBaseline: testSignerBaseline(),
				PreRotationSignerRef:      testSignerObjectReference(),
				RotationGuard:             testRotationGuard(ProviderAWS, "cluster-123", "aws://issuer", testSignerBaseline(), testSignerObjectReference()),
				ReplacementSigner:         testReplacementSignerEvidence(),
				Artifacts:                 allTestArtifacts(),
				Publications: []PublicationConfirmation{{
					Phase:    PhaseCombinedJWKSPublished,
					Artifact: ArtifactCombinedJWKS,
					SHA256:   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				}},
			},
			wantError: "does not match",
		},
		{
			name: "publication confirmation ahead of checkpoint",
			checkpoint: Checkpoint{
				SchemaVersion:             CheckpointSchemaVersion,
				Provider:                  ProviderAWS,
				PublicationMode:           PublicationModeManual,
				Phase:                     PhaseCombinedJWKSBuilt,
				OutputDir:                 "rotation-output",
				ClusterIdentity:           "cluster-123",
				TargetIdentity:            "aws://issuer",
				PreRotationSignerBaseline: testSignerBaseline(),
				PreRotationSignerRef:      testSignerObjectReference(),
				RotationGuard:             testRotationGuard(ProviderAWS, "cluster-123", "aws://issuer", testSignerBaseline(), testSignerObjectReference()),
				ReplacementSigner:         testReplacementSignerEvidence(),
				Artifacts:                 allTestArtifacts(),
				Publications: []PublicationConfirmation{{
					Phase:    PhaseCombinedJWKSPublished,
					Artifact: ArtifactCombinedJWKS,
					SHA256:   testDigest,
				}},
			},
			wantError: "ahead of checkpoint phase",
		},
		{
			name:       "valid complete checkpoint",
			checkpoint: completeTestCheckpoint(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.checkpoint.Validate()
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("Validate() returned unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Validate() error = %v, want an error containing %q", err, test.wantError)
			}
		})
	}
}

func TestCheckpointValidateRebootIntent(t *testing.T) {
	base := completeTestCheckpoint()
	base.Phase = PhaseRebootIntentRecorded
	base.Publications = base.Publications[:1]

	tests := []struct {
		name      string
		mutate    func(*Checkpoint)
		wantError string
	}{
		{name: "valid reboot intent"},
		{
			name: "missing reboot intent",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.RebootIntent = nil
			},
			wantError: "reboot intent must be recorded",
		},
		{
			name: "reboot intent before its phase",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.Phase = PhaseSignerRolloutStable
			},
			wantError: "reboot intent is ahead",
		},
		{
			name: "missing reboot intent ID",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.RebootIntent.ID = ""
			},
			wantError: "reboot intent ID must not be empty",
		},
		{
			name: "reboot intent ID not bound to checkpoint",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.RebootIntent.ID = "different-valid-looking-id"
			},
			wantError: "does not match the cluster and replacement key",
		},
		{
			name: "cluster identity changed without a new intent ID",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.ClusterIdentity = "other-cluster"
				setTestRotationGuard(checkpoint)
			},
			wantError: "does not match the cluster and replacement key",
		},
		{
			name: "missing reboot targets",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.RebootIntent.Targets = nil
			},
			wantError: "at least one target",
		},
		{
			name: "duplicate reboot target",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.RebootIntent.Targets = []string{"worker", "worker"}
			},
			wantError: "duplicate target",
		},
		{
			name: "missing reboot baselines",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.RebootIntent.Baselines = nil
			},
			wantError: "at least one node baseline",
		},
		{
			name: "unknown baseline target",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.RebootIntent.Baselines[0].Target = "infra"
			},
			wantError: "references unknown target",
		},
		{
			name: "duplicate baseline node",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.RebootIntent.Baselines[1].Node = checkpoint.RebootIntent.Baselines[0].Node
			},
			wantError: "duplicate node baseline",
		},
		{
			name: "missing baseline boot ID",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.RebootIntent.Baselines[0].BootID = ""
			},
			wantError: "boot ID must not be empty",
		},
		{
			name: "target without baseline",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.RebootIntent.Baselines = checkpoint.RebootIntent.Baselines[:1]
			},
			wantError: "has no node baseline",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			checkpoint := base
			checkpoint.RebootIntent = testNodeRebootIntent()
			if test.mutate != nil {
				test.mutate(&checkpoint)
			}
			err := checkpoint.Validate()
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("Validate() returned unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Validate() error = %v, want an error containing %q", err, test.wantError)
			}
		})
	}
}

func TestCheckpointValidateSignerEvidence(t *testing.T) {
	secondEntry := PublicSignerBaselineEntry{
		Name:   "service-account-002.pub",
		SHA256: strings.Repeat("c", 64),
		KeyID:  testOtherKeyID,
	}
	tests := []struct {
		name      string
		mutate    func(*Checkpoint)
		wantError string
	}{
		{name: "valid signer evidence"},
		{
			name: "baseline entries are not canonical",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.PreRotationSignerBaseline.Entries = []PublicSignerBaselineEntry{secondEntry, checkpoint.PreRotationSignerBaseline.Entries[0]}
			},
			wantError: "must be sorted",
		},
		{
			name: "baseline repeats exact public value",
			mutate: func(checkpoint *Checkpoint) {
				duplicate := secondEntry
				duplicate.SHA256 = checkpoint.PreRotationSignerBaseline.Entries[0].SHA256
				checkpoint.PreRotationSignerBaseline.Entries = append(checkpoint.PreRotationSignerBaseline.Entries, duplicate)
			},
			wantError: "duplicate public value digest",
		},
		{
			name: "baseline repeats semantic key",
			mutate: func(checkpoint *Checkpoint) {
				duplicate := secondEntry
				duplicate.KeyID = checkpoint.PreRotationSignerBaseline.Entries[0].KeyID
				checkpoint.PreRotationSignerBaseline.Entries = append(checkpoint.PreRotationSignerBaseline.Entries, duplicate)
			},
			wantError: "duplicate key ID",
		},
		{
			name: "missing replacement evidence",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.ReplacementSigner = nil
			},
			wantError: "replacement signer evidence must be recorded",
		},
		{
			name: "replacement repeats baseline name",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.ReplacementSigner.Entry.Name = checkpoint.PreRotationSignerBaseline.Entries[0].Name
			},
			wantError: "already exists",
		},
		{
			name: "replacement repeats baseline key ID",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.ReplacementSigner.Entry.KeyID = checkpoint.PreRotationSignerBaseline.Entries[0].KeyID
			},
			wantError: "already exists",
		},
		{
			name: "replacement artifact binding differs",
			mutate: func(checkpoint *Checkpoint) {
				checkpoint.ReplacementSigner.Entry.SHA256 = strings.Repeat("d", 64)
			},
			wantError: "does not match artifact",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			checkpoint := cloneCheckpoint(completeTestCheckpoint())
			if test.mutate != nil {
				test.mutate(&checkpoint)
			}
			err := checkpoint.Validate()
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("Validate() returned unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Validate() error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestCloneCheckpointDoesNotExposeSignerEvidenceAliases(t *testing.T) {
	original := completeTestCheckpoint()
	clone := cloneCheckpoint(original)
	clone.PreRotationSignerBaseline.Entries[0].SHA256 = strings.Repeat("c", 64)
	clone.PreRotationSignerRef.ResourceVersion = "changed"
	clone.RotationGuard.OperationID = strings.Repeat("d", 64)
	clone.ReplacementSigner.SecretRef.ResourceVersion = "changed"

	if reflect.DeepEqual(original.PreRotationSignerBaseline, clone.PreRotationSignerBaseline) || original.PreRotationSignerRef.ResourceVersion == "changed" || original.RotationGuard.OperationID == strings.Repeat("d", 64) || original.ReplacementSigner.SecretRef.ResourceVersion == "changed" {
		t.Fatal("cloneCheckpoint() exposed mutable signer evidence aliases")
	}
}

func TestOrderedPhasesPreserveSafeRotationOrder(t *testing.T) {
	phases := OrderedPhases()
	expected := []Phase{
		PhaseInitialized,
		PhasePreflightComplete,
		PhaseGuardAcquired,
		PhaseCurrentJWKSRead,
		PhaseNextKeyRequested,
		PhaseNextPublicKeyRead,
		PhaseNewJWKSBuilt,
		PhaseCombinedJWKSBuilt,
		PhaseCombinedJWKSPublished,
		PhaseSignerRolloutStable,
		PhaseRebootIntentRecorded,
		PhaseNodesRebooted,
		PhasePostRebootStable,
		PhaseNewOnlyJWKSPublished,
		PhaseGuardReleaseRecorded,
		PhaseComplete,
	}
	if !reflect.DeepEqual(phases, expected) {
		t.Fatalf("OrderedPhases() = %v, want %v", phases, expected)
	}

	position := make(map[Phase]int, len(phases))
	for index, phase := range phases {
		position[phase] = index
	}

	assertBefore := func(earlier, later Phase) {
		t.Helper()
		earlierPosition, earlierExists := position[earlier]
		laterPosition, laterExists := position[later]
		if !earlierExists || !laterExists {
			t.Fatalf("required phases %q and %q must both be present", earlier, later)
		}
		if earlierPosition >= laterPosition {
			t.Fatalf("phase %q must precede %q", earlier, later)
		}
	}

	assertBefore(PhasePreflightComplete, PhaseGuardAcquired)
	assertBefore(PhaseGuardAcquired, PhaseCurrentJWKSRead)
	assertBefore(PhaseCurrentJWKSRead, PhaseNextKeyRequested)
	assertBefore(PhaseCombinedJWKSPublished, PhaseSignerRolloutStable)
	assertBefore(PhaseSignerRolloutStable, PhaseRebootIntentRecorded)
	assertBefore(PhaseRebootIntentRecorded, PhaseNodesRebooted)
	assertBefore(PhaseNodesRebooted, PhasePostRebootStable)
	assertBefore(PhasePostRebootStable, PhaseNewOnlyJWKSPublished)
	assertBefore(PhaseNewOnlyJWKSPublished, PhaseGuardReleaseRecorded)
	assertBefore(PhaseGuardReleaseRecorded, PhaseComplete)
}

func allTestArtifacts() []ArtifactMetadata {
	return []ArtifactMetadata{
		{Name: ArtifactCurrentJWKS, SHA256: testDigest, KeyIDs: []string{testOldKeyID}},
		{Name: ArtifactReplacementPublicKey, SHA256: testReplacementDigest, KeyIDs: []string{testOtherKeyID}},
		{Name: ArtifactNewJWKS, SHA256: testDigest, KeyIDs: []string{testOtherKeyID}},
		{Name: ArtifactCombinedJWKS, SHA256: testDigest, KeyIDs: []string{testOldKeyID, testOtherKeyID}},
	}
}

func completeTestCheckpoint() Checkpoint {
	checkpoint := Checkpoint{
		SchemaVersion:             CheckpointSchemaVersion,
		Provider:                  ProviderAWS,
		PublicationMode:           PublicationModeDirect,
		Phase:                     PhaseComplete,
		OutputDir:                 "rotation-output",
		ClusterIdentity:           "cluster-123",
		TargetIdentity:            "aws://issuer",
		PreRotationSignerBaseline: testSignerBaseline(),
		PreRotationSignerRef:      testSignerObjectReference(),
		ReplacementSigner:         testReplacementSignerEvidence(),
		RebootIntent:              testNodeRebootIntent(),
		Artifacts:                 allTestArtifacts(),
		Publications: []PublicationConfirmation{
			{Phase: PhaseCombinedJWKSPublished, Artifact: ArtifactCombinedJWKS, SHA256: testDigest},
			{Phase: PhaseNewOnlyJWKSPublished, Artifact: ArtifactNewJWKS, SHA256: testDigest},
		},
	}
	checkpoint.RotationGuard = testRotationGuard(checkpoint.Provider, checkpoint.ClusterIdentity, checkpoint.TargetIdentity, checkpoint.PreRotationSignerBaseline, checkpoint.PreRotationSignerRef)
	return checkpoint
}

func testRotationGuard(provider Provider, clusterIdentity, targetIdentity string, baseline *PublicSignerBaseline, signerRef *SignerObjectReference) *RotationGuardReference {
	reference, err := deriveRotationGuardReference(clusterIdentity, provider, targetIdentity, *baseline, *signerRef)
	if err != nil {
		panic(fmt.Sprintf("derive test rotation guard: %v", err))
	}
	return &reference
}

func setTestRotationGuard(checkpoint *Checkpoint) {
	checkpoint.RotationGuard = testRotationGuard(checkpoint.Provider, checkpoint.ClusterIdentity, checkpoint.TargetIdentity, checkpoint.PreRotationSignerBaseline, checkpoint.PreRotationSignerRef)
}

func testSignerBaseline() *PublicSignerBaseline {
	return testSignerBaselineForKeyID(testOldKeyID)
}

func testSignerBaselineForKeyID(keyID string) *PublicSignerBaseline {
	return testSignerBaselineWithEntry(PublicSignerBaselineEntry{
		Name:   "service-account-001.pub",
		SHA256: testDigest,
		KeyID:  keyID,
	})
}

func testSignerBaselineForKeyIDs(keyIDs ...string) *PublicSignerBaseline {
	entries := make([]PublicSignerBaselineEntry, len(keyIDs))
	for index, keyID := range keyIDs {
		entries[index] = PublicSignerBaselineEntry{
			Name:   fmt.Sprintf("service-account-%03d.pub", index+1),
			SHA256: fmt.Sprintf("%064x", index+1),
			KeyID:  keyID,
		}
	}
	return &PublicSignerBaseline{
		ConfigMapUID:             "aaaaaaaa-2222-3333-4444-555555555555",
		ConfigMapResourceVersion: "67890",
		Entries:                  entries,
	}
}

func testReplacementEvidenceForMetadata(metadata ArtifactMetadata) *ReplacementSignerEvidence {
	return &ReplacementSignerEvidence{
		Entry: PublicSignerBaselineEntry{
			Name:   "service-account-002.pub",
			SHA256: metadata.SHA256,
			KeyID:  metadata.KeyIDs[0],
		},
		SecretRef: SignerObjectReference{
			UID:             "test-replacement-signer-uid",
			ResourceVersion: "2000",
		},
	}
}

func testSignerBaselineWithEntry(entry PublicSignerBaselineEntry) *PublicSignerBaseline {
	return &PublicSignerBaseline{
		ConfigMapUID:             "aaaaaaaa-2222-3333-4444-555555555555",
		ConfigMapResourceVersion: "67890",
		Entries:                  []PublicSignerBaselineEntry{entry},
	}
}

func testReplacementSignerEvidence() *ReplacementSignerEvidence {
	return &ReplacementSignerEvidence{
		Entry: PublicSignerBaselineEntry{
			Name:   "service-account-002.pub",
			SHA256: testReplacementDigest,
			KeyID:  testOtherKeyID,
		},
		SecretRef: SignerObjectReference{
			UID:             "99999999-2222-3333-4444-555555555555",
			ResourceVersion: "67891",
		},
	}
}

func testSignerBaselineForPublicKeys(t *testing.T, publicKeys ...[]byte) *PublicSignerBaseline {
	t.Helper()
	signers := make([]PublicSignerObservation, len(publicKeys))
	for index, publicKey := range publicKeys {
		signers[index] = PublicSignerObservation{
			Name:         fmt.Sprintf("service-account-%03d.pub", index+1),
			PublicKeyPEM: append([]byte(nil), publicKey...),
		}
	}
	state, err := normalizePublicSignerBundle(PublicSignerBundleObservation{
		ConfigMapUID:             "test-signer-configmap-uid",
		ConfigMapResourceVersion: "1000",
		Signers:                  signers,
	})
	if err != nil {
		t.Fatalf("normalize test signer baseline: %v", err)
	}
	baseline := clonePublicSignerBaseline(state.Baseline)
	return &baseline
}

func testReplacementEvidenceForPublicKey(t *testing.T, publicKey []byte, entryIndex int) *ReplacementSignerEvidence {
	t.Helper()
	state, err := normalizePublicSignerBundle(PublicSignerBundleObservation{
		ConfigMapUID:             "test-signer-configmap-uid",
		ConfigMapResourceVersion: "1001",
		Signers: []PublicSignerObservation{{
			Name:         fmt.Sprintf("service-account-%03d.pub", entryIndex),
			PublicKeyPEM: append([]byte(nil), publicKey...),
		}},
	})
	if err != nil {
		t.Fatalf("normalize test replacement signer: %v", err)
	}
	return &ReplacementSignerEvidence{
		Entry: state.Baseline.Entries[0],
		SecretRef: SignerObjectReference{
			UID:             "test-replacement-signer-uid",
			ResourceVersion: "2000",
		},
	}
}

func testSignerObjectReference() *SignerObjectReference {
	return &SignerObjectReference{
		UID:             "11111111-2222-3333-4444-555555555555",
		ResourceVersion: "12345",
	}
}

func testNodeRebootIntent() *RebootIntent {
	targets := []string{"master", "worker"}
	intentID, err := rebootIntentID("cluster-123", testOtherKeyID)
	if err != nil {
		panic(err)
	}
	return &RebootIntent{
		ID:      intentID,
		Targets: targets,
		Baselines: []NodeRebootBaseline{
			{Target: "master", Node: "master-0", BootID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
			{Target: "worker", Node: "worker-0", BootID: "ffffffff-1111-2222-3333-444444444444"},
		},
	}
}

func TestOrderedPhasesReturnsCopy(t *testing.T) {
	phases := OrderedPhases()
	phases[0] = PhaseComplete

	if OrderedPhases()[0] != PhaseInitialized {
		t.Fatal("OrderedPhases() exposed mutable contract state")
	}
}
