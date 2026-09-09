package rotation

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	jwkutil "github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/jwks"
)

func TestWriteArtifactIsDurableImmutableAndIdempotent(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "rotation-output")
	currentRaw := encodedJWKSForTest(t, testPublicKeyPEM(t))
	want, err := jwkutil.Inspect(currentRaw)
	if err != nil {
		t.Fatalf("inspect current JWKS fixture: %v", err)
	}

	metadata, err := WriteArtifact(outputDir, ArtifactCurrentJWKS, currentRaw)
	if err != nil {
		t.Fatalf("WriteArtifact() returned unexpected error: %v", err)
	}
	if metadata.Name != ArtifactCurrentJWKS || metadata.SHA256 != want.SHA256 || !reflect.DeepEqual(metadata.KeyIDs, want.KeyIDs) {
		t.Fatalf("WriteArtifact() metadata = %#v, want digest %q and key IDs %v", metadata, want.SHA256, want.KeyIDs)
	}

	artifactPath := filepath.Join(outputDir, ArtifactCurrentJWKS)
	written, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatalf("read written artifact: %v", err)
	}
	if string(written) != string(currentRaw) {
		t.Fatal("written artifact did not preserve its exact bytes")
	}
	info, err := os.Stat(artifactPath)
	if err != nil {
		t.Fatalf("stat written artifact: %v", err)
	}
	if got := info.Mode().Perm(); got != artifactFileMode {
		t.Fatalf("artifact mode = %o, want %o", got, artifactFileMode)
	}
	checkpoint := NewCheckpoint(ProviderAWS, PublicationModeDirect, outputDir)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save initialized checkpoint: %v", err)
	}
	checkpoint, err = LoadCheckpoint(outputDir)
	if err != nil {
		t.Fatalf("load initialized checkpoint: %v", err)
	}
	checkpoint.Phase = PhasePreflightComplete
	checkpoint.ClusterIdentity = "cluster-123"
	checkpoint.TargetIdentity = "aws://issuer"
	checkpoint.PreRotationSignerBaseline = testSignerBaselineForKeyID(metadata.KeyIDs[0])
	checkpoint.PreRotationSignerRef = testSignerObjectReference()
	setTestRotationGuard(&checkpoint)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save preflight checkpoint: %v", err)
	}
	checkpoint.Phase = PhaseGuardAcquired
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save guard-acquired checkpoint: %v", err)
	}
	checkpoint.Phase = PhaseCurrentJWKSRead
	checkpoint.Artifacts = []ArtifactMetadata{metadata}
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("record current JWKS: %v", err)
	}

	if _, err := WriteArtifact(outputDir, ArtifactCurrentJWKS, currentRaw); err != nil {
		t.Fatalf("idempotent WriteArtifact() returned unexpected error: %v", err)
	}
	different := encodedJWKSForTest(t, testPublicKeyPEM(t))
	if _, err := WriteArtifact(outputDir, ArtifactCurrentJWKS, different); err == nil || !strings.Contains(err.Error(), "already exists with different content") {
		t.Fatalf("WriteArtifact(different content) error = %v", err)
	}
}

func TestWriteArtifactRejectsReplacementOfUnrecordedEvidence(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "rotation-output")
	currentRaw := encodedJWKSForTest(t, testPublicKeyPEM(t))
	currentMetadata, err := WriteArtifact(outputDir, ArtifactCurrentJWKS, currentRaw)
	if err != nil {
		t.Fatalf("write current JWKS: %v", err)
	}

	checkpoint := NewCheckpoint(ProviderAWS, PublicationModeDirect, outputDir)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save initialized checkpoint: %v", err)
	}
	checkpoint, err = LoadCheckpoint(outputDir)
	if err != nil {
		t.Fatalf("load initialized checkpoint: %v", err)
	}
	checkpoint.Phase = PhasePreflightComplete
	checkpoint.ClusterIdentity = "cluster-123"
	checkpoint.TargetIdentity = "aws://issuer"
	checkpoint.PreRotationSignerBaseline = testSignerBaselineForKeyID(currentMetadata.KeyIDs[0])
	checkpoint.PreRotationSignerRef = testSignerObjectReference()
	setTestRotationGuard(&checkpoint)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save preflight checkpoint: %v", err)
	}
	checkpoint.Phase = PhaseGuardAcquired
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save guard-acquired checkpoint: %v", err)
	}
	checkpoint.Phase = PhaseCurrentJWKSRead
	checkpoint.Artifacts = []ArtifactMetadata{currentMetadata}
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save current-JWKS checkpoint: %v", err)
	}
	checkpoint.Phase = PhaseNextKeyRequested
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save replacement-requested checkpoint: %v", err)
	}

	wrongReplacement := testPublicKeyPEM(t)
	if _, err := WriteArtifact(outputDir, ArtifactReplacementPublicKey, wrongReplacement); err != nil {
		t.Fatalf("write unrecorded replacement fixture: %v", err)
	}
	correctReplacement := testPublicKeyPEM(t)
	if _, err := WriteArtifact(outputDir, ArtifactReplacementPublicKey, correctReplacement); err == nil || !strings.Contains(err.Error(), "already exists with different content") {
		t.Fatalf("replace unrecorded replacement error = %v", err)
	}
	written, err := os.ReadFile(filepath.Join(outputDir, ArtifactReplacementPublicKey))
	if err != nil {
		t.Fatalf("read preserved replacement: %v", err)
	}
	if string(written) != string(wrongReplacement) {
		t.Fatal("unrecorded replacement artifact was changed")
	}
}

func TestRotationWorkspaceReadArtifactRequiresRecordedEvidence(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "rotation-output")
	currentRaw := encodedJWKSForTest(t, testPublicKeyPEM(t))
	currentMetadata, err := WriteArtifact(outputDir, ArtifactCurrentJWKS, currentRaw)
	if err != nil {
		t.Fatalf("write current JWKS: %v", err)
	}

	checkpoint := NewCheckpoint(ProviderAWS, PublicationModeDirect, outputDir)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save initialized checkpoint: %v", err)
	}
	checkpoint, err = LoadCheckpoint(outputDir)
	if err != nil {
		t.Fatalf("load initialized checkpoint: %v", err)
	}

	err = WithRotationWorkspace(outputDir, func(workspace *RotationWorkspace) error {
		if _, err := workspace.ReadArtifact(ArtifactCurrentJWKS); err == nil || !strings.Contains(err.Error(), "is not recorded") {
			t.Fatalf("ReadArtifact(unrecorded) error = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("inspect unrecorded artifact: %v", err)
	}

	checkpoint.Phase = PhasePreflightComplete
	checkpoint.ClusterIdentity = "cluster-123"
	checkpoint.TargetIdentity = "aws://issuer"
	checkpoint.PreRotationSignerBaseline = testSignerBaselineForKeyID(currentMetadata.KeyIDs[0])
	checkpoint.PreRotationSignerRef = testSignerObjectReference()
	setTestRotationGuard(&checkpoint)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save preflight checkpoint: %v", err)
	}
	checkpoint.Phase = PhaseGuardAcquired
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save guard-acquired checkpoint: %v", err)
	}
	checkpoint.Phase = PhaseCurrentJWKSRead
	checkpoint.Artifacts = []ArtifactMetadata{currentMetadata}
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("record current JWKS: %v", err)
	}

	var stored StoredArtifact
	err = WithRotationWorkspace(outputDir, func(workspace *RotationWorkspace) error {
		var err error
		stored, err = workspace.ReadArtifact(ArtifactCurrentJWKS)
		return err
	})
	if err != nil {
		t.Fatalf("ReadArtifact(recorded) returned unexpected error: %v", err)
	}
	if stored.Path != filepath.Join(outputDir, ArtifactCurrentJWKS) || stored.Metadata.SHA256 != currentMetadata.SHA256 || !reflect.DeepEqual(stored.Metadata.KeyIDs, currentMetadata.KeyIDs) || string(stored.Data) != string(currentRaw) {
		t.Fatalf("ReadArtifact(recorded) = %#v", stored)
	}

	stored.Data[0] ^= 0xff
	stored.Metadata.KeyIDs[0] = "changed"
	written, err := os.ReadFile(filepath.Join(outputDir, ArtifactCurrentJWKS))
	if err != nil {
		t.Fatalf("read current JWKS after mutating result: %v", err)
	}
	if string(written) != string(currentRaw) || checkpoint.Artifacts[0].KeyIDs[0] == "changed" {
		t.Fatal("ReadArtifact returned aliases to persisted evidence")
	}
}

func TestWriteArtifactRejectsInvalidInput(t *testing.T) {
	validSingle := encodedJWKSForTest(t, testPublicKeyPEM(t))
	tests := []struct {
		name         string
		artifactName string
		payload      []byte
		wantError    string
	}{
		{name: "unsupported name", artifactName: "private.key", payload: validSingle, wantError: "unsupported rotation artifact"},
		{name: "invalid public key", artifactName: ArtifactReplacementPublicKey, payload: []byte("not PEM"), wantError: "decode signer public key PEM"},
		{name: "invalid current JWKS", artifactName: ArtifactCurrentJWKS, payload: []byte(`{"keys":[]}`), wantError: "at least one key"},
		{name: "noncanonical new JWKS", artifactName: ArtifactNewJWKS, payload: append([]byte(" \n"), validSingle...), wantError: "canonical encoding"},
		{name: "single-key combined JWKS", artifactName: ArtifactCombinedJWKS, payload: validSingle, wantError: "at least two key IDs"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := WriteArtifact(filepath.Join(t.TempDir(), "rotation-output"), test.artifactName, test.payload)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("WriteArtifact() error = %v, want error containing %q", err, test.wantError)
			}
		})
	}
}

func TestWriteArtifactDoesNotPersistUnvalidatedPublicKeyEnvelope(t *testing.T) {
	validPEM := testPublicKeyPEM(t)
	block, remainder := pem.Decode(validPEM)
	if block == nil || len(remainder) != 0 {
		t.Fatal("decode valid replacement-public-key fixture")
	}
	withHeaders := pem.EncodeToMemory(&pem.Block{
		Type:    "PUBLIC KEY",
		Headers: map[string]string{"Comment": "unexpected metadata"},
		Bytes:   block.Bytes,
	})
	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "leading data", payload: append([]byte("untrusted prefix\n"), validPEM...)},
		{name: "PEM headers", payload: withHeaders},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outputDir := filepath.Join(t.TempDir(), "rotation-output")
			_, err := WriteArtifact(outputDir, ArtifactReplacementPublicKey, test.payload)
			if err == nil {
				t.Fatal("WriteArtifact() unexpectedly accepted an invalid public-key envelope")
			}
			artifactPath := filepath.Join(outputDir, ArtifactReplacementPublicKey)
			if _, statErr := os.Lstat(artifactPath); !os.IsNotExist(statErr) {
				t.Fatalf("invalid public-key envelope persisted at %q: %v", artifactPath, statErr)
			}
		})
	}
}

func TestWriteArtifactRejectsUnsafeExistingPath(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "rotation-output")
	if err := ensureCheckpointDirectory(outputDir); err != nil {
		t.Fatalf("create checkpoint directory: %v", err)
	}
	target := filepath.Join(outputDir, "target.json")
	if err := os.WriteFile(target, []byte("target"), artifactFileMode); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(outputDir, ArtifactCurrentJWKS)); err != nil {
		t.Fatalf("create artifact symlink: %v", err)
	}

	validCurrent := encodedJWKSForTest(t, testPublicKeyPEM(t))
	_, err := WriteArtifact(outputDir, ArtifactCurrentJWKS, validCurrent)
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("WriteArtifact(symlink) error = %v", err)
	}
}

func TestWriteArtifactRejectsWritableExistingArtifact(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "rotation-output")
	currentRaw := encodedJWKSForTest(t, testPublicKeyPEM(t))
	if _, err := WriteArtifact(outputDir, ArtifactCurrentJWKS, currentRaw); err != nil {
		t.Fatalf("write current JWKS: %v", err)
	}
	artifactPath := filepath.Join(outputDir, ArtifactCurrentJWKS)
	if err := os.Chmod(artifactPath, 0o664); err != nil {
		t.Fatalf("make current JWKS group-writable: %v", err)
	}

	_, err := WriteArtifact(outputDir, ArtifactCurrentJWKS, currentRaw)
	if err == nil || !strings.Contains(err.Error(), "must not be writable") {
		t.Fatalf("WriteArtifact(writable artifact) error = %v", err)
	}
}

func TestCheckpointAndArtifactStoresRejectWritableWorkspace(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "rotation-output")
	if err := os.Mkdir(outputDir, 0o700); err != nil {
		t.Fatalf("create output directory: %v", err)
	}
	if err := os.Chmod(outputDir, 0o770); err != nil {
		t.Fatalf("make output directory group-writable: %v", err)
	}

	checkpoint := NewCheckpoint(ProviderAWS, PublicationModeDirect, outputDir)
	if err := SaveCheckpoint(checkpoint); err == nil || !strings.Contains(err.Error(), "must not be writable") {
		t.Fatalf("SaveCheckpoint(writable workspace) error = %v", err)
	}
	validCurrent := encodedJWKSForTest(t, testPublicKeyPEM(t))
	if _, err := WriteArtifact(outputDir, ArtifactCurrentJWKS, validCurrent); err == nil || !strings.Contains(err.Error(), "must not be writable") {
		t.Fatalf("WriteArtifact(writable workspace) error = %v", err)
	}
}

func TestCheckpointStorePersistsValidatedArtifactBundle(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "rotation-output")
	checkpoint := NewCheckpoint(ProviderAWS, PublicationModeDirect, outputDir)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save initialized checkpoint: %v", err)
	}

	currentRaw := encodedJWKSForTest(t, testPublicKeyPEM(t))
	replacementPEM := testPublicKeyPEM(t)
	prepared, err := PrepareJWKSArtifacts(currentRaw, replacementPEM)
	if err != nil {
		t.Fatalf("prepare JWKS artifact bundle: %v", err)
	}

	checkpoint, err = LoadCheckpoint(outputDir)
	if err != nil {
		t.Fatalf("load initialized checkpoint: %v", err)
	}
	checkpoint.Phase = PhasePreflightComplete
	checkpoint.ClusterIdentity = "cluster-123"
	checkpoint.TargetIdentity = "aws://issuer"
	checkpoint.PreRotationSignerBaseline = testSignerBaselineForKeyID(prepared.Current.KeyIDs[0])
	checkpoint.PreRotationSignerRef = testSignerObjectReference()
	setTestRotationGuard(&checkpoint)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save preflight checkpoint: %v", err)
	}
	checkpoint.Phase = PhaseGuardAcquired
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save guard-acquired checkpoint: %v", err)
	}

	currentMetadata, err := WriteArtifact(outputDir, ArtifactCurrentJWKS, prepared.Current.Data)
	if err != nil {
		t.Fatalf("write current JWKS: %v", err)
	}
	checkpoint.Phase = PhaseCurrentJWKSRead
	checkpoint.Artifacts = append(checkpoint.Artifacts, currentMetadata)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save current-JWKS checkpoint: %v", err)
	}

	checkpoint.Phase = PhaseNextKeyRequested
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save replacement-requested checkpoint: %v", err)
	}

	replacementMetadata, err := WriteArtifact(outputDir, ArtifactReplacementPublicKey, replacementPEM)
	if err != nil {
		t.Fatalf("write replacement public key: %v", err)
	}
	checkpoint.Phase = PhaseNextPublicKeyRead
	checkpoint.Artifacts = append(checkpoint.Artifacts, replacementMetadata)
	checkpoint.ReplacementSigner = testReplacementEvidenceForMetadata(replacementMetadata)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save replacement-public-key checkpoint: %v", err)
	}

	newMetadata, err := WriteArtifact(outputDir, ArtifactNewJWKS, prepared.New.Data)
	if err != nil {
		t.Fatalf("write new JWKS: %v", err)
	}
	checkpoint.Phase = PhaseNewJWKSBuilt
	checkpoint.Artifacts = append(checkpoint.Artifacts, newMetadata)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save new-JWKS checkpoint: %v", err)
	}

	combinedMetadata, err := WriteArtifact(outputDir, ArtifactCombinedJWKS, prepared.Combined.Data)
	if err != nil {
		t.Fatalf("write combined JWKS: %v", err)
	}
	checkpoint.Phase = PhaseCombinedJWKSBuilt
	checkpoint.Artifacts = append(checkpoint.Artifacts, combinedMetadata)
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save combined-JWKS checkpoint: %v", err)
	}

	loaded, err := LoadCheckpoint(outputDir)
	if err != nil {
		t.Fatalf("load validated artifact bundle: %v", err)
	}
	if loaded.Phase != PhaseCombinedJWKSBuilt || !reflect.DeepEqual(loaded.Artifacts, checkpoint.Artifacts) {
		t.Fatalf("loaded checkpoint = %#v, want phase %q and artifacts %#v", loaded, PhaseCombinedJWKSBuilt, checkpoint.Artifacts)
	}

	checkpoint.Phase = PhaseCombinedJWKSPublished
	checkpoint.Publications = append(checkpoint.Publications, PublicationConfirmation{
		Phase:    PhaseCombinedJWKSPublished,
		Artifact: ArtifactCombinedJWKS,
		SHA256:   combinedMetadata.SHA256,
	})
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save combined-publication checkpoint: %v", err)
	}
	checkpoint.Phase = PhaseSignerRolloutStable
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save signer-rollout checkpoint: %v", err)
	}
	checkpoint.Phase = PhaseRebootIntentRecorded
	checkpoint.RebootIntent = testNodeRebootIntent()
	checkpoint.RebootIntent.ID, err = rebootIntentID(checkpoint.ClusterIdentity, replacementMetadata.KeyIDs[0])
	if err != nil {
		t.Fatalf("derive reboot intent ID: %v", err)
	}
	if err := SaveCheckpoint(checkpoint); err != nil {
		t.Fatalf("save reboot-intent checkpoint: %v", err)
	}

	loaded, err = LoadCheckpoint(outputDir)
	if err != nil {
		t.Fatalf("load reboot-intent checkpoint: %v", err)
	}
	if loaded.Phase != PhaseRebootIntentRecorded || !reflect.DeepEqual(loaded.RebootIntent, checkpoint.RebootIntent) {
		t.Fatalf("loaded checkpoint = %#v, want phase %q and reboot intent %#v", loaded, PhaseRebootIntentRecorded, checkpoint.RebootIntent)
	}
}
