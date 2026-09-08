package rotation

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	jwkutil "github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/jwks"
)

const artifactFileMode = 0o644

// StoredArtifact is validated public evidence recorded by a rotation
// checkpoint. Data and metadata are copied before they are returned.
type StoredArtifact struct {
	Metadata ArtifactMetadata
	Path     string
	Data     []byte
}

// WriteArtifact validates and durably writes one public rotation artifact.
// Artifact names are immutable within a workspace: an identical retry is
// accepted, while an attempt to replace prior evidence fails closed.
func WriteArtifact(outputDir, name string, payload []byte) (ArtifactMetadata, error) {
	var metadata ArtifactMetadata
	err := WithRotationWorkspace(outputDir, func(workspace *RotationWorkspace) error {
		var err error
		metadata, err = workspace.WriteArtifact(name, payload)
		return err
	})
	if err != nil {
		return ArtifactMetadata{}, err
	}
	return metadata, nil
}

// WriteArtifact validates and persists a public artifact while retaining the
// workspace lease held by the surrounding orchestration operation.
func (w *RotationWorkspace) WriteArtifact(name string, payload []byte) (ArtifactMetadata, error) {
	if err := w.validateActive(); err != nil {
		return ArtifactMetadata{}, err
	}
	payload = append([]byte(nil), payload...)
	metadata, err := inspectArtifactPayload(name, payload)
	if err != nil {
		return ArtifactMetadata{}, err
	}
	checkpoint, err := w.LoadCheckpoint()
	if errors.Is(err, errCheckpointNotFound) {
		checkpoint = Checkpoint{OutputDir: w.outputDir}
	} else if err != nil {
		return ArtifactMetadata{}, fmt.Errorf("load rotation checkpoint before writing artifact: %w", err)
	}

	artifactPath := filepath.Join(w.outputDir, name)
	existing, existingErr := readExistingArtifact(artifactPath, name)
	switch {
	case existingErr == nil:
		if !bytes.Equal(existing, payload) {
			return ArtifactMetadata{}, fmt.Errorf("rotation artifact %q already exists with different content", name)
		}
	case !errors.Is(existingErr, os.ErrNotExist):
		return ArtifactMetadata{}, existingErr
	}

	if artifactIsRecorded(checkpoint, name) {
		return metadata, nil
	}
	payloads, err := loadArtifactPrerequisites(w.outputDir, name)
	if err != nil {
		return ArtifactMetadata{}, err
	}
	payloads[name] = payload
	if err := validateArtifactRelationships(checkpoint, payloads); err != nil {
		return ArtifactMetadata{}, err
	}
	if existingErr == nil && bytes.Equal(existing, payload) {
		return metadata, nil
	}

	if err := writeFileAtomically(w.outputDir, name, payload, artifactFileMode); err != nil {
		return ArtifactMetadata{}, fmt.Errorf("persist rotation artifact %q: %w", name, err)
	}
	return metadata, nil
}

// ReadArtifact returns an artifact only when the active checkpoint records the
// same digest and key identities. Unrecorded files are never treated as
// completed phase evidence.
func (w *RotationWorkspace) ReadArtifact(name string) (StoredArtifact, error) {
	if err := w.validateActive(); err != nil {
		return StoredArtifact{}, err
	}
	checkpoint, err := w.LoadCheckpoint()
	if err != nil {
		return StoredArtifact{}, fmt.Errorf("load rotation checkpoint before reading artifact: %w", err)
	}

	var recorded ArtifactMetadata
	found := false
	for _, artifact := range checkpoint.Artifacts {
		if artifact.Name == name {
			recorded = artifact
			found = true
			break
		}
	}
	if !found {
		return StoredArtifact{}, fmt.Errorf("rotation artifact %q is not recorded by checkpoint phase %q", name, checkpoint.Phase)
	}

	artifactPath := filepath.Join(w.outputDir, name)
	payload, err := readExistingArtifact(artifactPath, name)
	if err != nil {
		return StoredArtifact{}, err
	}
	observed, err := inspectArtifactPayload(name, payload)
	if err != nil {
		return StoredArtifact{}, err
	}
	if observed.SHA256 != recorded.SHA256 || !slices.Equal(observed.KeyIDs, recorded.KeyIDs) {
		return StoredArtifact{}, fmt.Errorf("rotation artifact %q does not match its recorded metadata", name)
	}

	recorded.KeyIDs = append([]string(nil), recorded.KeyIDs...)
	return StoredArtifact{
		Metadata: recorded,
		Path:     artifactPath,
		Data:     append([]byte(nil), payload...),
	}, nil
}

func artifactIsRecorded(checkpoint Checkpoint, name string) bool {
	for _, artifact := range checkpoint.Artifacts {
		if artifact.Name == name {
			return true
		}
	}
	return false
}

func loadArtifactPrerequisites(outputDir, name string) (map[string][]byte, error) {
	var required []string
	switch name {
	case ArtifactCurrentJWKS:
	case ArtifactReplacementPublicKey:
		required = []string{ArtifactCurrentJWKS}
	case ArtifactNewJWKS:
		required = []string{ArtifactCurrentJWKS, ArtifactReplacementPublicKey}
	case ArtifactCombinedJWKS:
		required = []string{ArtifactCurrentJWKS, ArtifactReplacementPublicKey, ArtifactNewJWKS}
	default:
		return nil, fmt.Errorf("unsupported rotation artifact %q", name)
	}

	payloads := make(map[string][]byte, len(required)+1)
	for _, prerequisite := range required {
		payload, err := readExistingArtifact(filepath.Join(outputDir, prerequisite), prerequisite)
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("rotation artifact %q requires existing artifact %q", name, prerequisite)
		}
		if err != nil {
			return nil, err
		}
		payloads[prerequisite] = payload
	}
	return payloads, nil
}

func inspectArtifactPayload(name string, payload []byte) (ArtifactMetadata, error) {
	var keyIDs []string
	if len(payload) > maxArtifactSize {
		return ArtifactMetadata{}, fmt.Errorf("rotation artifact %q exceeds %d bytes", name, maxArtifactSize)
	}

	switch name {
	case ArtifactReplacementPublicKey:
		keySet, err := jwkutil.NewSigner(payload)
		if err != nil {
			return ArtifactMetadata{}, fmt.Errorf("validate rotation artifact %q: %w", name, err)
		}
		keyIDs = []string{keySet.Keys[0].KeyID}
	case ArtifactCurrentJWKS:
		artifact, err := jwkutil.Inspect(payload)
		if err != nil {
			return ArtifactMetadata{}, fmt.Errorf("validate rotation artifact %q: %w", name, err)
		}
		keyIDs = artifact.KeyIDs
	case ArtifactNewJWKS, ArtifactCombinedJWKS:
		keySet, err := jwkutil.Parse(payload)
		if err != nil {
			return ArtifactMetadata{}, fmt.Errorf("validate rotation artifact %q: %w", name, err)
		}
		canonical, err := jwkutil.Encode(keySet)
		if err != nil {
			return ArtifactMetadata{}, fmt.Errorf("encode rotation artifact %q: %w", name, err)
		}
		if !bytes.Equal(payload, canonical.Data) {
			return ArtifactMetadata{}, fmt.Errorf("rotation artifact %q must use canonical encoding", name)
		}
		keyIDs = canonical.KeyIDs
	default:
		return ArtifactMetadata{}, fmt.Errorf("unsupported rotation artifact %q", name)
	}

	digest := sha256.Sum256(payload)
	metadata := ArtifactMetadata{
		Name:   name,
		SHA256: fmt.Sprintf("%x", digest),
		KeyIDs: keyIDs,
	}
	if err := validateArtifact(metadata); err != nil {
		return ArtifactMetadata{}, err
	}
	return metadata, nil
}

func readExistingArtifact(path, name string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("rotation artifact %q must be a regular file", name)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("rotation artifact %q must not be writable by group or others", name)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open rotation artifact %q: %w", name, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened rotation artifact %q: %w", name, err)
	}
	if !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("rotation artifact %q changed while it was opened", name)
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxArtifactSize+1))
	if err != nil {
		return nil, fmt.Errorf("read rotation artifact %q: %w", name, err)
	}
	if len(payload) > maxArtifactSize {
		return nil, fmt.Errorf("rotation artifact %q exceeds %d bytes", name, maxArtifactSize)
	}
	return payload, nil
}
