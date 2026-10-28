package rotation

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

const CheckpointSchemaVersion = 1

var publicSignerEntryNamePattern = regexp.MustCompile(`^service-account-[0-9]+\.pub$`)

type Provider string

const (
	ProviderAWS   Provider = "aws"
	ProviderAzure Provider = "azure"
	ProviderGCP   Provider = "gcp"
)

type PublicationMode string

const (
	PublicationModeDirect PublicationMode = "direct"
	PublicationModeManual PublicationMode = "manual"
)

const (
	ArtifactReplacementPublicKey = "serviceaccount-signer.public"
	ArtifactCurrentJWKS          = "jwks.current.json"
	ArtifactNewJWKS              = "jwks.new.json"
	ArtifactCombinedJWKS         = "jwks.combined.json"
)

type Phase string

const (
	PhaseInitialized           Phase = "initialized"
	PhasePreflightComplete     Phase = "preflight-complete"
	PhaseGuardAcquired         Phase = "guard-acquired"
	PhaseCurrentJWKSRead       Phase = "current-jwks-read"
	PhaseNextKeyRequested      Phase = "next-key-requested"
	PhaseNextPublicKeyRead     Phase = "next-public-key-read"
	PhaseNewJWKSBuilt          Phase = "new-jwks-built"
	PhaseCombinedJWKSBuilt     Phase = "combined-jwks-built"
	PhaseCombinedJWKSPublished Phase = "combined-jwks-published"
	PhaseSignerRolloutStable   Phase = "signer-rollout-stable"
	PhaseRebootIntentRecorded  Phase = "reboot-intent-recorded"
	PhaseNodesRebooted         Phase = "nodes-rebooted"
	PhasePostRebootStable      Phase = "post-reboot-stable"
	PhaseNewOnlyJWKSPublished  Phase = "new-only-jwks-published"
	PhaseGuardReleaseRecorded  Phase = "guard-release-recorded"
	PhaseComplete              Phase = "complete"
)

var orderedPhases = []Phase{
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

type ArtifactMetadata struct {
	Name   string   `json:"name"`
	SHA256 string   `json:"sha256,omitempty"`
	KeyIDs []string `json:"keyIDs,omitempty"`
}

// PublicationConfirmation binds a completed publication checkpoint to the
// exact public artifact that was applied. Resuming code must still reconcile
// the provider's observable state; this local record is not proof by itself.
type PublicationConfirmation struct {
	Phase    Phase  `json:"phase"`
	Artifact string `json:"artifact"`
	SHA256   string `json:"sha256"`
}

// SignerObjectReference identifies the pre-rotation signer Secret without
// recording any Secret payload. Both values are used as deletion preconditions
// so a delayed retry cannot delete a replacement object.
type SignerObjectReference struct {
	UID             string `json:"uid"`
	ResourceVersion string `json:"resourceVersion"`
}

// PublicSignerBaselineEntry binds one public signer ConfigMap entry name to
// both its exact byte representation and its derived key identity. Recording
// names and digests prevents an overwrite or rename from being mistaken for a
// newly appended signer.
type PublicSignerBaselineEntry struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	KeyID  string `json:"keyID"`
}

// PublicSignerBaseline records the complete public signer ConfigMap before
// rotation. The resource version is point-in-time evidence; after replacement
// the ConfigMap is expected to have a newer resource version but the UID and
// every recorded entry must remain unchanged.
type PublicSignerBaseline struct {
	ConfigMapUID             string                      `json:"configMapUID"`
	ConfigMapResourceVersion string                      `json:"configMapResourceVersion"`
	Entries                  []PublicSignerBaselineEntry `json:"entries"`
}

// ReplacementSignerEvidence binds the one appended public ConfigMap entry to
// the metadata-only identity of the replacement signer Secret.
type ReplacementSignerEvidence struct {
	Entry     PublicSignerBaselineEntry `json:"entry"`
	SecretRef SignerObjectReference     `json:"secretRef"`
}

// RotationGuardReference deterministically identifies both the cluster-wide
// signer-rotation guard scope and one exact operation. It contains no secret
// material and is derived from immutable preflight evidence.
type RotationGuardReference struct {
	ScopeID     string `json:"scopeID"`
	OperationID string `json:"operationID"`
}

// NodeRebootBaseline records the observable, non-secret state used to prove
// that a node in a target machine config pool rebooted after the intent was
// persisted.
type NodeRebootBaseline struct {
	Target string `json:"target"`
	Node   string `json:"node"`
	BootID string `json:"bootID"`
}

// RebootIntent durably identifies one disruptive reboot request and the exact
// machine config pools and node boot IDs that must be reconciled on resume.
type RebootIntent struct {
	ID        string               `json:"id"`
	Targets   []string             `json:"targets"`
	Baselines []NodeRebootBaseline `json:"baselines"`
}

// Checkpoint records only the non-secret information needed to validate and
// resume an externally initiated rotation. Cloud credentials and signer key
// material must never be added to this structure.
type Checkpoint struct {
	SchemaVersion             int                        `json:"schemaVersion"`
	Provider                  Provider                   `json:"provider"`
	PublicationMode           PublicationMode            `json:"publicationMode"`
	Phase                     Phase                      `json:"phase"`
	OutputDir                 string                     `json:"outputDir"`
	ClusterIdentity           string                     `json:"clusterIdentity,omitempty"`
	TargetIdentity            string                     `json:"targetIdentity,omitempty"`
	PreRotationSignerBaseline *PublicSignerBaseline      `json:"preRotationSignerBaseline,omitempty"`
	PreRotationSignerRef      *SignerObjectReference     `json:"preRotationSignerRef,omitempty"`
	RotationGuard             *RotationGuardReference    `json:"rotationGuard,omitempty"`
	ReplacementSigner         *ReplacementSignerEvidence `json:"replacementSigner,omitempty"`
	RebootIntent              *RebootIntent              `json:"rebootIntent,omitempty"`
	Artifacts                 []ArtifactMetadata         `json:"artifacts,omitempty"`
	Publications              []PublicationConfirmation  `json:"publicationConfirmations,omitempty"`
	LastErrorCode             string                     `json:"lastErrorCode,omitempty"`
}

func NewCheckpoint(provider Provider, publicationMode PublicationMode, outputDir string) Checkpoint {
	return Checkpoint{
		SchemaVersion:   CheckpointSchemaVersion,
		Provider:        provider,
		PublicationMode: publicationMode,
		Phase:           PhaseInitialized,
		OutputDir:       outputDir,
	}
}

func OrderedPhases() []Phase {
	phases := make([]Phase, len(orderedPhases))
	copy(phases, orderedPhases)
	return phases
}

func (c Checkpoint) Validate() error {
	if c.SchemaVersion != CheckpointSchemaVersion {
		return fmt.Errorf("unsupported rotation checkpoint schema version %d", c.SchemaVersion)
	}

	if !isSupportedProvider(c.Provider) {
		return fmt.Errorf("unsupported rotation provider %q", c.Provider)
	}

	if !isSupportedPublicationMode(c.PublicationMode) {
		return fmt.Errorf("unsupported rotation publication mode %q", c.PublicationMode)
	}

	if !isSupportedPhase(c.Phase) {
		return fmt.Errorf("unsupported rotation phase %q", c.Phase)
	}

	if strings.TrimSpace(c.OutputDir) == "" {
		return fmt.Errorf("rotation output directory must not be empty")
	}

	artifacts := make(map[string]ArtifactMetadata, len(c.Artifacts))
	for _, artifact := range c.Artifacts {
		if err := validateArtifact(artifact); err != nil {
			return err
		}
		if _, exists := artifacts[artifact.Name]; exists {
			return fmt.Errorf("duplicate rotation artifact %q", artifact.Name)
		}
		artifacts[artifact.Name] = artifact
	}
	allowedArtifacts := make(map[string]struct{}, len(requiredArtifacts(c.Phase)))
	for _, artifactName := range requiredArtifacts(c.Phase) {
		allowedArtifacts[artifactName] = struct{}{}
	}
	for artifactName := range artifacts {
		if _, allowed := allowedArtifacts[artifactName]; !allowed {
			return fmt.Errorf("rotation artifact %q is ahead of checkpoint phase %q", artifactName, c.Phase)
		}
	}

	publications := make(map[Phase]PublicationConfirmation, len(c.Publications))
	for _, publication := range c.Publications {
		if err := validatePublicationConfirmation(publication, artifacts); err != nil {
			return err
		}
		if _, exists := publications[publication.Phase]; exists {
			return fmt.Errorf("duplicate rotation publication confirmation for phase %q", publication.Phase)
		}
		if phasePosition(c.Phase) < phasePosition(publication.Phase) {
			return fmt.Errorf("rotation publication confirmation for phase %q is ahead of checkpoint phase %q", publication.Phase, c.Phase)
		}
		publications[publication.Phase] = publication
	}

	if phaseAtLeast(c.Phase, PhasePreflightComplete) {
		if strings.TrimSpace(c.ClusterIdentity) == "" {
			return fmt.Errorf("rotation cluster identity must be recorded after preflight")
		}
		if strings.TrimSpace(c.TargetIdentity) == "" {
			return fmt.Errorf("rotation target identity must be recorded after preflight")
		}
		if c.PreRotationSignerBaseline == nil {
			return fmt.Errorf("pre-rotation public signer baseline must be recorded after preflight")
		}
		if err := validatePublicSignerBaseline(*c.PreRotationSignerBaseline); err != nil {
			return fmt.Errorf("invalid pre-rotation public signer baseline: %w", err)
		}
		if c.PreRotationSignerRef == nil {
			return fmt.Errorf("pre-rotation signer object reference must be recorded after preflight")
		}
		if err := validateSignerObjectReference(*c.PreRotationSignerRef); err != nil {
			return fmt.Errorf("invalid pre-rotation signer object reference: %w", err)
		}
		if c.RotationGuard == nil {
			return fmt.Errorf("rotation guard reference must be recorded after preflight")
		}
		if err := validateRotationGuardReference(*c.RotationGuard); err != nil {
			return fmt.Errorf("invalid rotation guard reference: %w", err)
		}
		expectedGuard, err := deriveRotationGuardReference(c.ClusterIdentity, c.Provider, c.TargetIdentity, *c.PreRotationSignerBaseline, *c.PreRotationSignerRef)
		if err != nil {
			return fmt.Errorf("derive rotation guard reference: %w", err)
		}
		if *c.RotationGuard != expectedGuard {
			return fmt.Errorf("rotation guard reference does not match the recorded preflight evidence")
		}
	} else if c.ClusterIdentity != "" || c.TargetIdentity != "" || c.PreRotationSignerBaseline != nil || c.PreRotationSignerRef != nil || c.RotationGuard != nil {
		return fmt.Errorf("rotation identities must not be recorded before preflight completes")
	}

	if phaseAtLeast(c.Phase, PhaseNextPublicKeyRead) {
		if c.ReplacementSigner == nil {
			return fmt.Errorf("replacement signer evidence must be recorded after reading the replacement public key")
		}
		if err := validateReplacementSignerEvidence(*c.ReplacementSigner, c.PreRotationSignerBaseline); err != nil {
			return fmt.Errorf("invalid replacement signer evidence: %w", err)
		}
		if c.PreRotationSignerRef != nil && c.ReplacementSigner.SecretRef.UID == c.PreRotationSignerRef.UID {
			return fmt.Errorf("replacement signer Secret UID must differ from the pre-rotation signer Secret UID")
		}
		replacementArtifact, exists := artifacts[ArtifactReplacementPublicKey]
		if exists && (replacementArtifact.SHA256 != c.ReplacementSigner.Entry.SHA256 || len(replacementArtifact.KeyIDs) != 1 || replacementArtifact.KeyIDs[0] != c.ReplacementSigner.Entry.KeyID) {
			return fmt.Errorf("replacement signer evidence does not match artifact %q", ArtifactReplacementPublicKey)
		}
	} else if c.ReplacementSigner != nil {
		return fmt.Errorf("replacement signer evidence is ahead of checkpoint phase %q", c.Phase)
	}

	if phaseAtLeast(c.Phase, PhaseRebootIntentRecorded) {
		if c.RebootIntent == nil {
			return fmt.Errorf("rotation reboot intent must be recorded at phase %q", PhaseRebootIntentRecorded)
		}
		if err := validateRebootIntent(*c.RebootIntent); err != nil {
			return fmt.Errorf("invalid rotation reboot intent: %w", err)
		}
		if replacement, exists := artifacts[ArtifactReplacementPublicKey]; exists {
			expectedID, err := rebootIntentID(c.ClusterIdentity, replacement.KeyIDs[0])
			if err != nil {
				return fmt.Errorf("derive rotation reboot intent ID: %w", err)
			}
			if c.RebootIntent.ID != expectedID {
				return fmt.Errorf("rotation reboot intent ID does not match the cluster and replacement key")
			}
		}
	} else if c.RebootIntent != nil {
		return fmt.Errorf("rotation reboot intent is ahead of checkpoint phase %q", c.Phase)
	}

	for _, requiredArtifact := range requiredArtifacts(c.Phase) {
		if _, exists := artifacts[requiredArtifact]; !exists {
			return fmt.Errorf("rotation phase %q requires artifact %q", c.Phase, requiredArtifact)
		}
	}

	for _, requiredPublication := range requiredPublications(c.Phase) {
		if _, exists := publications[requiredPublication]; !exists {
			return fmt.Errorf("rotation phase %q requires publication confirmation for phase %q", c.Phase, requiredPublication)
		}
	}

	return nil
}

func isSupportedProvider(provider Provider) bool {
	switch provider {
	case ProviderAWS, ProviderAzure, ProviderGCP:
		return true
	default:
		return false
	}
}

func isSupportedPublicationMode(mode PublicationMode) bool {
	switch mode {
	case PublicationModeDirect, PublicationModeManual:
		return true
	default:
		return false
	}
}

func isSupportedPhase(phase Phase) bool {
	for _, supportedPhase := range orderedPhases {
		if phase == supportedPhase {
			return true
		}
	}
	return false
}

func phasePosition(phase Phase) int {
	for position, supportedPhase := range orderedPhases {
		if phase == supportedPhase {
			return position
		}
	}
	return -1
}

func phaseAtLeast(current, required Phase) bool {
	return phasePosition(current) >= phasePosition(required)
}

func requiredArtifacts(phase Phase) []string {
	required := []string{}
	if phaseAtLeast(phase, PhaseCurrentJWKSRead) {
		required = append(required, ArtifactCurrentJWKS)
	}
	if phaseAtLeast(phase, PhaseNextPublicKeyRead) {
		required = append(required, ArtifactReplacementPublicKey)
	}
	if phaseAtLeast(phase, PhaseNewJWKSBuilt) {
		required = append(required, ArtifactNewJWKS)
	}
	if phaseAtLeast(phase, PhaseCombinedJWKSBuilt) {
		required = append(required, ArtifactCombinedJWKS)
	}
	return required
}

func requiredPublications(phase Phase) []Phase {
	required := []Phase{}
	if phaseAtLeast(phase, PhaseCombinedJWKSPublished) {
		required = append(required, PhaseCombinedJWKSPublished)
	}
	if phaseAtLeast(phase, PhaseNewOnlyJWKSPublished) {
		required = append(required, PhaseNewOnlyJWKSPublished)
	}
	return required
}

func validateArtifact(artifact ArtifactMetadata) error {
	switch artifact.Name {
	case ArtifactReplacementPublicKey, ArtifactCurrentJWKS, ArtifactNewJWKS, ArtifactCombinedJWKS:
	default:
		return fmt.Errorf("unsupported rotation artifact %q", artifact.Name)
	}

	if err := validateSHA256(artifact.SHA256); err != nil {
		return fmt.Errorf("rotation artifact %q: %w", artifact.Name, err)
	}
	if len(artifact.KeyIDs) == 0 {
		return fmt.Errorf("rotation artifact %q must record at least one key ID", artifact.Name)
	}
	seenKeyIDs := make(map[string]struct{}, len(artifact.KeyIDs))
	for _, keyID := range artifact.KeyIDs {
		if keyID == "" || strings.TrimSpace(keyID) != keyID {
			return fmt.Errorf("rotation artifact %q contains an invalid key ID", artifact.Name)
		}
		if _, exists := seenKeyIDs[keyID]; exists {
			return fmt.Errorf("rotation artifact %q contains duplicate key ID %q", artifact.Name, keyID)
		}
		seenKeyIDs[keyID] = struct{}{}
	}
	if (artifact.Name == ArtifactReplacementPublicKey || artifact.Name == ArtifactNewJWKS) && len(artifact.KeyIDs) != 1 {
		return fmt.Errorf("rotation artifact %q must contain exactly one key ID", artifact.Name)
	}
	if artifact.Name == ArtifactCombinedJWKS && len(artifact.KeyIDs) < 2 {
		return fmt.Errorf("rotation artifact %q must contain at least two key IDs", artifact.Name)
	}

	return nil
}

func validatePublicationConfirmation(publication PublicationConfirmation, artifacts map[string]ArtifactMetadata) error {
	var expectedArtifact string
	switch publication.Phase {
	case PhaseCombinedJWKSPublished:
		expectedArtifact = ArtifactCombinedJWKS
	case PhaseNewOnlyJWKSPublished:
		expectedArtifact = ArtifactNewJWKS
	default:
		return fmt.Errorf("unsupported rotation publication confirmation phase %q", publication.Phase)
	}

	if publication.Artifact != expectedArtifact {
		return fmt.Errorf("rotation publication confirmation for phase %q must reference artifact %q", publication.Phase, expectedArtifact)
	}
	if err := validateSHA256(publication.SHA256); err != nil {
		return fmt.Errorf("rotation publication confirmation for phase %q: %w", publication.Phase, err)
	}

	artifact, exists := artifacts[publication.Artifact]
	if !exists {
		return fmt.Errorf("rotation publication confirmation for phase %q references missing artifact %q", publication.Phase, publication.Artifact)
	}
	if publication.SHA256 != artifact.SHA256 {
		return fmt.Errorf("rotation publication confirmation for phase %q does not match artifact %q digest", publication.Phase, publication.Artifact)
	}

	return nil
}

func validateSHA256(digest string) error {
	if len(digest) != 64 {
		return fmt.Errorf("SHA-256 digest must contain 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return fmt.Errorf("SHA-256 digest must contain only hexadecimal characters")
	}
	return nil
}

func validateDerivedKeyID(keyID string) error {
	if strings.TrimSpace(keyID) != keyID {
		return fmt.Errorf("key ID must not contain surrounding whitespace")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(keyID)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("key ID must be an unpadded base64url-encoded SHA-256 digest")
	}
	return nil
}

func validateSignerObjectReference(reference SignerObjectReference) error {
	if err := validateOpaqueCheckpointValue("signer UID", reference.UID); err != nil {
		return err
	}
	if err := validateOpaqueCheckpointValue("signer resource version", reference.ResourceVersion); err != nil {
		return err
	}
	return nil
}

func validatePublicSignerBaseline(baseline PublicSignerBaseline) error {
	if err := validateOpaqueCheckpointValue("public signer ConfigMap UID", baseline.ConfigMapUID); err != nil {
		return err
	}
	if err := validateOpaqueCheckpointValue("public signer ConfigMap resource version", baseline.ConfigMapResourceVersion); err != nil {
		return err
	}
	if len(baseline.Entries) == 0 {
		return fmt.Errorf("public signer baseline must contain at least one entry")
	}

	names := make(map[string]struct{}, len(baseline.Entries))
	digests := make(map[string]struct{}, len(baseline.Entries))
	keyIDs := make(map[string]struct{}, len(baseline.Entries))
	previousName := ""
	for _, entry := range baseline.Entries {
		if err := validatePublicSignerBaselineEntry(entry); err != nil {
			return err
		}
		if previousName != "" && entry.Name <= previousName {
			return fmt.Errorf("public signer baseline entries must be sorted by unique name")
		}
		previousName = entry.Name
		if _, exists := names[entry.Name]; exists {
			return fmt.Errorf("public signer baseline contains duplicate entry name %q", entry.Name)
		}
		names[entry.Name] = struct{}{}
		if _, exists := digests[entry.SHA256]; exists {
			return fmt.Errorf("public signer baseline contains duplicate public value digest %q", entry.SHA256)
		}
		digests[entry.SHA256] = struct{}{}
		if _, exists := keyIDs[entry.KeyID]; exists {
			return fmt.Errorf("public signer baseline contains duplicate key ID %q", entry.KeyID)
		}
		keyIDs[entry.KeyID] = struct{}{}
	}
	return nil
}

func validatePublicSignerBaselineEntry(entry PublicSignerBaselineEntry) error {
	if !publicSignerEntryNamePattern.MatchString(entry.Name) {
		return fmt.Errorf("public signer entry name %q is not supported", entry.Name)
	}
	if err := validateSHA256(entry.SHA256); err != nil {
		return fmt.Errorf("public signer entry %q: %w", entry.Name, err)
	}
	if err := validateDerivedKeyID(entry.KeyID); err != nil {
		return fmt.Errorf("public signer entry %q has invalid key ID: %w", entry.Name, err)
	}
	return nil
}

func validateReplacementSignerEvidence(evidence ReplacementSignerEvidence, baseline *PublicSignerBaseline) error {
	if err := validatePublicSignerBaselineEntry(evidence.Entry); err != nil {
		return err
	}
	if err := validateSignerObjectReference(evidence.SecretRef); err != nil {
		return err
	}
	if baseline == nil {
		return fmt.Errorf("replacement signer evidence requires a pre-rotation public signer baseline")
	}
	for _, entry := range baseline.Entries {
		switch {
		case entry.Name == evidence.Entry.Name:
			return fmt.Errorf("replacement signer entry name %q already exists in the pre-rotation baseline", evidence.Entry.Name)
		case entry.SHA256 == evidence.Entry.SHA256:
			return fmt.Errorf("replacement signer repeats a pre-rotation public value")
		case entry.KeyID == evidence.Entry.KeyID:
			return fmt.Errorf("replacement signer key ID %q already exists in the pre-rotation baseline", evidence.Entry.KeyID)
		}
	}
	return nil
}

func validateRebootIntent(intent RebootIntent) error {
	if err := validateOpaqueCheckpointValue("reboot intent ID", intent.ID); err != nil {
		return err
	}
	if len(intent.Targets) == 0 {
		return fmt.Errorf("reboot intent must contain at least one target")
	}

	targets := make(map[string]struct{}, len(intent.Targets))
	for _, target := range intent.Targets {
		if err := validateOpaqueCheckpointValue("reboot target", target); err != nil {
			return err
		}
		if _, exists := targets[target]; exists {
			return fmt.Errorf("reboot intent contains duplicate target %q", target)
		}
		targets[target] = struct{}{}
	}

	if len(intent.Baselines) == 0 {
		return fmt.Errorf("reboot intent must contain at least one node baseline")
	}
	baselineCounts := make(map[string]int, len(targets))
	nodes := make(map[string]struct{}, len(intent.Baselines))
	for _, baseline := range intent.Baselines {
		if err := validateOpaqueCheckpointValue("reboot baseline target", baseline.Target); err != nil {
			return err
		}
		if _, exists := targets[baseline.Target]; !exists {
			return fmt.Errorf("reboot baseline for node %q references unknown target %q", baseline.Node, baseline.Target)
		}
		if err := validateOpaqueCheckpointValue("reboot baseline node", baseline.Node); err != nil {
			return err
		}
		if _, exists := nodes[baseline.Node]; exists {
			return fmt.Errorf("reboot intent contains duplicate node baseline %q", baseline.Node)
		}
		nodes[baseline.Node] = struct{}{}
		if err := validateOpaqueCheckpointValue("reboot baseline boot ID", baseline.BootID); err != nil {
			return err
		}
		baselineCounts[baseline.Target]++
	}
	for _, target := range intent.Targets {
		if baselineCounts[target] == 0 {
			return fmt.Errorf("reboot target %q has no node baseline", target)
		}
	}
	return nil
}

func validateOpaqueCheckpointValue(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must not contain surrounding whitespace", name)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s must not contain control characters", name)
		}
	}
	return nil
}
