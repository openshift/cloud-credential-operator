package rotation

import (
	"fmt"

	jwkutil "github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/jwks"
)

// PreparedJWKSArtifacts contains the exact validated provider state plus the
// deterministic replacement-only and overlapping key sets needed by rotation.
type PreparedJWKSArtifacts struct {
	Current  jwkutil.Artifact
	New      jwkutil.Artifact
	Combined jwkutil.Artifact
}

// PrepareJWKSArtifacts validates the provider's current JWKS and a replacement
// signer public key, then builds idempotent new-only and combined artifacts.
// The current artifact preserves the provider bytes exactly for recovery.
func PrepareJWKSArtifacts(currentRaw, replacementPublicPEM []byte) (PreparedJWKSArtifacts, error) {
	var artifacts PreparedJWKSArtifacts
	currentSet, err := jwkutil.Parse(currentRaw)
	if err != nil {
		return artifacts, fmt.Errorf("parse current JWKS: %w", err)
	}
	artifacts.Current, err = jwkutil.Inspect(currentRaw)
	if err != nil {
		return artifacts, fmt.Errorf("inspect current JWKS: %w", err)
	}

	replacementSet, err := jwkutil.NewSigner(replacementPublicPEM)
	if err != nil {
		return artifacts, fmt.Errorf("build replacement JWKS: %w", err)
	}
	artifacts.New, err = jwkutil.Encode(replacementSet)
	if err != nil {
		return artifacts, fmt.Errorf("encode replacement JWKS: %w", err)
	}

	combinedSet, err := jwkutil.Merge(currentSet, replacementSet)
	if err != nil {
		return artifacts, fmt.Errorf("merge current and replacement JWKS: %w", err)
	}
	artifacts.Combined, err = jwkutil.Encode(combinedSet)
	if err != nil {
		return artifacts, fmt.Errorf("encode combined JWKS: %w", err)
	}

	return artifacts, nil
}
