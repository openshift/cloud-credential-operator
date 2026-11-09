package jwks

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"unicode"

	jose "github.com/go-jose/go-jose/v4"
)

// Artifact is a validated, encoded public JWKS and the non-secret metadata
// needed to bind it to a rotation checkpoint.
type Artifact struct {
	Data   []byte
	SHA256 string
	KeyIDs []string
}

// Inspect validates an existing JWKS while preserving its exact bytes for
// recovery and digest comparison.
func Inspect(raw []byte) (Artifact, error) {
	var artifact Artifact
	keySet, err := Parse(raw)
	if err != nil {
		return artifact, err
	}
	digest := sha256.Sum256(raw)
	artifact.Data = append([]byte(nil), raw...)
	artifact.SHA256 = fmt.Sprintf("%x", digest)
	artifact.KeyIDs = make([]string, 0, len(keySet.Keys))
	for _, key := range keySet.Keys {
		artifact.KeyIDs = append(artifact.KeyIDs, key.KeyID)
	}
	return artifact, nil
}

// Parse decodes and validates an RSA signing-key set used by the OpenShift
// service-account issuer. Unknown top-level fields and trailing data fail
// closed, as do private, duplicate, or incorrectly identified keys.
func Parse(raw []byte) (jose.JSONWebKeySet, error) {
	var keySet jose.JSONWebKeySet
	fields, err := decodeJSONObjectFields(raw, "JWKS")
	if err != nil {
		return keySet, fmt.Errorf("decode JWKS: %w", err)
	}
	for field := range fields {
		if field != "keys" {
			return keySet, fmt.Errorf("decode JWKS: unknown field %q", field)
		}
	}
	encodedKeys, exists := fields["keys"]
	if !exists {
		return keySet, fmt.Errorf("decode JWKS: missing field %q", "keys")
	}
	var keys []json.RawMessage
	if err := json.Unmarshal(encodedKeys, &keys); err != nil {
		return keySet, fmt.Errorf("decode JWKS keys: %w", err)
	}

	keySet.Keys = make([]jose.JSONWebKey, 0, len(keys))
	for index, encodedKey := range keys {
		if err := validateEncodedKeyFields(index, encodedKey); err != nil {
			return keySet, err
		}
		var key jose.JSONWebKey
		if err := json.Unmarshal(encodedKey, &key); err != nil {
			return keySet, fmt.Errorf("decode JWKS key %d: %w", index, err)
		}
		keySet.Keys = append(keySet.Keys, key)
	}

	if err := Validate(keySet); err != nil {
		return keySet, err
	}
	return keySet, nil
}

func validateEncodedKeyFields(index int, encodedKey json.RawMessage) error {
	fields, err := decodeJSONObjectFields(encodedKey, fmt.Sprintf("JWKS key %d", index))
	if err != nil {
		return fmt.Errorf("decode JWKS key %d fields: %w", index, err)
	}
	for field := range fields {
		switch field {
		case "use", "kty", "kid", "alg", "n", "e", "x5c", "x5u", "x5t", "x5t#S256":
		default:
			return fmt.Errorf("JWKS key %d contains unsupported field %q", index, field)
		}
	}
	return nil
}

func decodeJSONObjectFields(raw []byte, context string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	opening, ok := token.(json.Delim)
	if !ok || opening != '{' {
		return nil, fmt.Errorf("%s must be a JSON object", context)
	}

	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		fieldToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		field, ok := fieldToken.(string)
		if !ok {
			return nil, fmt.Errorf("%s contains a non-string field name", context)
		}
		if _, exists := fields[field]; exists {
			return nil, fmt.Errorf("%s contains duplicate field %q", context, field)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[field] = value
	}
	closing, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != '}' {
		return nil, fmt.Errorf("%s has an invalid closing delimiter", context)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("unexpected trailing JSON value")
		}
		return nil, fmt.Errorf("decode trailing data: %w", err)
	}
	return fields, nil
}

// NewSigner creates a one-key JWKS from exactly one PEM-encoded PKIX RSA
// public-key block with no headers and only surrounding whitespace. OpenShift
// public signer ConfigMaps use both PUBLIC KEY and RSA PUBLIC KEY labels for
// PKIX-encoded public key bytes.
func NewSigner(publicPEM []byte) (jose.JSONWebKeySet, error) {
	var keySet jose.JSONWebKeySet
	trimmedLeading := bytes.TrimLeftFunc(publicPEM, unicode.IsSpace)
	block, remainder := pem.Decode(trimmedLeading)
	if block == nil {
		return keySet, fmt.Errorf("decode signer public key PEM")
	}
	switch block.Type {
	case "PUBLIC KEY", "RSA PUBLIC KEY":
	default:
		return keySet, fmt.Errorf("signer public key PEM block type must be %q or %q", "PUBLIC KEY", "RSA PUBLIC KEY")
	}
	if len(block.Headers) != 0 {
		return keySet, fmt.Errorf("signer public key PEM must not contain headers")
	}
	consumed := trimmedLeading[:len(trimmedLeading)-len(remainder)]
	openingMarker := []byte("-----BEGIN " + block.Type + "-----")
	if bytes.LastIndex(consumed, openingMarker) != 0 {
		return keySet, fmt.Errorf("signer public key PEM contains leading data")
	}
	if len(bytes.TrimSpace(remainder)) != 0 {
		return keySet, fmt.Errorf("signer public key PEM contains trailing data")
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return keySet, fmt.Errorf("parse signer public key: %w", err)
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return keySet, fmt.Errorf("signer public key must be RSA")
	}

	keyID, err := KeyIDFromPublicKey(publicKey)
	if err != nil {
		return keySet, err
	}
	keySet.Keys = []jose.JSONWebKey{{
		Key:       publicKey,
		KeyID:     keyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}
	return keySet, nil
}

// Merge preserves current-key order and appends the replacement once. A retry
// with the same replacement is idempotent; a repeated key ID with different
// key material fails closed.
func Merge(current, replacement jose.JSONWebKeySet) (jose.JSONWebKeySet, error) {
	var combined jose.JSONWebKeySet
	if err := Validate(current); err != nil {
		return combined, fmt.Errorf("validate current JWKS: %w", err)
	}
	if err := Validate(replacement); err != nil {
		return combined, fmt.Errorf("validate replacement JWKS: %w", err)
	}
	if len(replacement.Keys) != 1 {
		return combined, fmt.Errorf("replacement JWKS must contain exactly one key, got %d", len(replacement.Keys))
	}

	replacementKey := replacement.Keys[0]
	replacementDER, err := x509.MarshalPKIXPublicKey(replacementKey.Key)
	if err != nil {
		return combined, fmt.Errorf("serialize replacement public key: %w", err)
	}
	for _, currentKey := range current.Keys {
		if currentKey.KeyID != replacementKey.KeyID {
			continue
		}
		currentDER, err := x509.MarshalPKIXPublicKey(currentKey.Key)
		if err != nil {
			return combined, fmt.Errorf("serialize current public key %q: %w", currentKey.KeyID, err)
		}
		if !bytes.Equal(currentDER, replacementDER) {
			return combined, fmt.Errorf("key ID %q identifies different public keys", replacementKey.KeyID)
		}
		combined.Keys = append([]jose.JSONWebKey(nil), current.Keys...)
		return combined, nil
	}

	combined.Keys = make([]jose.JSONWebKey, 0, len(current.Keys)+1)
	combined.Keys = append(combined.Keys, current.Keys...)
	combined.Keys = append(combined.Keys, replacementKey)
	return combined, nil
}

// Encode validates and deterministically marshals a JWKS with the metadata used
// by rotation checkpoints.
func Encode(keySet jose.JSONWebKeySet) (Artifact, error) {
	var artifact Artifact
	if err := Validate(keySet); err != nil {
		return artifact, err
	}

	encoded, err := json.MarshalIndent(keySet, "", "  ")
	if err != nil {
		return artifact, fmt.Errorf("encode JWKS: %w", err)
	}
	encoded = append(encoded, '\n')
	digest := sha256.Sum256(encoded)

	artifact.Data = encoded
	artifact.SHA256 = fmt.Sprintf("%x", digest)
	artifact.KeyIDs = make([]string, 0, len(keySet.Keys))
	for _, key := range keySet.Keys {
		artifact.KeyIDs = append(artifact.KeyIDs, key.KeyID)
	}
	return artifact, nil
}

// Validate verifies the semantic constraints of service-account issuer keys.
func Validate(keySet jose.JSONWebKeySet) error {
	if len(keySet.Keys) == 0 {
		return fmt.Errorf("JWKS must contain at least one key")
	}

	seenKeyIDs := make(map[string]struct{}, len(keySet.Keys))
	for index := range keySet.Keys {
		key := &keySet.Keys[index]
		if !key.Valid() {
			return fmt.Errorf("JWKS key %d is invalid", index)
		}
		if !key.IsPublic() {
			return fmt.Errorf("JWKS key %d must contain public key material only", index)
		}
		publicKey, ok := key.Key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("JWKS key %d must be RSA", index)
		}
		if key.KeyID == "" || strings.TrimSpace(key.KeyID) != key.KeyID {
			return fmt.Errorf("JWKS key %d must have a non-empty key ID without surrounding whitespace", index)
		}
		expectedKeyID, err := KeyIDFromPublicKey(publicKey)
		if err != nil {
			return fmt.Errorf("derive JWKS key %d ID: %w", index, err)
		}
		if key.KeyID != expectedKeyID {
			return fmt.Errorf("JWKS key %d ID %q does not match its public key", index, key.KeyID)
		}
		if key.Algorithm != "" && key.Algorithm != string(jose.RS256) {
			return fmt.Errorf("JWKS key %q uses unsupported algorithm %q", key.KeyID, key.Algorithm)
		}
		if key.Use != "" && key.Use != "sig" {
			return fmt.Errorf("JWKS key %q uses unsupported purpose %q", key.KeyID, key.Use)
		}
		if _, exists := seenKeyIDs[key.KeyID]; exists {
			return fmt.Errorf("JWKS contains duplicate key ID %q", key.KeyID)
		}
		seenKeyIDs[key.KeyID] = struct{}{}
	}
	return nil
}

// KeyIDFromPublicKey derives the Kubernetes/OpenShift service-account key ID
// from the SHA-256 digest of the PKIX DER public key.
func KeyIDFromPublicKey(publicKey interface{}) (string, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("serialize public key to DER: %w", err)
	}
	digest := sha256.Sum256(publicKeyDER)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}
