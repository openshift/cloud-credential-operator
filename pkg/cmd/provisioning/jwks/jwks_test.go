package jwks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func TestNewSignerAndParse(t *testing.T) {
	_, keySet := newTestSigner(t)
	artifact, err := Encode(keySet)
	if err != nil {
		t.Fatalf("Encode() returned unexpected error: %v", err)
	}

	parsed, err := Parse(artifact.Data)
	if err != nil {
		t.Fatalf("Parse() returned unexpected error: %v", err)
	}
	if len(parsed.Keys) != 1 || parsed.Keys[0].KeyID != keySet.Keys[0].KeyID {
		t.Fatalf("parsed key set = %#v, want key ID %q", parsed, keySet.Keys[0].KeyID)
	}
	if parsed.Keys[0].Algorithm != string(jose.RS256) || parsed.Keys[0].Use != "sig" {
		t.Fatalf("parsed signer metadata = alg %q use %q", parsed.Keys[0].Algorithm, parsed.Keys[0].Use)
	}
}

func TestNewSignerAcceptsRSAPublicKeyLabelWithPKIXDER(t *testing.T) {
	publicPEM := newTestPublicPEM(t)
	block, remainder := pem.Decode(publicPEM)
	if block == nil || len(remainder) != 0 {
		t.Fatal("decode PKIX public-key fixture")
	}
	standard, err := NewSigner(publicPEM)
	if err != nil {
		t.Fatalf("NewSigner(PUBLIC KEY) returned unexpected error: %v", err)
	}

	rsaLabelPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: block.Bytes})
	got, err := NewSigner(rsaLabelPEM)
	if err != nil {
		t.Fatalf("NewSigner(RSA PUBLIC KEY with PKIX DER) returned unexpected error: %v", err)
	}
	if len(got.Keys) != 1 || got.Keys[0].KeyID != standard.Keys[0].KeyID {
		t.Fatalf("NewSigner(RSA PUBLIC KEY) = %#v, want key ID %q", got, standard.Keys[0].KeyID)
	}
}

func TestNewSignerRejectsInvalidPublicKey(t *testing.T) {
	validPEM := newTestPublicPEM(t)
	validBlock, remainder := pem.Decode(validPEM)
	if validBlock == nil || len(remainder) != 0 {
		t.Fatal("decode valid public-key fixture")
	}
	parsedPublicKey, err := x509.ParsePKIXPublicKey(validBlock.Bytes)
	if err != nil {
		t.Fatalf("parse valid public-key fixture: %v", err)
	}
	rsaPublicKey, ok := parsedPublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("valid public-key fixture has type %T, want RSA", parsedPublicKey)
	}
	wrongType := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: validBlock.Bytes})
	pkcs1Public := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(rsaPublicKey)})
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate private-key fixture: %v", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private-key fixture: %v", err)
	}
	privateAsPublic := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: privateDER})
	withHeaders := pem.EncodeToMemory(&pem.Block{
		Type:    "PUBLIC KEY",
		Headers: map[string]string{"Comment": "unexpected metadata"},
		Bytes:   validBlock.Bytes,
	})

	tests := []struct {
		name      string
		publicPEM []byte
		wantError string
	}{
		{name: "not PEM", publicPEM: []byte("not PEM"), wantError: "decode signer public key PEM"},
		{name: "leading junk", publicPEM: append([]byte("untrusted prefix\n"), validPEM...), wantError: "leading data"},
		{name: "wrong block type", publicPEM: wrongType, wantError: `block type must be "PUBLIC KEY" or "RSA PUBLIC KEY"`},
		{name: "PKCS1 public DER", publicPEM: pkcs1Public, wantError: "parse signer public key"},
		{name: "private DER with public label", publicPEM: privateAsPublic, wantError: "parse signer public key"},
		{name: "PEM headers", publicPEM: withHeaders, wantError: "must not contain headers"},
		{name: "trailing data", publicPEM: append(append([]byte(nil), validPEM...), []byte("trailing")...), wantError: "trailing data"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewSigner(test.publicPEM)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("NewSigner() error = %v, want error containing %q", err, test.wantError)
			}
		})
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal ECDSA public key: %v", err)
	}
	_, err = NewSigner(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if err == nil || !strings.Contains(err.Error(), "must be RSA") {
		t.Fatalf("NewSigner(ECDSA) error = %v, want RSA error", err)
	}
}

func TestNewSignerAllowsSurroundingWhitespace(t *testing.T) {
	validPEM := newTestPublicPEM(t)
	want, err := NewSigner(validPEM)
	if err != nil {
		t.Fatalf("NewSigner(valid fixture) returned unexpected error: %v", err)
	}
	wrapped := append([]byte(" \t\r\n"), validPEM...)
	wrapped = append(wrapped, []byte("\n\r\t ")...)

	got, err := NewSigner(wrapped)
	if err != nil {
		t.Fatalf("NewSigner(whitespace-wrapped fixture) returned unexpected error: %v", err)
	}
	if len(got.Keys) != 1 || got.Keys[0].KeyID != want.Keys[0].KeyID {
		t.Fatalf("NewSigner(whitespace-wrapped fixture) key set = %#v, want key ID %q", got, want.Keys[0].KeyID)
	}
}

func TestParseRejectsUnsafeJWKS(t *testing.T) {
	privateKey, validSet := newTestSigner(t)
	validArtifact, err := Encode(validSet)
	if err != nil {
		t.Fatalf("encode valid JWKS: %v", err)
	}

	wrongKeyID := validSet
	wrongKeyID.Keys = append([]jose.JSONWebKey(nil), validSet.Keys...)
	wrongKeyID.Keys[0].KeyID = "wrong-key-id"

	unsupportedAlgorithm := validSet
	unsupportedAlgorithm.Keys = append([]jose.JSONWebKey(nil), validSet.Keys...)
	unsupportedAlgorithm.Keys[0].Algorithm = "RS512"

	unsupportedUse := validSet
	unsupportedUse.Keys = append([]jose.JSONWebKey(nil), validSet.Keys...)
	unsupportedUse.Keys[0].Use = "enc"

	duplicate := validSet
	duplicate.Keys = append(append([]jose.JSONWebKey(nil), validSet.Keys...), validSet.Keys[0])

	privateSet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       privateKey,
		KeyID:     validSet.Keys[0].KeyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	ecdsaKeyID, err := KeyIDFromPublicKey(&ecdsaKey.PublicKey)
	if err != nil {
		t.Fatalf("derive ECDSA key ID: %v", err)
	}
	ecdsaSet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &ecdsaKey.PublicKey, KeyID: ecdsaKeyID, Use: "sig"}}}

	unknownTopLevel := append([]byte(nil), validArtifact.Data...)
	unknownTopLevel = []byte(strings.Replace(string(unknownTopLevel), "{", `{"unexpected":true,`, 1))
	unknownKeyField := []byte(strings.Replace(string(validArtifact.Data), `"kty"`, `"key_ops":["verify"],"kty"`, 1))
	nonRSAKeyField := []byte(strings.Replace(string(validArtifact.Data), `"kty"`, `"crv":"P-256","x":"ignored","kty"`, 1))
	privateFragment := []byte(strings.Replace(string(validArtifact.Data), `"kty"`, `"p":"AQAB","kty"`, 1))
	duplicateTopLevel := []byte(strings.Replace(string(validArtifact.Data), `"keys":`, `"keys":[],"keys":`, 1))
	duplicateKeyID := []byte(strings.Replace(string(validArtifact.Data), `"kid":`, `"kid":"duplicate","kid":`, 1))
	duplicateModulus := []byte(strings.Replace(string(validArtifact.Data), `"n":`, `"n":"AQ","n":`, 1))

	tests := []struct {
		name      string
		raw       []byte
		wantError string
	}{
		{name: "empty set", raw: []byte(`{"keys":[]}`), wantError: "at least one key"},
		{name: "malformed", raw: []byte(`{"keys":`), wantError: "decode JWKS"},
		{name: "unknown top-level field", raw: unknownTopLevel, wantError: "unknown field"},
		{name: "unsupported key field", raw: unknownKeyField, wantError: "unsupported field"},
		{name: "non-RSA key fields", raw: nonRSAKeyField, wantError: "unsupported field"},
		{name: "private key fragment", raw: privateFragment, wantError: "unsupported field"},
		{name: "duplicate top-level field", raw: duplicateTopLevel, wantError: "duplicate field"},
		{name: "duplicate key ID field", raw: duplicateKeyID, wantError: "duplicate field"},
		{name: "duplicate modulus field", raw: duplicateModulus, wantError: "duplicate field"},
		{name: "trailing JSON", raw: append(validArtifact.Data, []byte(`{}`)...), wantError: "trailing JSON value"},
		{name: "incorrect key ID", raw: mustMarshalKeySet(t, wrongKeyID), wantError: "does not match its public key"},
		{name: "unsupported algorithm", raw: mustMarshalKeySet(t, unsupportedAlgorithm), wantError: "unsupported algorithm"},
		{name: "unsupported use", raw: mustMarshalKeySet(t, unsupportedUse), wantError: "unsupported purpose"},
		{name: "duplicate key ID", raw: mustMarshalKeySet(t, duplicate), wantError: "duplicate key ID"},
		{name: "private key", raw: mustMarshalKeySet(t, privateSet), wantError: "unsupported field"},
		{name: "non-RSA key", raw: mustMarshalKeySet(t, ecdsaSet), wantError: "unsupported field"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(test.raw)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Parse() error = %v, want error containing %q", err, test.wantError)
			}
		})
	}
}

func TestKeyIDFromPublicKeyCompatibilityVector(t *testing.T) {
	publicKey := &rsa.PublicKey{N: big.NewInt(3233), E: 17}
	keyID, err := KeyIDFromPublicKey(publicKey)
	if err != nil {
		t.Fatalf("KeyIDFromPublicKey() returned unexpected error: %v", err)
	}
	const expectedKeyID = "6WtxEDjtjJdrMQPQXDEWDrhLO-JtqWqYWjji-yH4_2w"
	if keyID != expectedKeyID {
		t.Fatalf("KeyIDFromPublicKey() = %q, want %q", keyID, expectedKeyID)
	}
}

func TestMergeIsOrderedAndIdempotent(t *testing.T) {
	_, current := newTestSigner(t)
	_, replacement := newTestSigner(t)

	combined, err := Merge(current, replacement)
	if err != nil {
		t.Fatalf("Merge() returned unexpected error: %v", err)
	}
	if len(combined.Keys) != 2 {
		t.Fatalf("combined key count = %d, want 2", len(combined.Keys))
	}
	if combined.Keys[0].KeyID != current.Keys[0].KeyID || combined.Keys[1].KeyID != replacement.Keys[0].KeyID {
		t.Fatalf("combined key order = [%q %q], want [%q %q]", combined.Keys[0].KeyID, combined.Keys[1].KeyID, current.Keys[0].KeyID, replacement.Keys[0].KeyID)
	}

	retried, err := Merge(combined, replacement)
	if err != nil {
		t.Fatalf("Merge(retry) returned unexpected error: %v", err)
	}
	if len(retried.Keys) != 2 {
		t.Fatalf("retried key count = %d, want 2", len(retried.Keys))
	}
}

func TestMergeRejectsInvalidReplacement(t *testing.T) {
	_, current := newTestSigner(t)
	_, first := newTestSigner(t)
	_, second := newTestSigner(t)
	replacement := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{first.Keys[0], second.Keys[0]}}

	_, err := Merge(current, replacement)
	if err == nil || !strings.Contains(err.Error(), "exactly one key") {
		t.Fatalf("Merge() error = %v, want exactly-one-key error", err)
	}
}

func TestEncodeReturnsDigestAndKeyIDs(t *testing.T) {
	_, first := newTestSigner(t)
	_, second := newTestSigner(t)
	keySet := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{first.Keys[0], second.Keys[0]}}

	artifact, err := Encode(keySet)
	if err != nil {
		t.Fatalf("Encode() returned unexpected error: %v", err)
	}
	digest := sha256.Sum256(artifact.Data)
	if artifact.SHA256 != fmt.Sprintf("%x", digest) {
		t.Fatalf("artifact digest = %q, want %x", artifact.SHA256, digest)
	}
	if len(artifact.KeyIDs) != 2 || artifact.KeyIDs[0] != first.Keys[0].KeyID || artifact.KeyIDs[1] != second.Keys[0].KeyID {
		t.Fatalf("artifact key IDs = %v", artifact.KeyIDs)
	}
}

func newTestSigner(t *testing.T) (*rsa.PrivateKey, jose.JSONWebKeySet) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal RSA public key: %v", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	keySet, err := NewSigner(publicPEM)
	if err != nil {
		t.Fatalf("NewSigner() returned unexpected error: %v", err)
	}
	return privateKey, keySet
}

func newTestPublicPEM(t *testing.T) []byte {
	t.Helper()
	_, keySet := newTestSigner(t)
	der, err := x509.MarshalPKIXPublicKey(keySet.Keys[0].Key)
	if err != nil {
		t.Fatalf("marshal test public key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func mustMarshalKeySet(t *testing.T, keySet jose.JSONWebKeySet) []byte {
	t.Helper()
	raw, err := json.Marshal(keySet)
	if err != nil {
		t.Fatalf("marshal JWKS fixture: %v", err)
	}
	return raw
}
