package rotation

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"

	jwkutil "github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/jwks"
)

func TestPrepareJWKSArtifacts(t *testing.T) {
	currentPEM := testPublicKeyPEM(t)
	replacementPEM := testPublicKeyPEM(t)
	currentSet, err := jwkutil.NewSigner(currentPEM)
	if err != nil {
		t.Fatalf("create current JWKS: %v", err)
	}
	currentEncoded, err := jwkutil.Encode(currentSet)
	if err != nil {
		t.Fatalf("encode current JWKS: %v", err)
	}
	currentRaw := append([]byte(" \n"), currentEncoded.Data...)

	artifacts, err := PrepareJWKSArtifacts(currentRaw, replacementPEM)
	if err != nil {
		t.Fatalf("PrepareJWKSArtifacts() returned unexpected error: %v", err)
	}
	if !bytes.Equal(artifacts.Current.Data, currentRaw) {
		t.Fatal("current recovery artifact did not preserve provider bytes")
	}
	if len(artifacts.New.KeyIDs) != 1 {
		t.Fatalf("new artifact key IDs = %v, want one", artifacts.New.KeyIDs)
	}
	if len(artifacts.Combined.KeyIDs) != 2 {
		t.Fatalf("combined artifact key IDs = %v, want two", artifacts.Combined.KeyIDs)
	}
	if artifacts.Combined.KeyIDs[0] != currentEncoded.KeyIDs[0] || artifacts.Combined.KeyIDs[1] != artifacts.New.KeyIDs[0] {
		t.Fatalf("combined key order = %v, want current then replacement", artifacts.Combined.KeyIDs)
	}

	retried, err := PrepareJWKSArtifacts(artifacts.Combined.Data, replacementPEM)
	if err != nil {
		t.Fatalf("PrepareJWKSArtifacts(retry) returned unexpected error: %v", err)
	}
	if !bytes.Equal(retried.Combined.Data, artifacts.Combined.Data) {
		t.Fatal("retry changed an already combined JWKS")
	}
}

func TestPrepareJWKSArtifactsRejectsInvalidInputs(t *testing.T) {
	validPEM := testPublicKeyPEM(t)
	validSet, err := jwkutil.NewSigner(validPEM)
	if err != nil {
		t.Fatalf("create valid JWKS: %v", err)
	}
	validArtifact, err := jwkutil.Encode(validSet)
	if err != nil {
		t.Fatalf("encode valid JWKS: %v", err)
	}

	tests := []struct {
		name           string
		current        []byte
		replacementPEM []byte
		wantError      string
	}{
		{name: "invalid current JWKS", current: []byte(`{"keys":[]}`), replacementPEM: validPEM, wantError: "parse current JWKS"},
		{name: "invalid replacement public key", current: validArtifact.Data, replacementPEM: []byte("not PEM"), wantError: "build replacement JWKS"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := PrepareJWKSArtifacts(test.current, test.replacementPEM)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("PrepareJWKSArtifacts() error = %v, want error containing %q", err, test.wantError)
			}
		})
	}
}

func TestPrepareJWKSArtifactsPreservesSupportedCurrentMetadata(t *testing.T) {
	currentSet, err := jwkutil.NewSigner(testPublicKeyPEM(t))
	if err != nil {
		t.Fatalf("create current JWKS: %v", err)
	}
	certificateURL, err := url.Parse("https://issuer.example.test/certificate.pem")
	if err != nil {
		t.Fatalf("parse certificate URL: %v", err)
	}
	currentSet.Keys[0].CertificatesURL = certificateURL
	currentSet.Keys[0].CertificateThumbprintSHA1 = bytes.Repeat([]byte{0x11}, 20)
	currentSet.Keys[0].CertificateThumbprintSHA256 = bytes.Repeat([]byte{0x22}, 32)
	currentArtifact, err := jwkutil.Encode(currentSet)
	if err != nil {
		t.Fatalf("encode current JWKS: %v", err)
	}

	prepared, err := PrepareJWKSArtifacts(currentArtifact.Data, testPublicKeyPEM(t))
	if err != nil {
		t.Fatalf("PrepareJWKSArtifacts() returned unexpected error: %v", err)
	}
	combined, err := jwkutil.Parse(prepared.Combined.Data)
	if err != nil {
		t.Fatalf("parse combined JWKS: %v", err)
	}
	current := combined.Keys[0]
	if current.CertificatesURL == nil || current.CertificatesURL.String() != certificateURL.String() {
		t.Fatalf("combined certificate URL = %v, want %v", current.CertificatesURL, certificateURL)
	}
	if !bytes.Equal(current.CertificateThumbprintSHA1, currentSet.Keys[0].CertificateThumbprintSHA1) {
		t.Fatal("combined JWKS did not preserve the current SHA-1 certificate thumbprint")
	}
	if !bytes.Equal(current.CertificateThumbprintSHA256, currentSet.Keys[0].CertificateThumbprintSHA256) {
		t.Fatal("combined JWKS did not preserve the current SHA-256 certificate thumbprint")
	}
}

func testPublicKeyPEM(t *testing.T) []byte {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal RSA public key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
}
