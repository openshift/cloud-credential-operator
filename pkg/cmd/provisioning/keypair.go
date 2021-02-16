package provisioning

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

const (
	privateKeyFile = "serviceaccount-signer.private"
	publicKeyFile  = "serviceaccount-signer.public"
)

func createKeys(prefixDir string) error {

	privateKeyFilePath := filepath.Join(prefixDir, privateKeyFile)
	publicKeyFilePath := filepath.Join(prefixDir, publicKeyFile)
	bitSize := 4096

	_, err := os.Stat(privateKeyFilePath)
	if err == nil {
		log.Printf("Using existing RSA keypair found at %s", privateKeyFilePath)
		return nil
	}

	log.Print("Generating RSA keypair")
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return errors.Wrap(err, "Failed to generate private key")
	}

	log.Print("Writing private key to ", privateKeyFilePath)
	f, err := os.Create(privateKeyFilePath)
	if err != nil {
		return errors.Wrap(err, "Failed to create private key file")
	}

	err = pem.Encode(f, &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(privateKey),
	})
	f.Close()
	if err != nil {
		return errors.Wrap(err, "Failed to write out private key data")
	}

	log.Print("Writing public key to ", publicKeyFilePath)
	f, err = os.Create(publicKeyFilePath)
	if err != nil {
		errors.Wrap(err, "Failed to create public key file")
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		errors.Wrap(err, "Failed to generate public key from private")
	}

	err = pem.Encode(f, &pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   pubKeyBytes,
	})
	f.Close()
	if err != nil {
		errors.Wrap(err, "Failed to write out public key data")
	}
	return nil
}

func keyCmd(cmd *cobra.Command, args []string) {
	err := createKeys(CreateOpts.TargetDir)
	if err != nil {
		log.Fatal(err)
	}
}

// NewKeyProvision provides the "create key-pair" subcommand
func NewKeyProvision() *cobra.Command {
	keyProvisionCmd := &cobra.Command{
		Use: "key-pair",
		Run: keyCmd,
	}

	return keyProvisionCmd
}
