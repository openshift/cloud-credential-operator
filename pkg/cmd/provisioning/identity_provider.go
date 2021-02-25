package provisioning

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/openshift/cloud-credential-operator/pkg/aws"
)

var (
	// IdentityProviderOpts captures the options that affect creation of the identity provider
	IdentityProviderOpts = options{
		InfraName:     "",
		Region:        "",
		PublicKeyPath: "",
	}

	// discoveryDocumentTemplate is a template of the discovery document that needs to be populated with appropriate values
	discoveryDocumentTemplate = `{
	"issuer": "%s",
	"jwks_uri": "%s/%s",
    "response_types_supported": [
        "id_token"
    ],
    "subject_types_supported": [
        "public"
    ],
    "id_token_signing_alg_values_supported": [
        "RS256"
    ],
    "claims_supported": [
        "aud",
        "exp",
        "sub",
        "iat",
        "iss",
        "sub"
    ]
}`
)

type JSONWebKeySet struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

func createIdentityProvider(client aws.Client, infraName, region, publicKeyPath, targetDir string) error {
	bucketName := fmt.Sprintf("%s-installer", infraName)
	issuerURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com", bucketName, region)

	var bucketTagValue string
	_, err := client.CreateBucket(&s3.CreateBucketInput{
		Bucket: awssdk.String(bucketName),
	})
	if err != nil {
		var aerr awserr.Error
		if errors.As(err, &aerr) {
			switch aerr.Code() {
			case s3.ErrCodeBucketAlreadyOwnedByYou:
				bucketTagValue = sharedCcoctlAWSResourceTagValue
				log.Printf("Bucket %s already exists and is owned by the user", bucketName)
			default:
				return errors.Wrap(aerr, "Failed to create a bucket to store OpenID Connect configuration")
			}
		} else {
			return errors.Wrap(err, "Failed to create a bucket to store OpenID Connect configuration")
		}
	} else {
		bucketTagValue = ownedCcoctlAWSResourceTagValue
		log.Print("Bucket ", bucketName, " created")
	}

	_, err = client.PutBucketTagging(&s3.PutBucketTaggingInput{
		Bucket: awssdk.String(bucketName),
		Tagging: &s3.Tagging{
			TagSet: []*s3.Tag{
				{
					Key:   awssdk.String(fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, infraName)),
					Value: awssdk.String(bucketTagValue),
				},
			},
		},
	})
	if err != nil {
		return errors.Wrapf(err, "Failed to tag the bucket %s", bucketName)
	}

	discoveryDocumentJSON := fmt.Sprintf(discoveryDocumentTemplate, issuerURL, issuerURL, keysURI)
	_, err = client.PutObject(&s3.PutObjectInput{
		ACL:     awssdk.String("public-read"),
		Body:    awssdk.ReadSeekCloser(strings.NewReader(discoveryDocumentJSON)),
		Bucket:  awssdk.String(bucketName),
		Key:     awssdk.String(discoveryDocumentURI),
		Tagging: awssdk.String(fmt.Sprintf("%s/%s=%s", ccoctlAWSResourceTagKeyPrefix, infraName, ownedCcoctlAWSResourceTagValue)),
	})
	if err != nil {
		return errors.Wrapf(err, "Failed to upload discovery document in the S3 bucket %s", bucketName)
	}
	log.Printf("OpenID Connect discovery document in the S3 bucket %s at %s updated", bucketName, discoveryDocumentURI)

	err = saveToFile("discovery document", filepath.Join(targetDir, "oidc-configuration"), []byte(discoveryDocumentJSON))
	if err != nil {
		return err
	}

	jwks, err := buildJsonWebKeySet(publicKeyPath)
	if err != nil {
		return errors.Wrap(err, "Failed to build JSON web key set from the public key")
	}

	_, err = client.PutObject(&s3.PutObjectInput{
		ACL:     awssdk.String("public-read"),
		Body:    awssdk.ReadSeekCloser(bytes.NewReader(jwks)),
		Bucket:  awssdk.String(bucketName),
		Key:     awssdk.String(keysURI),
		Tagging: awssdk.String(fmt.Sprintf("%s/%s=%s", ccoctlAWSResourceTagKeyPrefix, infraName, ownedCcoctlAWSResourceTagValue)),
	})

	if err != nil {
		return errors.Wrapf(err, "Failed to upload JSON web key set (JWKS) in the S3 bucket %s", bucketName)
	}
	log.Printf("JSON web key set (JWKS) in the S3 bucket %s at %s updated", bucketName, keysURI)

	err = saveToFile("JSON web key set (JWKS)", filepath.Join(targetDir, "keys.json"), jwks)
	if err != nil {
		return err
	}

	oidcProviderList, err := client.ListOpenIDConnectProviders(&iam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		return errors.Wrap(err, "Failed to fetch list of Identity Providers")
	}

	var providerARN string
	for _, provider := range oidcProviderList.OpenIDConnectProviderList {
		ok, err := isExistingIdentifyProvider(client, *provider.Arn, infraName)
		if err != nil {
			return errors.Wrapf(err, "Failed to check existing Identity Provider %s", *provider.Arn)
		}

		if ok {
			providerARN = *provider.Arn
			log.Printf("Existing Identity Provider found with ARN: %s", providerARN)
			break
		}
	}

	if len(providerARN) == 0 {
		oidcOutput, err := client.CreateOpenIDConnectProvider(&iam.CreateOpenIDConnectProviderInput{
			ClientIDList: []*string{
				awssdk.String("openshift"),
				awssdk.String("sts.amazonaws.com"),
			},
			ThumbprintList: []*string{
				awssdk.String("A9D53002E97E00E043244F3D170D6F4C414104FD"), // root CA thumbprint for Amazon S3 (DigiCert)
			},
			Url: awssdk.String(issuerURL),
		})
		if err != nil {
			return errors.Wrap(err, "Failed to create Identity Provider")
		}

		providerARN = *oidcOutput.OpenIDConnectProviderArn

		_, err = client.TagOpenIDConnectProvider(&iam.TagOpenIDConnectProviderInput{
			OpenIDConnectProviderArn: &providerARN,
			Tags: []*iam.Tag{
				{
					Key:   awssdk.String(fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, infraName)),
					Value: awssdk.String(ownedCcoctlAWSResourceTagValue),
				},
			},
		})
		if err != nil {
			return errors.Wrapf(err, "Failed to tag the identity provider with arn: %s", providerARN)
		}

		log.Printf("Identity Provider created with ARN: %s", providerARN)
	}
	return nil
}

// buildJsonWebKeySet builds JSON web key set from the public key
func buildJsonWebKeySet(publicKeyPath string) ([]byte, error) {
	log.Print("Reading public key")
	publicKeyContent, err := ioutil.ReadFile(publicKeyPath)

	if err != nil {
		return nil, errors.Wrap(err, "Failed to read public key")
	}

	block, _ := pem.Decode(publicKeyContent)
	if block == nil {
		return nil, errors.Wrap(err, "Error decoding PEM file")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "Error parsing key content")
	}

	var alg jose.SignatureAlgorithm
	switch publicKey.(type) {
	case *rsa.PublicKey:
		alg = jose.RS256
	default:
		return nil, errors.New("Public key is not of type RSA")
	}

	kid, err := keyIDFromPublicKey(publicKey)
	if err != nil {
		return nil, errors.New("Failed to fetch key ID from public key")
	}

	var keys []jose.JSONWebKey
	keys = append(keys, jose.JSONWebKey{
		Key:       publicKey,
		KeyID:     kid,
		Algorithm: string(alg),
		Use:       "sig",
	})

	keySet, err := json.MarshalIndent(JSONWebKeySet{Keys: keys}, "", "    ")
	if err != nil {
		return nil, errors.New("JSON encoding of web key set failed")
	}

	return keySet, nil
}

// keyIDFromPublicKey derives a key ID non-reversibly from a public key
// reference: https://github.com/kubernetes/kubernetes/blob/0f140bf1eeaf63c155f5eba1db8db9b5d52d5467/pkg/serviceaccount/jwt.go#L89-L111
func keyIDFromPublicKey(publicKey interface{}) (string, error) {
	publicKeyDERBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to serialize public key to DER format: %v", err)
	}

	hasher := crypto.SHA256.New()
	hasher.Write(publicKeyDERBytes)
	publicKeyDERHash := hasher.Sum(nil)

	keyID := base64.RawURLEncoding.EncodeToString(publicKeyDERHash)

	return keyID, nil
}

// saveToFile saves the given data to a given file
func saveToFile(fileName, filePath string, data []byte) error {
	log.Printf("Saving %s locally at %s", fileName, filePath)
	f, err := os.Create(filePath)
	if err != nil {
		return errors.Wrapf(err, "Failed to create file %s to store %s", filePath, fileName)
	}
	_, err = f.Write(data)
	f.Close()
	if err != nil {
		return errors.Wrapf(err, "Failed to write %s to file %s", fileName, filePath)
	}
	return nil
}

// isExistingIdentifyProvider checks if given identity provider is owned by given infra name
func isExistingIdentifyProvider(client aws.Client, providerARN, infraName string) (bool, error) {
	provider, err := client.GetOpenIDConnectProvider(&iam.GetOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: awssdk.String(providerARN),
	})
	if err != nil {
		return false, errors.Wrapf(err, "Failed to get Identity Provider with ARN %s", providerARN)
	}

	for _, tag := range provider.Tags {
		if tag.Key == awssdk.String(fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, infraName)) {
			return true, nil
		}
	}
	return false, nil
}

func identityProviderCmd(cmd *cobra.Command, args []string) {
	cfg := &awssdk.Config{
		Region: awssdk.String(CreateOpts.Region),
	}

	s, err := session.NewSession(cfg)
	if err != nil {
		log.Fatal(err)
	}

	awsClient := aws.NewClientFromSession(s)

	err = createIdentityProvider(awsClient, CreateOpts.InfraName, CreateOpts.Region, CreateOpts.PublicKeyPath, CreateOpts.TargetDir)
	if err != nil {
		log.Fatal(err)
	}
}

// NewIdentityProviderSetup provides the "create identity-provider" subcommand
func NewIdentityProviderSetup() *cobra.Command {
	identityProviderSetupCmd := &cobra.Command{
		Use: "identity-provider",
		Run: identityProviderCmd,
	}

	identityProviderSetupCmd.PersistentFlags().StringVar(&CreateOpts.InfraName, "infra-name", "", "Name prefix for all created AWS resources")
	identityProviderSetupCmd.MarkPersistentFlagRequired("infra-name")
	identityProviderSetupCmd.PersistentFlags().StringVar(&CreateOpts.Region, "region", "", "AWS region where the S3 OpenID Connect endpoint will be created")
	identityProviderSetupCmd.MarkPersistentFlagRequired("region")
	identityProviderSetupCmd.PersistentFlags().StringVar(&CreateOpts.PublicKeyPath, "public-key", "", "Path to public ServiceAccount signing key")
	identityProviderSetupCmd.MarkPersistentFlagRequired("public-key")

	return identityProviderSetupCmd
}
