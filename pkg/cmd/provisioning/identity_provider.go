package provisioning

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path"
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
		NamePrefix:    "",
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

	// S3 bucket template (usable with aws CLI --cli-input-json param)
	oidcBucketTemplateWithLocation = `{
	"ACL": "private",
	"Bucket": "%s",
	"CreateBucketConfiguration": {
		"LocationConstraint": "%s"
	}
}`
	// 'us-east-1' is the default region, and AWS returns an error if you try to set it
	oidcBucketTemplateWithoutLocation = `{
	"ACL": "private",
	"Bucket": "%s"
}`

	// iam identity provider with "openshift" and "sts.amazonaws.com" as static audiences
	iamIdentityProviderTemplate = `{
	"Url": "%s",
	"ClientIDList": [
		"openshift",
		"sts.amazonaws.com"
	],
	"ThumbprintList": [
		"%s"
	]
}
`
)

type JSONWebKeySet struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

func createIdentityProvider(client aws.Client, namePrefix, region, publicKeyPath, targetDir string, generateOnly bool) error {
	// Create the S3 bucket
	bucketName := fmt.Sprintf("%s-oidc", namePrefix)
	if err := createOIDCBucket(client, bucketName, namePrefix, region, targetDir, generateOnly); err != nil {
		return err
	}
	issuerURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com", bucketName, region)

	// Create the OIDC config file
	if err := createOIDCConfiguration(client, bucketName, issuerURL, namePrefix, targetDir, generateOnly); err != nil {
		return err
	}

	// Create the OIDC key list
	if err := createJSONWebKeySet(client, publicKeyPath, bucketName, namePrefix, targetDir, generateOnly); err != nil {
		return err
	}

	// Create the IAM Identity Provider
	if err := createIAMIdentityProvider(client, issuerURL, namePrefix, targetDir, generateOnly); err != nil {
		return err
	}

	return nil
}

func getTLSFingerprint(bucketURL string) (string, error) {
	u, err := url.Parse(bucketURL)
	if err != nil {
		return "", err
	}

	urlWithPort := fmt.Sprintf("%s:443", u.Host)

	conn, err := tls.Dial("tcp", urlWithPort, &tls.Config{})
	if err != nil {
		return "", err
	}

	certs := conn.ConnectionState().PeerCertificates
	numCerts := len(certs)

	fingerprint := sha1.Sum(certs[numCerts-1].Raw)
	var buf bytes.Buffer
	for _, f := range fingerprint {
		fmt.Fprintf(&buf, "%02X", f)
	}
	return buf.String(), nil
}

func createIAMIdentityProvider(client aws.Client, issuerURL, namePrefix, targetDir string, generateOnly bool) error {
	fingerprint, err := getTLSFingerprint(issuerURL)
	if err != nil {
		return errors.Wrap(err, "failed to get fingerprint")
	}

	if generateOnly {
		oidcIdentityProviderJSON := fmt.Sprintf(iamIdentityProviderTemplate, issuerURL, fingerprint)

		err := saveToFile("AWS IAM Identity Provider", filepath.Join(targetDir, iamIdentityProviderFilename), []byte(oidcIdentityProviderJSON))
		if err != nil {
			return errors.Wrap(err, "failed to save IAM Identity Provider file")
		}

	} else {
		oidcProviderList, err := client.ListOpenIDConnectProviders(&iam.ListOpenIDConnectProvidersInput{})
		if err != nil {
			return errors.Wrap(err, "failed to fetch list of Identity Providers")
		}

		var providerARN string
		for _, provider := range oidcProviderList.OpenIDConnectProviderList {
			ok, err := isExistingIdentifyProvider(client, *provider.Arn, namePrefix)
			if err != nil {
				return errors.Wrapf(err, "failed to check existing Identity Provider %s", *provider.Arn)
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
					awssdk.String(fingerprint),
				},
				Url: awssdk.String(issuerURL),
			})
			if err != nil {
				return errors.Wrap(err, "failed to create Identity Provider")
			}

			providerARN = *oidcOutput.OpenIDConnectProviderArn

			_, err = client.TagOpenIDConnectProvider(&iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &providerARN,
				Tags: []*iam.Tag{
					{
						Key:   awssdk.String(fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, namePrefix)),
						Value: awssdk.String(ownedCcoctlAWSResourceTagValue),
					},
				},
			})
			if err != nil {
				return errors.Wrapf(err, "failed to tag the identity provider with arn: %s", providerARN)
			}

			log.Printf("Identity Provider created with ARN: %s", providerARN)
		}
	}
	return nil
}

func createJSONWebKeySet(client aws.Client, publicKeyFilepath, bucketName, namePrefix, targetDir string, generateOnly bool) error {
	jwks, err := buildJsonWebKeySet(publicKeyFilepath)
	if err != nil {
		return errors.Wrap(err, "failed to build JSON web key set from the public key")
	}

	if generateOnly {
		err = saveToFile("JSON web key set (JWKS)", filepath.Join(targetDir, oidcKeysFilename), jwks)
		if err != nil {
			return errors.Wrap(err, "failed to save keys.json file")
		}
	} else {
		_, err = client.PutObject(&s3.PutObjectInput{
			ACL:     awssdk.String("public-read"),
			Body:    awssdk.ReadSeekCloser(bytes.NewReader(jwks)),
			Bucket:  awssdk.String(bucketName),
			Key:     awssdk.String(keysURI),
			Tagging: awssdk.String(fmt.Sprintf("%s/%s=%s", ccoctlAWSResourceTagKeyPrefix, namePrefix, ownedCcoctlAWSResourceTagValue)),
		})

		if err != nil {
			return errors.Wrapf(err, "failed to upload JSON web key set (JWKS) in the S3 bucket %s", bucketName)
		}
		log.Printf("JSON web key set (JWKS) in the S3 bucket %s at %s updated", bucketName, keysURI)
	}
	return nil
}

func createOIDCConfiguration(client aws.Client, bucketName, issuerURL, namePrefix, targetDir string, generateOnly bool) error {
	discoveryDocumentJSON := fmt.Sprintf(discoveryDocumentTemplate, issuerURL, issuerURL, keysURI)
	if generateOnly {
		err := saveToFile("discovery document", filepath.Join(targetDir, oidcConfigurationFilename), []byte(discoveryDocumentJSON))
		if err != nil {
			return errors.Wrap(err, "failed to save oidc configuration file")
		}
	} else {
		_, err := client.PutObject(&s3.PutObjectInput{
			ACL:     awssdk.String("public-read"),
			Body:    awssdk.ReadSeekCloser(strings.NewReader(discoveryDocumentJSON)),
			Bucket:  awssdk.String(bucketName),
			Key:     awssdk.String(discoveryDocumentURI),
			Tagging: awssdk.String(fmt.Sprintf("%s/%s=%s", ccoctlAWSResourceTagKeyPrefix, namePrefix, ownedCcoctlAWSResourceTagValue)),
		})
		if err != nil {
			return errors.Wrapf(err, "failed to upload discovery document in the S3 bucket %s", bucketName)
		}
		log.Printf("OpenID Connect discovery document in the S3 bucket %s at %s updated", bucketName, discoveryDocumentURI)
	}
	return nil
}

func createOIDCBucket(client aws.Client, bucketName, namePrefix, region, targetDir string, generateOnly bool) error {

	if generateOnly {
		oidcBucketFilepath := filepath.Join(targetDir, oidcBucketFilename)
		var oidcBucketJSON string
		switch region {
		case "us-east-1":
			oidcBucketJSON = fmt.Sprintf(oidcBucketTemplateWithoutLocation, bucketName)
		default:
			oidcBucketJSON = fmt.Sprintf(oidcBucketTemplateWithLocation, bucketName, region)
		}

		err := saveToFile("OIDC S3 bucket", oidcBucketFilepath, []byte(oidcBucketJSON))
		if err != nil {
			return errors.Wrap(err, "failed to save oidc bucket JSON file")
		}
	} else {
		s3BucketInput := &s3.CreateBucketInput{
			Bucket: awssdk.String(bucketName),
		}
		// can't constrain to 'us-east-1'...it is the default and will error if you specify it
		if region != "us-east-1" {
			s3BucketInput.CreateBucketConfiguration = &s3.CreateBucketConfiguration{
				LocationConstraint: awssdk.String(region),
			}
		}

		_, err := client.CreateBucket(s3BucketInput)
		if err != nil {
			var aerr awserr.Error
			if errors.As(err, &aerr) {
				switch aerr.Code() {
				case s3.ErrCodeBucketAlreadyOwnedByYou:
					log.Printf("Bucket %s already exists and is owned by the user", bucketName)
				default:
					return errors.Wrap(aerr, "failed to create a bucket to store OpenID Connect configuration")
				}
			} else {
				return errors.Wrap(err, "failed to create a bucket to store OpenID Connect configuration")
			}
		} else {
			log.Print("Bucket ", bucketName, " created")
			_, err = client.PutBucketTagging(&s3.PutBucketTaggingInput{
				Bucket: awssdk.String(bucketName),
				Tagging: &s3.Tagging{
					TagSet: []*s3.Tag{
						{
							Key:   awssdk.String(fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, namePrefix)),
							Value: awssdk.String(ownedCcoctlAWSResourceTagValue),
						},
					},
				},
			})
			if err != nil {
				return errors.Wrapf(err, "failed to tag the bucket %s", bucketName)
			}
		}
	}

	return nil
}

// buildJsonWebKeySet builds JSON web key set from the public key
func buildJsonWebKeySet(publicKeyPath string) ([]byte, error) {
	log.Print("Reading public key")
	publicKeyContent, err := ioutil.ReadFile(publicKeyPath)

	if err != nil {
		return nil, errors.Wrap(err, "failed to read public key")
	}

	block, _ := pem.Decode(publicKeyContent)
	if block == nil {
		return nil, errors.Wrap(err, "frror decoding PEM file")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing key content")
	}

	var alg jose.SignatureAlgorithm
	switch publicKey.(type) {
	case *rsa.PublicKey:
		alg = jose.RS256
	default:
		return nil, errors.New("public key is not of type RSA")
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
func saveToFile(filePurpose, filePath string, data []byte) error {
	log.Printf("Saving %s locally at %s", filePurpose, filePath)
	f, err := os.Create(filePath)
	if err != nil {
		return errors.Wrapf(err, "failed to create file %s to store %s", filePath, filePurpose)
	}
	_, err = f.Write(data)
	f.Close()
	if err != nil {
		return errors.Wrapf(err, "failed to write %s to file %s", filePurpose, filePath)
	}
	return nil
}

// isExistingIdentifyProvider checks if given identity provider is owned by given name prefix
func isExistingIdentifyProvider(client aws.Client, providerARN, namePrefix string) (bool, error) {
	provider, err := client.GetOpenIDConnectProvider(&iam.GetOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: awssdk.String(providerARN),
	})
	if err != nil {
		return false, errors.Wrapf(err, "failed to get Identity Provider with ARN %s", providerARN)
	}

	for _, tag := range provider.Tags {
		if tag.Key == awssdk.String(fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, namePrefix)) {
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

	publicKeyPath := CreateOpts.PublicKeyPath
	if publicKeyPath == "" {
		publicKeyPath = path.Join(CreateOpts.TargetDir, publicKeyFile)
	}

	err = createIdentityProvider(awsClient, CreateOpts.NamePrefix, CreateOpts.Region, publicKeyPath, CreateOpts.TargetDir, CreateOpts.DryRun)
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

	identityProviderSetupCmd.PersistentFlags().StringVar(&CreateOpts.NamePrefix, "name-prefix", "", "Name prefix for all created AWS resources")
	identityProviderSetupCmd.MarkPersistentFlagRequired("name-prefix")
	identityProviderSetupCmd.PersistentFlags().StringVar(&CreateOpts.Region, "region", "", "AWS region where the S3 OpenID Connect endpoint will be created")
	identityProviderSetupCmd.MarkPersistentFlagRequired("region")
	identityProviderSetupCmd.PersistentFlags().StringVar(&CreateOpts.PublicKeyPath, "public-key-file", "", "Path to public ServiceAccount signing key")
	identityProviderSetupCmd.PersistentFlags().BoolVar(&CreateOpts.DryRun, "dry-run", false, "Skip creating objects, and just save what would have been created into files")

	return identityProviderSetupCmd
}
