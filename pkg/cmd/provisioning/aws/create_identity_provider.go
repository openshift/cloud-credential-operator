package aws

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
	"path/filepath"
	"strings"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"

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
	// CreateIdentityProviderOpts captures the options that affect creation of the identity provider
	CreateIdentityProviderOpts = options{
		Name:          "",
		Region:        "",
		PublicKeyPath: "",
		TargetDir:     "",
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

func createIdentityProvider(client aws.Client, name, region, publicKeyPath, targetDir string, generateOnly bool) (string, error) {
	// Create the S3 bucket
	bucketName := fmt.Sprintf("%s-oidc", name)
	if err := createOIDCBucket(client, bucketName, name, region, targetDir, generateOnly); err != nil {
		return "", err
	}
	issuerURL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com", bucketName, region)

	// Create the OIDC config file
	if err := createOIDCConfiguration(client, bucketName, issuerURL, name, targetDir, generateOnly); err != nil {
		return "", err
	}

	// Create the OIDC key list
	if err := createJSONWebKeySet(client, publicKeyPath, bucketName, name, targetDir, generateOnly); err != nil {
		return "", err
	}

	// Create the IAM Identity Provider
	identityProviderARN, err := createIAMIdentityProvider(client, issuerURL, name, targetDir, generateOnly)
	if err != nil {
		return "", err
	}

	// Create the installer manifest file
	if err := createClusterAuthentication(issuerURL, targetDir); err != nil {
		return "", err
	}

	return identityProviderARN, nil
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

func createIAMIdentityProvider(client aws.Client, issuerURL, name, targetDir string, generateOnly bool) (string, error) {
	var providerARN string

	fingerprint, err := getTLSFingerprint(issuerURL)
	if err != nil {
		return "", errors.Wrap(err, "failed to get fingerprint")
	}

	if generateOnly {
		oidcIdentityProviderJSON := fmt.Sprintf(iamIdentityProviderTemplate, issuerURL, fingerprint)

		err := saveToFile("AWS IAM Identity Provider", filepath.Join(targetDir, iamIdentityProviderFilename), []byte(oidcIdentityProviderJSON))
		if err != nil {
			return "", errors.Wrap(err, "failed to save IAM Identity Provider file")
		}

	} else {
		oidcProviderList, err := client.ListOpenIDConnectProviders(&iam.ListOpenIDConnectProvidersInput{})
		if err != nil {
			return "", errors.Wrap(err, "failed to fetch list of Identity Providers")
		}

		for _, provider := range oidcProviderList.OpenIDConnectProviderList {
			ok, err := isExistingIdentifyProvider(client, *provider.Arn, name)
			if err != nil {
				return "", errors.Wrapf(err, "failed to check existing Identity Provider %s", *provider.Arn)
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
				return "", errors.Wrap(err, "failed to create Identity Provider")
			}

			providerARN = *oidcOutput.OpenIDConnectProviderArn

			_, err = client.TagOpenIDConnectProvider(&iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &providerARN,
				Tags: []*iam.Tag{
					{
						Key:   awssdk.String(fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, name)),
						Value: awssdk.String(ownedCcoctlAWSResourceTagValue),
					},
					{
						Key:   awssdk.String(nameTagKey),
						Value: awssdk.String(name),
					},
				},
			})
			if err != nil {
				return "", errors.Wrapf(err, "failed to tag the identity provider with arn: %s", providerARN)
			}

			log.Printf("Identity Provider created with ARN: %s", providerARN)
		}
	}
	return providerARN, nil
}

func createJSONWebKeySet(client aws.Client, publicKeyFilepath, bucketName, name, targetDir string, generateOnly bool) error {
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
			Tagging: awssdk.String(fmt.Sprintf("%s/%s=%s&%s=%s", ccoctlAWSResourceTagKeyPrefix, name, ownedCcoctlAWSResourceTagValue, nameTagKey, name)),
		})

		if err != nil {
			return errors.Wrapf(err, "failed to upload JSON web key set (JWKS) in the S3 bucket %s", bucketName)
		}
		log.Printf("JSON web key set (JWKS) in the S3 bucket %s at %s updated", bucketName, keysURI)
	}
	return nil
}

func createOIDCConfiguration(client aws.Client, bucketName, issuerURL, name, targetDir string, generateOnly bool) error {
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
			Tagging: awssdk.String(fmt.Sprintf("%s/%s=%s&%s=%s", ccoctlAWSResourceTagKeyPrefix, name, ownedCcoctlAWSResourceTagValue, nameTagKey, name)),
		})
		if err != nil {
			return errors.Wrapf(err, "failed to upload discovery document in the S3 bucket %s", bucketName)
		}
		log.Printf("OpenID Connect discovery document in the S3 bucket %s at %s updated", bucketName, discoveryDocumentURI)
	}
	return nil
}

func createOIDCBucket(client aws.Client, bucketName, name, region, targetDir string, generateOnly bool) error {

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
							Key:   awssdk.String(fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, name)),
							Value: awssdk.String(ownedCcoctlAWSResourceTagValue),
						},
						{
							Key:   awssdk.String(nameTagKey),
							Value: awssdk.String(name),
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
		if *tag.Key == fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, namePrefix) {
			return true, nil
		}
	}
	return false, nil
}

func createClusterAuthentication(issuerURL, targetDir string) error {
	clusterAuthenticationTemplate := `apiVersion: config.openshift.io/v1
kind: Authentication
metadata:
  name: cluster
spec:
  serviceAccountIssuer: %s`

	clusterAuthFile := filepath.Join(targetDir, manifestsDirName, "cluster-authentication-02-config.yaml")

	fileData := fmt.Sprintf(clusterAuthenticationTemplate, issuerURL)
	if err := ioutil.WriteFile(clusterAuthFile, []byte(fileData), 0600); err != nil {
		return errors.Wrap(err, "failed to save cluster authentication file")
	}
	return nil
}

func createIdentityProviderCmd(cmd *cobra.Command, args []string) {
	cfg := &awssdk.Config{
		Region: awssdk.String(CreateIdentityProviderOpts.Region),
	}

	s, err := session.NewSession(cfg)
	if err != nil {
		log.Fatal(err)
	}

	awsClient := aws.NewClientFromSession(s)

	publicKeyPath := CreateIdentityProviderOpts.PublicKeyPath
	if publicKeyPath == "" {
		publicKeyPath = filepath.Join(CreateIdentityProviderOpts.TargetDir, publicKeyFile)
	}

	_, err = createIdentityProvider(awsClient, CreateIdentityProviderOpts.Name, CreateIdentityProviderOpts.Region, publicKeyPath, CreateIdentityProviderOpts.TargetDir, CreateIdentityProviderOpts.DryRun)
	if err != nil {
		log.Fatal(err)
	}
}

// initEnvForCreateIdentityProviderCmd will ensure the destination directory is ready to receive the generated
// files, and will create the directory if necessary.
func initEnvForCreateIdentityProviderCmd(cmd *cobra.Command, args []string) {
	if CreateIdentityProviderOpts.TargetDir == "" {
		pwd, err := os.Getwd()
		if err != nil {
			log.Fatalf("Failed to get current directory: %s", err)
		}

		CreateIdentityProviderOpts.TargetDir = pwd
	}

	fPath, err := filepath.Abs(CreateIdentityProviderOpts.TargetDir)
	if err != nil {
		log.Fatalf("Failed to resolve full path: %s", err)
	}

	// create target dir if necessary
	err = provisioning.EnsureDir(fPath)
	if err != nil {
		log.Fatalf("failed to create target directory at %s", fPath)
	}

	// create manifests dir if necessary
	manifestsDir := filepath.Join(fPath, manifestsDirName)
	err = provisioning.EnsureDir(manifestsDir)
	if err != nil {
		log.Fatalf("failed to create manifests directory at %s", manifestsDir)
	}
}

// NewCreateIdentityProviderCmd provides the "create-identity-provider" subcommand
func NewCreateIdentityProviderCmd() *cobra.Command {
	createIdentityProviderCmd := &cobra.Command{
		Use:              "create-identity-provider",
		Short:            "Create IAM identity provider",
		Run:              createIdentityProviderCmd,
		PersistentPreRun: initEnvForCreateIdentityProviderCmd,
	}

	createIdentityProviderCmd.PersistentFlags().StringVar(&CreateIdentityProviderOpts.Name, "name", "", "User-defined name for all created AWS resources (can be separate from the cluster's infra-id)")
	createIdentityProviderCmd.MarkPersistentFlagRequired("name")
	createIdentityProviderCmd.PersistentFlags().StringVar(&CreateIdentityProviderOpts.Region, "region", "", "AWS region where the S3 OpenID Connect endpoint will be created")
	createIdentityProviderCmd.MarkPersistentFlagRequired("region")
	createIdentityProviderCmd.PersistentFlags().StringVar(&CreateIdentityProviderOpts.PublicKeyPath, "public-key-file", "", "Path to public ServiceAccount signing key")
	createIdentityProviderCmd.PersistentFlags().BoolVar(&CreateIdentityProviderOpts.DryRun, "dry-run", false, "Skip creating objects, and just save what would have been created into files")
	createIdentityProviderCmd.PersistentFlags().StringVar(&CreateIdentityProviderOpts.TargetDir, "output-dir", "", "Directory to place generated files (defaults to current directory)")

	return createIdentityProviderCmd
}
