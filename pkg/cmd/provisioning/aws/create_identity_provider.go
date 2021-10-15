package aws

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/openshift/cloud-credential-operator/pkg/aws"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
)

var (
	// CreateIdentityProviderOpts captures the options that affect creation of the identity provider
	CreateIdentityProviderOpts = options{
		Name:          "",
		Region:        "",
		PublicKeyPath: "",
		TargetDir:     "",
	}

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
	// ccoctlAWSResourceTagKeyPrefix is the prefix of the tag key applied to the AWS resources created/shared by ccoctl
	ccoctlAWSResourceTagKeyPrefix = "openshift.io/cloud-credential-operator"
	// ownedCcoctlAWSResourceTagValue is the value of the tag applied to the AWS resources created by ccoctl
	ownedCcoctlAWSResourceTagValue = "owned"
	// nameTagKey is the key of the "Name" tag applied to the AWS resources created by ccoctl
	nameTagKey = "Name"
	// Generated identity provider files
	oidcBucketFilename          = "01-oidc-bucket.json"
	oidcConfigurationFilename   = "02-openid-configuration"
	oidcKeysFilename            = "03-keys.json"
	iamIdentityProviderFilename = "04-iam-identity-provider.json"
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
	if err := provisioning.CreateClusterAuthentication(issuerURL, targetDir); err != nil {
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

		iamIdentityProviderFullPath := filepath.Join(targetDir, iamIdentityProviderFilename)
		log.Printf("Saving AWS IAM Identity Provider locally at %s", iamIdentityProviderFullPath)
		if err := ioutil.WriteFile(iamIdentityProviderFullPath, []byte(oidcIdentityProviderJSON), fileModeCcoctlDryRun); err != nil {
			return "", errors.Wrap(err, fmt.Sprintf("Failed to save AWS IAM Identity Provider locally at %s", iamIdentityProviderFullPath))
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
	jwks, err := provisioning.BuildJsonWebKeySet(publicKeyFilepath)
	if err != nil {
		return errors.Wrap(err, "failed to build JSON web key set from the public key")
	}

	if generateOnly {
		oidcKeysFullPath := filepath.Join(targetDir, oidcKeysFilename)
		log.Printf("Saving JSON web key set (JWKS) locally at %s", oidcKeysFullPath)
		if err := ioutil.WriteFile(oidcKeysFullPath, jwks, fileModeCcoctlDryRun); err != nil {
			return errors.Wrap(err, fmt.Sprintf("Failed to save JSON web key set (JWKS) locally at %s", oidcKeysFullPath))
		}
	} else {
		_, err = client.PutObject(&s3.PutObjectInput{
			ACL:     awssdk.String("public-read"),
			Body:    awssdk.ReadSeekCloser(bytes.NewReader(jwks)),
			Bucket:  awssdk.String(bucketName),
			Key:     awssdk.String(provisioning.KeysURI),
			Tagging: awssdk.String(fmt.Sprintf("%s/%s=%s&%s=%s", ccoctlAWSResourceTagKeyPrefix, name, ownedCcoctlAWSResourceTagValue, nameTagKey, name)),
		})

		if err != nil {
			return errors.Wrapf(err, "failed to upload JSON web key set (JWKS) in the S3 bucket %s", bucketName)
		}
		log.Printf("JSON web key set (JWKS) in the S3 bucket %s at %s updated", bucketName, provisioning.KeysURI)
	}
	return nil
}

func createOIDCConfiguration(client aws.Client, bucketName, issuerURL, name, targetDir string, generateOnly bool) error {
	discoveryDocumentJSON := fmt.Sprintf(provisioning.DiscoveryDocumentTemplate, issuerURL, issuerURL, provisioning.KeysURI)
	if generateOnly {
		oidcConfigurationFullPath := filepath.Join(targetDir, oidcConfigurationFilename)
		log.Printf("Saving discovery document locally at %s", oidcConfigurationFullPath)
		if err := ioutil.WriteFile(oidcConfigurationFullPath, []byte(discoveryDocumentJSON), fileModeCcoctlDryRun); err != nil {
			return errors.Wrap(err, fmt.Sprintf("Failed to save discovery document locally at %s", oidcConfigurationFullPath))
		}
	} else {
		_, err := client.PutObject(&s3.PutObjectInput{
			ACL:     awssdk.String("public-read"),
			Body:    awssdk.ReadSeekCloser(strings.NewReader(discoveryDocumentJSON)),
			Bucket:  awssdk.String(bucketName),
			Key:     awssdk.String(provisioning.DiscoveryDocumentURI),
			Tagging: awssdk.String(fmt.Sprintf("%s/%s=%s&%s=%s", ccoctlAWSResourceTagKeyPrefix, name, ownedCcoctlAWSResourceTagValue, nameTagKey, name)),
		})
		if err != nil {
			return errors.Wrapf(err, "failed to upload discovery document in the S3 bucket %s", bucketName)
		}
		log.Printf("OpenID Connect discovery document in the S3 bucket %s at %s updated", bucketName, provisioning.DiscoveryDocumentURI)
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

		log.Printf("Saving OIDC S3 bucket locally at %s", oidcBucketFilepath)
		if err := ioutil.WriteFile(oidcBucketFilepath, []byte(oidcBucketJSON), fileModeCcoctlDryRun); err != nil {
			return errors.Wrap(err, fmt.Sprintf("Failed to save OIDC S3 bucket locally at %s", oidcBucketFilepath))
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

func createIdentityProviderCmd(cmd *cobra.Command, args []string) {
	s, err := awsSession(CreateIdentityProviderOpts.Region)
	if err != nil {
		log.Fatal(err)
	}

	awsClient := aws.NewClientFromSession(s)

	publicKeyPath := CreateIdentityProviderOpts.PublicKeyPath
	if publicKeyPath == "" {
		publicKeyPath = filepath.Join(CreateIdentityProviderOpts.TargetDir, provisioning.PublicKeyFile)
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
	manifestsDir := filepath.Join(fPath, provisioning.ManifestsDirName)
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
