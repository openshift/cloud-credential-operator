package aws

import (
	"bytes"
	"context"
	"crypto/sha1"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

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

	// Block public access to S3 bucket template (usable with aws CLI --cli-input-json param)
	blockPublicAccessToOidcBucketTemplate = `{
	"Bucket": "%s",
	"PublicAccessBlockConfiguration": {
        "BlockPublicAcls": true,
        "IgnorePublicAcls": true,
        "BlockPublicPolicy": true,
        "RestrictPublicBuckets": true
    }
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
	// oidcBucketTemplateAllowingOAIAccess is the S3 bucket policy allowing access to CloudFront Origin Access Identity
	oidcBucketTemplateAllowingOAIAccess = `{
    "Version": "2008-10-17",
    "Id": "PolicyForCloudFrontPrivateContent",
    "Statement": [
        {
            "Sid": "1",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity %s"
            },
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::%s/*"
        }
    ]
}`
	// cloudFrontOriginAccessIdentityTemplate is the template for CloudFront Origin Access Identity (usable with aws CLI --cli-input-json param)
	cloudFrontOriginAccessIdentityTemplate = `{
   "CloudFrontOriginAccessIdentityConfig":{
      "CallerReference":"%s",
      "Comment":"%s"
   }
}`
	// putBucketPolicyToAllowOriginAccessIdentityTemplate is a template for making OIDC S3 bucket accessible by
	// CloudFront Origin Access Identity (usable with aws CLI --cli-input-json param)
	putBucketPolicyToAllowOriginAccessIdentityTemplate = `{
        "Bucket": "%s",
        "Policy": "{\"Version\":\"2008-10-17\",\"Id\":\"PolicyForCloudFrontPrivateContent\",\"Statement\":[{\"Sid\":\"1\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::cloudfront:user\/CloudFront Origin Access Identity <enter_cloudfront_origin_access_identity_here>\"},\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::%s\/*\"}]}"
}`
	// cloudFrontDistributionWithTagsTemplate is a template for creating CloudFront Distribution with tags
	// (usable with aws CLI --cli-input-json param)
	cloudFrontDistributionWithTagsTemplate = `{
   "DistributionConfigWithTags":{
      "DistributionConfig":{
         "CallerReference":"%s",
         "Aliases":{
            "Quantity":0
         },
         "Origins":{
            "Quantity":1,
            "Items":[
               {
                  "Id":"%s.s3.%s.%s",
                  "DomainName":"%s.s3.%s.%s",
                  "OriginPath":"",
                  "CustomHeaders":{
                     "Quantity":0
                  },
                  "S3OriginConfig":{
                     "OriginAccessIdentity":"origin-access-identity/cloudfront/<enter_cloudfront_origin_access_identity_here>"
                  },
                  "ConnectionAttempts":3,
                  "ConnectionTimeout":10,
                  "OriginShield":{
                     "Enabled":false
                  }
               }
            ]
         },
         "DefaultCacheBehavior":{
            "TargetOriginId":"%s.s3.%s.%s",
            "TrustedSigners":{
               "Enabled":false,
               "Quantity":0
            },
            "TrustedKeyGroups":{
               "Enabled":false,
               "Quantity":0
            },
            "ViewerProtocolPolicy":"https-only",
            "AllowedMethods":{
               "Quantity":2,
               "Items":[
                  "HEAD",
                  "GET"
               ],
               "CachedMethods":{
                  "Quantity":2,
                  "Items":[
                     "HEAD",
                     "GET"
                  ]
               }
            },
            "SmoothStreaming":false,
            "Compress":false,
            "LambdaFunctionAssociations":{
               "Quantity":0
            },
            "FunctionAssociations":{
               "Quantity":0
            },
            "FieldLevelEncryptionId":"",
            "CachePolicyId":"4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
         },
         "CacheBehaviors":{
            "Quantity":0
         },
         "CustomErrorResponses":{
            "Quantity":0
         },
         "Comment":"%s",
         "Logging":{
            "Enabled":false,
            "IncludeCookies":false,
            "Bucket":"",
            "Prefix":""
         },
         "PriceClass":"PriceClass_All",
         "Enabled":true,
         "ViewerCertificate":{
            "CloudFrontDefaultCertificate":true
         }
      },
      "Tags":{
         "Items":[
            {
               "Key":"Name",
               "Value":"%s"
            }
         ]
      }
   }
}`

	readOnlyAnonUserPolicyTemplate = `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "AllowReadPublicAccess",
				"Principal": "*",
				"Effect": "Allow",
				"Action": [
					"s3:GetObject"
				],
				"Resource": [
					"arn:%s:s3:::%s/*"
				]
			}
		]
}`

	// ccoctlAWSResourceTagKeyPrefix is the prefix of the tag key applied to the AWS resources created/shared by ccoctl
	ccoctlAWSResourceTagKeyPrefix = "openshift.io/cloud-credential-operator"
	// ownedCcoctlAWSResourceTagValue is the value of the tag applied to the AWS resources created by ccoctl
	ownedCcoctlAWSResourceTagValue = "owned"
	// nameTagKey is the key of the "Name" tag applied to the AWS resources created by ccoctl
	nameTagKey = "Name"
	// cloudFrontCachingDisabledPolicyID is the ID of the policy that disables caching for a CloudFront distribution
	cloudFrontCachingDisabledPolicyID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
	// cloudFrontDistributionDeployedStatus is status of the CloudFront when it is fully deployed
	cloudFrontDistributionDeployedStatus = "Deployed"
	// cloudFrontDistributionStatusCheckDelay is the time delay between subsequent status checks of CloudFront distribution
	cloudFrontDistributionStatusCheckDelay = time.Second * 30
	// cloudFrontOriginAccessIdentityActivationGracePeriod is a period to allow CloudFront Origin Access Identity to become
	// active
	cloudFrontOriginAccessIdentityActivationGracePeriod = time.Second * 30
	// placeholderCloudFrontURL is a placeholder for cloudfront distribution URL that user needs to enter after generating files
	placeholderCloudFrontURL = "<enter_cloudfront_distribution_url_here>"
	// Generated identity provider files
	oidcBucketFilename                                 = "01-oidc-bucket.json"
	oidcConfigurationFilename                          = "02-openid-configuration"
	oidcKeysFilename                                   = "03-keys.json"
	iamIdentityProviderFilename                        = "04-iam-identity-provider.json"
	cloudFrontOriginAccessIdentityFilename             = "05-cloudfront-origin-access-identity.json"
	putBucketPolicyToAllowOriginAccessIdentityFilename = "06-put-bucket-policy-to-allow-origin-access-identity.json"
	blockPublicAccessToOidcBucketFilename              = "07-block-public-access-to-oidc-bucket.json"
	cloudFrontDistributionFilename                     = "08-cloudfront-distribution.json"
)

func createIdentityProvider(client aws.Client, name, region, publicKeyPath, targetDir string, createPrivateS3, generateOnly bool) (string, error) {
	// Create the S3 bucket and (if specified) a CloudFront Distribution to serve OIDC endpoint
	bucketName := fmt.Sprintf("%s-oidc", name)
	issuerURL, err := createOIDCEndpoint(client, bucketName, name, region, targetDir, createPrivateS3, generateOnly)
	if err != nil {
		return "", err
	}

	// Create the OIDC config file
	if err := createOIDCConfiguration(client, bucketName, issuerURL, name, targetDir, createPrivateS3, generateOnly); err != nil {
		return "", err
	}

	// Create the OIDC key list
	if err := createJSONWebKeySet(client, publicKeyPath, bucketName, name, targetDir, createPrivateS3, generateOnly); err != nil {
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
	client := http.DefaultClient
	resp, err := client.Head(bucketURL)
	if err != nil {
		return "", errors.Wrapf(err, "error validating TLS Fingerprint")
	}
	defer resp.Body.Close()

	if resp.TLS == nil {
		return "", errors.Wrapf(err, "unable to get TLS connection from URL %s", bucketURL)
	}
	if resp.TLS.PeerCertificates == nil {
		return "", errors.Wrapf(err, "unable to get TLS PeerCertificates from connection URL %s", bucketURL)
	}

	certs := resp.TLS.PeerCertificates

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

	if generateOnly {
		oidcIdentityProviderJSON := fmt.Sprintf(iamIdentityProviderTemplate, issuerURL, "<enter_tls_fingerprint_for_issuer_url_here>")
		iamIdentityProviderFullPath := filepath.Join(targetDir, iamIdentityProviderFilename)
		log.Printf("Saving AWS IAM Identity Provider locally at %s", iamIdentityProviderFullPath)
		if err := os.WriteFile(iamIdentityProviderFullPath, []byte(oidcIdentityProviderJSON), fileModeCcoctlDryRun); err != nil {
			return "", errors.Wrap(err, fmt.Sprintf("Failed to save AWS IAM Identity Provider locally at %s", iamIdentityProviderFullPath))
		}

	} else {
		fingerprint, err := getTLSFingerprint(issuerURL)
		if err != nil {
			return "", errors.Wrap(err, "failed to get fingerprint")
		}

		oidcProviderList, err := client.ListOpenIDConnectProviders(context.Background(), &iam.ListOpenIDConnectProvidersInput{})
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
			oidcOutput, err := client.CreateOpenIDConnectProvider(context.Background(), &iam.CreateOpenIDConnectProviderInput{
				ClientIDList: []string{
					"openshift",
					"sts.amazonaws.com",
				},
				ThumbprintList: []string{
					fingerprint,
				},
				Url: awssdk.String(issuerURL),
			})
			if err != nil {
				return "", errors.Wrap(err, "failed to create Identity Provider")
			}

			providerARN = *oidcOutput.OpenIDConnectProviderArn

			_, err = client.TagOpenIDConnectProvider(context.Background(), &iam.TagOpenIDConnectProviderInput{
				OpenIDConnectProviderArn: &providerARN,
				Tags: []iamtypes.Tag{
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

func createJSONWebKeySet(client aws.Client, publicKeyFilepath, bucketName, name, targetDir string, createPrivateS3, generateOnly bool) error {
	jwks, err := provisioning.BuildJsonWebKeySet(publicKeyFilepath)
	if err != nil {
		return errors.Wrap(err, "failed to build JSON web key set from the public key")
	}

	if generateOnly {
		oidcKeysFullPath := filepath.Join(targetDir, oidcKeysFilename)
		log.Printf("Saving JSON web key set (JWKS) locally at %s", oidcKeysFullPath)
		if err := os.WriteFile(oidcKeysFullPath, jwks, fileModeCcoctlDryRun); err != nil {
			return errors.Wrap(err, fmt.Sprintf("Failed to save JSON web key set (JWKS) locally at %s", oidcKeysFullPath))
		}
	} else {
		_, err = client.PutObject(context.Background(), &s3.PutObjectInput{
			Body:    bytes.NewReader(jwks),
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

func createOIDCConfiguration(client aws.Client, bucketName, issuerURL, name, targetDir string, createPrivateS3, generateOnly bool) error {
	discoveryDocumentJSON := fmt.Sprintf(provisioning.DiscoveryDocumentTemplate, issuerURL, issuerURL, provisioning.KeysURI)
	if generateOnly {
		oidcConfigurationFullPath := filepath.Join(targetDir, oidcConfigurationFilename)
		log.Printf("Saving discovery document locally at %s", oidcConfigurationFullPath)
		if err := os.WriteFile(oidcConfigurationFullPath, []byte(discoveryDocumentJSON), fileModeCcoctlDryRun); err != nil {
			return errors.Wrap(err, fmt.Sprintf("Failed to save discovery document locally at %s", oidcConfigurationFullPath))
		}
	} else {
		_, err := client.PutObject(context.Background(), &s3.PutObjectInput{
			Body:    strings.NewReader(discoveryDocumentJSON),
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

func getDNSSuffix(region string) (string, error) {
	resolver := s3.NewDefaultEndpointResolverV2()
	endpoint, err := resolver.ResolveEndpoint(context.Background(), s3.EndpointParameters{
		Region: &region,
	})
	if err != nil {
		return "", err
	}

	parsedURL, err := url.Parse(endpoint.URI.String())
	if err != nil {
		return "", errors.Wrapf(err, "failed to parse endpoint URL: %s", endpoint.URI.String())
	}

	hostParts := strings.Split(parsedURL.Hostname(), ".")
	if len(hostParts) < 3 {
		return "", fmt.Errorf("invalid hostname: %s", parsedURL.Hostname())
	}

	return strings.Join(hostParts[2:], "."), nil
}

func getPartition(region string) (string, error) {
	if strings.HasPrefix(region, "us-gov-") {
		return "aws-us-gov", nil
	}
	if strings.HasPrefix(region, "cn-") {
		return "aws-cn", nil
	}
	return "aws", nil
}

func createOIDCEndpoint(client aws.Client, bucketName, name, region, targetDir string, createPrivateS3, generateOnly bool) (string, error) {
	dnsSuffix, err := getDNSSuffix(region)
	if err != nil {
		return "", err
	}

	s3BucketURL := fmt.Sprintf("https://%s.s3.%s.%s", bucketName, region, dnsSuffix)

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
		if err := os.WriteFile(oidcBucketFilepath, []byte(oidcBucketJSON), fileModeCcoctlDryRun); err != nil {
			return "", errors.Wrap(err, fmt.Sprintf("Failed to save OIDC S3 bucket locally at %s", oidcBucketFilepath))
		}

		if createPrivateS3 {
			cloudFrontOriginAccessIdentityFilepath := filepath.Join(targetDir, cloudFrontOriginAccessIdentityFilename)
			cloudFrontOriginAccessIdentityJSON := fmt.Sprintf(cloudFrontOriginAccessIdentityTemplate, name, fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, name))
			log.Printf("Saving JSON to create CloudFront Origin Access Identity locally at %s", cloudFrontOriginAccessIdentityFilepath)
			if err := os.WriteFile(cloudFrontOriginAccessIdentityFilepath, []byte(cloudFrontOriginAccessIdentityJSON), fileModeCcoctlDryRun); err != nil {
				return "", errors.Wrap(err, fmt.Sprintf("Failed to save JSON to create CloudFront Origin Access Identity locally at %s", cloudFrontOriginAccessIdentityFilepath))
			}

			putBucketPolicyToAllowOriginAccessIdentityFilepath := filepath.Join(targetDir, putBucketPolicyToAllowOriginAccessIdentityFilename)
			putBucketPolicyToAllowOriginAccessIdentityJSON := fmt.Sprintf(putBucketPolicyToAllowOriginAccessIdentityTemplate, bucketName, bucketName)
			log.Printf("Saving JSON to put bucket policy allowing access from CloudFront Origin Access Identity locally at %s", putBucketPolicyToAllowOriginAccessIdentityFilepath)
			if err := os.WriteFile(putBucketPolicyToAllowOriginAccessIdentityFilepath, []byte(putBucketPolicyToAllowOriginAccessIdentityJSON), fileModeCcoctlDryRun); err != nil {
				return "", errors.Wrap(err, fmt.Sprintf("Failed to save JSON to put bucket policy allowing access from CloudFront Origin Access Identity locally at %s", putBucketPolicyToAllowOriginAccessIdentityFilepath))
			}

			blockPublicAccessToOidcBucketFilepath := filepath.Join(targetDir, blockPublicAccessToOidcBucketFilename)
			blockPublicAccessToOidcBucketJSON := fmt.Sprintf(blockPublicAccessToOidcBucketTemplate, bucketName)
			log.Printf("Saving JSON to block public access to OIDC S3 bucket locally at %s", oidcBucketFilepath)
			if err := os.WriteFile(blockPublicAccessToOidcBucketFilepath, []byte(blockPublicAccessToOidcBucketJSON), fileModeCcoctlDryRun); err != nil {
				return "", errors.Wrap(err, fmt.Sprintf("Failed to save JSON to block public access to OIDC S3 bucket locally at %s", blockPublicAccessToOidcBucketFilepath))
			}

			cloudFrontDistributionFilepath := filepath.Join(targetDir, cloudFrontDistributionFilename)
			cloudFrontDistributionJSON := fmt.Sprintf(cloudFrontDistributionWithTagsTemplate, name, bucketName, region, dnsSuffix, bucketName, region, dnsSuffix, bucketName, region, dnsSuffix, fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, name), name)
			log.Printf("Saving JSON to create CloudFront Distribution locally at %s", cloudFrontDistributionFilepath)
			if err := os.WriteFile(cloudFrontDistributionFilepath, []byte(cloudFrontDistributionJSON), fileModeCcoctlDryRun); err != nil {
				return "", errors.Wrap(err, fmt.Sprintf("Failed to save JSON to create CloudFront Distribution locally at %s", cloudFrontDistributionFilepath))
			}

			return placeholderCloudFrontURL, nil
		}
	} else {
		s3BucketInput := &s3.CreateBucketInput{
			Bucket: awssdk.String(bucketName),
		}
		// can't constrain to 'us-east-1'...it is the default and will error if you specify it
		if region != "us-east-1" {
			s3BucketInput.CreateBucketConfiguration = &s3types.CreateBucketConfiguration{
				LocationConstraint: s3types.BucketLocationConstraint(region),
			}
		}

		_, err := client.CreateBucket(context.Background(), s3BucketInput)
		if err != nil {
			var aerr *s3types.BucketAlreadyOwnedByYou
			if !errors.As(err, &aerr) {
				return "", errors.Wrap(err, "failed to create a bucket to store OpenID Connect configuration")
			}
			log.Printf("Bucket %s already exists and is owned by the user", bucketName)
			if createPrivateS3 {
				// find the cloudfront distribution
				paginator := cloudfront.NewListDistributionsPaginator(client, &cloudfront.ListDistributionsInput{})
				for paginator.HasMorePages() {
					distList, err := paginator.NextPage(context.TODO())
					if err != nil {
						return "", errors.Wrap(err, "failed to list cloudfront distributions")
					}

					if distList.DistributionList == nil {
						// No distributions found at all
						break
					}

					s3OriginDomainName := fmt.Sprintf("%s.s3.%s.%s", bucketName, region, dnsSuffix)
					for _, dist := range distList.DistributionList.Items {
						for _, origin := range dist.Origins.Items {
							if awssdk.ToString(origin.DomainName) == s3OriginDomainName {
								log.Printf("Found existing CloudFront distribution %s for S3 bucket %s", awssdk.ToString(dist.Id), bucketName)
								cloudFrontURL := fmt.Sprintf("https://%s", awssdk.ToString(dist.DomainName))
								return cloudFrontURL, nil
							}
						}
					}
				}
				return "", fmt.Errorf("found S3 bucket %s but no matching CloudFront distribution", bucketName)
			}

		} else {
			log.Print("Bucket ", bucketName, " created")
			_, err = client.PutBucketTagging(context.Background(), &s3.PutBucketTaggingInput{
				Bucket: awssdk.String(bucketName),
				Tagging: &s3types.Tagging{
					TagSet: []s3types.Tag{
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
				return "", errors.Wrapf(err, "failed to tag the bucket %s", bucketName)
			}

			if createPrivateS3 {
				createOriginAccessIdentityOutput, err := client.CreateCloudFrontOriginAccessIdentity(context.Background(), &cloudfront.CreateCloudFrontOriginAccessIdentityInput{
					CloudFrontOriginAccessIdentityConfig: &cftypes.CloudFrontOriginAccessIdentityConfig{
						CallerReference: awssdk.String(name),
						Comment:         awssdk.String(fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, name)),
					},
				})
				if err != nil {
					return "", errors.Wrapf(err, "failed to create CloudFront origin access identity")
				}
				originAccessIdentityID := *createOriginAccessIdentityOutput.CloudFrontOriginAccessIdentity.Id
				log.Printf("CloudFront origin access identity created with ID %s, waiting %s for it to become active", originAccessIdentityID, cloudFrontOriginAccessIdentityActivationGracePeriod)
				// CloudFront origin access identity takes some time to become active. Adding policy to bucket before
				// it gets active results in an error. Introducing a delay to avoid it.
				time.Sleep(cloudFrontOriginAccessIdentityActivationGracePeriod)

				oidcBucketPolicyAllowingOAIAccess := fmt.Sprintf(oidcBucketTemplateAllowingOAIAccess, originAccessIdentityID, bucketName)
				_, err = client.PutBucketPolicy(context.Background(), &s3.PutBucketPolicyInput{
					Bucket: awssdk.String(bucketName),
					Policy: awssdk.String(oidcBucketPolicyAllowingOAIAccess),
				})
				if err != nil {
					return "", errors.Wrapf(err, "failed to add policy for the bucket %s", bucketName)
				}
				log.Printf("Update policy for bucket %s to allow access from CloudFront origin access identity with ID %s", bucketName, originAccessIdentityID)

				_, err = client.PutPublicAccessBlock(context.Background(), &s3.PutPublicAccessBlockInput{
					Bucket: awssdk.String(bucketName),
					PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
						BlockPublicAcls:       awssdk.Bool(true),
						BlockPublicPolicy:     awssdk.Bool(true),
						IgnorePublicAcls:      awssdk.Bool(true),
						RestrictPublicBuckets: awssdk.Bool(true),
					},
				})
				if err != nil {
					return "", errors.Wrapf(err, "failed to block public access for the bucket %s", bucketName)
				}
				log.Printf("Blocked public access for the bucket %s", bucketName)

				cloudFrontDistributionDomainName := fmt.Sprintf("%s.s3.%s.%s", bucketName, region, dnsSuffix)
				cloudFrontDistributionOriginAccessIdentity := fmt.Sprintf("origin-access-identity/cloudfront/%s", originAccessIdentityID)
				createCloudFrontDistributionOutput, err := client.CreateDistributionWithTags(context.Background(), &cloudfront.CreateDistributionWithTagsInput{
					DistributionConfigWithTags: &cftypes.DistributionConfigWithTags{
						DistributionConfig: &cftypes.DistributionConfig{
							CallerReference: awssdk.String(name),
							Comment:         awssdk.String(fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, name)),
							Origins: &cftypes.Origins{
								Items: []cftypes.Origin{
									{
										Id:         awssdk.String(s3BucketURL),
										DomainName: awssdk.String(cloudFrontDistributionDomainName),
										S3OriginConfig: &cftypes.S3OriginConfig{
											OriginAccessIdentity: awssdk.String(cloudFrontDistributionOriginAccessIdentity),
										},
									},
								},
								Quantity: awssdk.Int32(1),
							},
							Enabled: awssdk.Bool(true),
							DefaultCacheBehavior: &cftypes.DefaultCacheBehavior{
								AllowedMethods: &cftypes.AllowedMethods{
									Quantity: awssdk.Int32(2),
									Items: []cftypes.Method{
										cftypes.MethodHead,
										cftypes.MethodGet,
									},
									CachedMethods: &cftypes.CachedMethods{
										Quantity: awssdk.Int32(2),
										Items: []cftypes.Method{
											cftypes.MethodHead,
											cftypes.MethodGet,
										},
									},
								},
								TargetOriginId:       awssdk.String(s3BucketURL),
								ViewerProtocolPolicy: cftypes.ViewerProtocolPolicyHttpsOnly,
								CachePolicyId:        awssdk.String(cloudFrontCachingDisabledPolicyID),
							},
							ViewerCertificate: &cftypes.ViewerCertificate{
								CloudFrontDefaultCertificate: awssdk.Bool(true),
							},
						},
						Tags: &cftypes.Tags{
							Items: []cftypes.Tag{
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
					},
				})
				if err != nil {
					return "", errors.Wrapf(err, "failed to create CloudFront Distribution")
				}
				distributionID := *createCloudFrontDistributionOutput.Distribution.Id
				log.Printf("CloudFront distribution created with ID %s", distributionID)

				for {
					getCloudFrontDistributionOutput, err := client.GetDistribution(context.Background(), &cloudfront.GetDistributionInput{
						Id: &distributionID,
					})
					if err != nil {
						return "", errors.Wrapf(err, "failed to get CloudFront Distribution with ID %v", distributionID)
					}

					if *getCloudFrontDistributionOutput.Distribution.Status == cloudFrontDistributionDeployedStatus {
						log.Printf("CloudFront distribution with ID %s is successfully deployed", distributionID)
						break
					}
					log.Printf("Waiting %s for CloudFront distribution with ID %s to be deployed...", cloudFrontDistributionStatusCheckDelay, distributionID)
					time.Sleep(cloudFrontDistributionStatusCheckDelay)
				}
				cloudFrontURL := fmt.Sprintf("https://%s", *createCloudFrontDistributionOutput.Distribution.DomainName)
				return cloudFrontURL, nil
			} else {
				// Allow policies to control public access to the bucket.
				// Continue to disallow ACLs from controlling public access to the bucket.
				_, err = client.PutPublicAccessBlock(context.Background(), &s3.PutPublicAccessBlockInput{
					Bucket: awssdk.String(bucketName),
					PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
						BlockPublicAcls:       awssdk.Bool(true),
						BlockPublicPolicy:     awssdk.Bool(false),
						IgnorePublicAcls:      awssdk.Bool(true),
						RestrictPublicBuckets: awssdk.Bool(false),
					},
				})
				if err != nil {
					return "", errors.Wrapf(err, "failed to allow public access for the bucket %s", bucketName)
				}

				partition, err := getPartition(region)
				if err != nil {
					return "", errors.Wrapf(err, "failed to determine partition for region %s", region)
				}
				_, err = client.PutBucketPolicy(context.Background(), &s3.PutBucketPolicyInput{
					Bucket: awssdk.String(bucketName),
					Policy: awssdk.String(fmt.Sprintf(readOnlyAnonUserPolicyTemplate, partition, bucketName)),
				})
				if err != nil {
					return "", errors.Wrapf(err, "failed to apply public access policy to the bucket %s", bucketName)
				}

			}

		}
	}
	return s3BucketURL, nil
}

// isExistingIdentifyProvider checks if given identity provider is owned by given name prefix
func isExistingIdentifyProvider(client aws.Client, providerARN, namePrefix string) (bool, error) {
	provider, err := client.GetOpenIDConnectProvider(context.Background(), &iam.GetOpenIDConnectProviderInput{
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
	awsClient, err := newAWSClient(CreateIdentityProviderOpts.Region)
	if err != nil {
		log.Fatal(err)
	}

	publicKeyPath := CreateIdentityProviderOpts.PublicKeyPath
	if publicKeyPath == "" {
		publicKeyPath = filepath.Join(CreateIdentityProviderOpts.TargetDir, provisioning.PublicKeyFile)
	}

	_, err = createIdentityProvider(awsClient, CreateIdentityProviderOpts.Name, CreateIdentityProviderOpts.Region, publicKeyPath, CreateIdentityProviderOpts.TargetDir, CreateIdentityProviderOpts.CreatePrivateS3Bucket, CreateIdentityProviderOpts.DryRun)
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
	createIdentityProviderCmd.PersistentFlags().BoolVar(&CreateIdentityProviderOpts.CreatePrivateS3Bucket, "create-private-s3-bucket", false, "Create private S3 bucket with public CloudFront OIDC endpoint")

	return createIdentityProviderCmd
}
