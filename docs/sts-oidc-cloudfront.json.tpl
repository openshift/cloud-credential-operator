{
    "DistributionConfig": {
        "CallerReference": "${CLUSTER_NAME}",
        "Aliases": {
            "Quantity": 0
        },
        "Origins": {
            "Quantity": 1,
            "Items": [
            {
                "Id": "${OIDC_BUCKET_NAME}.s3.${CLUSTER_REGION}.amazonaws.com",
                "DomainName": "${OIDC_BUCKET_NAME}.s3.${CLUSTER_REGION}.amazonaws.com",
                "OriginPath": "${OIDC_BUCKET_PATH}",
                "CustomHeaders": {
                    "Quantity": 0
                },
                "S3OriginConfig": {
                    "OriginAccessIdentity": "origin-access-identity/cloudfront/${OAI_CLOUDFRONT_ID}"
                },
                "ConnectionAttempts": 3,
                "ConnectionTimeout": 10,
                "OriginShield": {
                "Enabled": false
                }
            }
            ]
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "${OIDC_BUCKET_NAME}.s3.${CLUSTER_REGION}.amazonaws.com",
            "TrustedSigners": {
                "Enabled": false,
                "Quantity": 0
            },
            "TrustedKeyGroups": {
                "Enabled": false,
                "Quantity": 0
            },
            "ViewerProtocolPolicy": "https-only",
            "AllowedMethods": {
                "Quantity": 2,
                "Items": [
                    "HEAD",
                    "GET"
                ],
                "CachedMethods": {
                    "Quantity": 2,
                    "Items": [
                        "HEAD",
                        "GET"
                    ]
                }
            },
            "SmoothStreaming": false,
            "Compress": false,
            "LambdaFunctionAssociations": {
                "Quantity": 0
            },
            "FunctionAssociations": {
                "Quantity": 0
            },
            "FieldLevelEncryptionId": "",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
        },
        "CacheBehaviors": {
            "Quantity": 0
        },
        "CustomErrorResponses": {
            "Quantity": 0
        },
        "Comment": "${CLUSTER_NAME}",
        "Logging": {
            "Enabled": false,
            "IncludeCookies": false,
            "Bucket": "",
            "Prefix": ""
        },
        "PriceClass": "PriceClass_All",
        "Enabled": true,
        "ViewerCertificate": {
            "CloudFrontDefaultCertificate": true
        }
    },
    "Tags": {
        "Items": [
            {
                "Key": "Name",
                "Value": "${CLUSTER_NAME}"
            }
        ]
    }
}
