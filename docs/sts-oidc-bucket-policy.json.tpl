{
    "Version": "2008-10-17",
    "Id": "PolicyForCloudFrontPrivateContent",
    "Statement": [
        {
            "Sid": "1",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity ${OAI_CLOUDFRONT_ID}"
            },
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::${OIDC_BUCKET_NAME}/*"
        }
    ]
}
