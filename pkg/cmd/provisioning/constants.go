package provisioning

const (
	// privateKeyFile is the name of the private key file created by "ccoctl create key-pair" command
	privateKeyFile = "serviceaccount-signer.private"
	// publicKeyFile is the name of the public key file created by "ccoctl create key-pair" command
	publicKeyFile = "serviceaccount-signer.public"
	// discoveryDocumentURI is a URI for the OpenID configuration discovery document
	discoveryDocumentURI = ".well-known/openid-configuration"
	// keysURI is a URI for public key that enables client to validate a JSON Web Token issued by the Identity Provider
	keysURI = "keys.json"
	// ccoctlAWSResourceTagKeyPrefix is the prefix of the tag key applied to the AWS resources created/shared by ccoctl
	ccoctlAWSResourceTagKeyPrefix = "openshift.io/cloud-credential-operator"
	// ownedCcoctlAWSResourceTagValue is the value of the tag applied to the AWS resources created by ccoctl
	ownedCcoctlAWSResourceTagValue = "owned"

	// Generated files

	// identity provider files
	oidcBucketFilename          = "01-oidc-bucket.json"
	oidcConfigurationFilename   = "02-openid-configuration"
	oidcKeysFilename            = "03-keys.json"
	iamIdentityProviderFilename = "04-iam-identity-provider.json"

	// role files
	roleFilenameFormat       = "05-%d-%s-role.json"
	rolePolicyFilenameFormat = "06-%d-%s-policy.json"
)
