package provisioning

const (
	// PrivateKeyFile is the name of the private key file created by "ccoctl create key-pair" command
	PrivateKeyFile = "serviceaccount-signer.private"
	// PublicKeyFile is the name of the public key file created by "ccoctl create key-pair" command
	PublicKeyFile = "serviceaccount-signer.public"
	// DiscoveryDocumentURI is a URI for the OpenID configuration discovery document
	DiscoveryDocumentURI = ".well-known/openid-configuration"
	// KeysURI is a URI for public key that enables client to validate a JSON Web Token issued by the Identity Provider
	KeysURI = "keys.json"
	// ManifestsDirName is the name of the directory to save installer manifests created by ccoctl
	ManifestsDirName = "manifests"
	// TLSDirName is the name of the directory to save bound service account signing key created by ccoctl
	TLSDirName = "tls"
)
