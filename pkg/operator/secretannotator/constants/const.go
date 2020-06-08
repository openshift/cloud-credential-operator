package constants

const (
	ControllerName = "secretannotator"

	CloudCredSecretNamespace = "kube-system"

	AnnotationKey = "cloudcredential.openshift.io/mode"

	// AWSCloudCredSecretName is the name of the secret created by the installer containing cloud creds.
	AWSCloudCredSecretName = "aws-creds"

	// AzureCloudCredSecretName is the name of the secret created by the install containing cloud creds.
	AzureCloudCredSecretName = "azure-credentials"

	// GCPCloudCredSecretName is the name of the secret created by the installer containing cloud creds.
	GCPCloudCredSecretName = "gcp-credentials"

	// OpenStackCloudCredsSecretName is the name of the secret created by the installer containing cloud creds.
	OpenStackCloudCredsSecretName = "openstack-credentials"

	// OvirtCloudCredsSecretName is then ame of the secret created by the installer containing cloud creds.
	OvirtCloudCredsSecretName = "ovirt-credentials"

	// VSphereCloudCredSecretName is the name of the secret where credentials
	// for vSphere are stored.
	VSphereCloudCredSecretName = "vsphere-creds"

	// MintAnnotation is used whenever it is determined that the cloud creds
	// are sufficient for minting new creds to satisfy a CredentialsRequest
	MintAnnotation = "mint"

	// PassthroughAnnotation is used whenever it is determined that the cloud creds
	// are sufficient for passing through to satisfy a CredentialsRequest.
	// This would be based on having creds that can satisfy the static list of creds
	// found in this repo's manifests/ dir.
	PassthroughAnnotation = "passthrough"

	// InsufficientAnnotation is used to indicate that the creds do not have
	// sufficient permissions for cluster runtime.
	InsufficientAnnotation = "insufficient"
)
