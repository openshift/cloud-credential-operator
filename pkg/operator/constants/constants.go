package constants

import "k8s.io/apimachinery/pkg/types"

// CredentialsMode enumerates the possible modes of operation for CCO
type CredentialsMode string

const (
	// metrics vars

	// ModeMint indicates that CCO is running in a mode where it will attempt
	// to create new users/credentials when processing CredentialsRequest objects.
	ModeMint CredentialsMode = "mint"

	// ModePassthrough indicates that CCO is running in a mode where it will
	// process CredentialsRequests by passing through the shared cloud credentials.
	ModePassthrough CredentialsMode = "passthrough"

	// ModeCredsRemoved indicates that the credentials CCO uses to reconcile
	// CredentialsRequest objects has been removed, and CCO can only validate
	// that already-reconciled credentials are still in a healthy state.
	ModeCredsRemoved CredentialsMode = "credsremoved"

	// ModeManual indicates that a user has disabled CCO from reconciling
	// CredentialsRequest objects, and is processing CredentialsRequest objects
	// via some alternative means.
	ModeManual CredentialsMode = "manual"

	// ModeDegraded indicates that the cloud credentials exists, but the cannot be used
	// (usually due to insuffient permissions)
	ModeDegraded CredentialsMode = "degraded"

	// ModeUnknown is used to indicate when we are unable to determine the mode CCO is
	// running under (typically just haven't added support for the cloud/platform)
	ModeUnknown CredentialsMode = "unknown"

	// StatusModeMismatch is used to set a clusteroperator condition when
	// the legacy configmap setting of disabled: "true" conflicts with the
	// specified operator config mode.
	StatusModeMismatch = "ModeMismatch"

	// StatusModeInvalid is used to set a clusteroperator condition when
	// the operator config CR specifies an invalide mode
	StatusModeInvalid = "ModeInvalid"

	// MissingSecretsForUpgradeReason is used when a manual mode cluster is not upgradable due to missing
	// secrets the operator knows will be required for the next minor release of OpenShift.
	MissingSecretsForUpgradeReason = "ManualModeMissingSecrets"

	// ErrorDeterminingUpgradeableReason is used when we encounter unexpected errors checking if a cluster can
	// be updated.
	ErrorDeterminingUpgradeableReason = "ErrorDeterminingUpgradeable"

	// MissingRootCredentialUpgradeableReason is used a cluster is in mint mode with the root credential removed.
	// In this state the root credential must be resotred before we can upgrade to the next minor release of OpenShift.
	MissingRootCredentialUpgradeableReason = "MissingRootCredential"

	// secret annoation vars

	// AnnotationKey is the annotation the cloud credentials secret will be annotated with to indicate
	// what mode the secrets can be used for.
	AnnotationKey = "cloudcredential.openshift.io/mode"

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

	// SecretAnnotatorControllerName is the name the various secret annotation accuators
	// will use for logging purposes.
	SecretAnnotatorControllerName = "secretannotator"

	// cloud credential secret infor

	// AWSCloudCredSecretName is the name of the secret created by the installer containing cloud creds.
	AWSCloudCredSecretName = "aws-creds"

	// AzureCloudCredSecretName is the name of the secret created by the install containing cloud creds.
	AzureCloudCredSecretName = "azure-credentials"

	// CloudCredOperatorConfigMap is an optional ConfigMap that can be used to alter behavior of the operator.
	CloudCredOperatorConfigMap = "cloud-credential-operator-config"

	// CloudCredOperatorConfig is the name of the credentialsrequest.operator.openshift.io CR holding CCO's config
	CloudCredOperatorConfig = "cluster"

	// CloudCredOperatorConfigTimestampAnnotation is the annotation controllers can update to trigger a status sync.
	CloudCredOperatorConfigTimestampAnnotation = "cloudcredential.operator.openshift.io/statussync"

	// CloudCredClusterOperatorName is the name of the CCO's ClusterOperator object
	CloudCredClusterOperatorName = "cloud-credential"

	// CloudCredSecretNamespace is where the cloud credentials can be found
	CloudCredSecretNamespace = "kube-system"

	// GCPCloudCredSecretName is the name of the secret created by the installer containing cloud creds.
	GCPCloudCredSecretName = "gcp-credentials"

	// OpenStackCloudCredsSecretName is the name of the secret created by the installer containing cloud creds.
	OpenStackCloudCredsSecretName = "openstack-credentials"

	// OvirtCloudCredsSecretName is then ame of the secret created by the installer containing cloud creds.
	OvirtCloudCredsSecretName = "ovirt-credentials"

	// VSphereCloudCredSecretName is the name of the secret where credentials
	// for vSphere are stored.
	VSphereCloudCredSecretName = "vsphere-creds"
)

var (
	// CredentialsModeList is a list of all the types of modes CCO can be operating under.
	CredentialsModeList = []CredentialsMode{
		ModeMint,
		ModePassthrough,
		ModeCredsRemoved,
		ModeManual,
		ModeDegraded,
		ModeUnknown,
	}

	// Add known new credentials for next version upgrade

	// AWSUpcomingSecrets contains the list of known new AWS credential secrets for the next version of OpenShift
	AWSUpcomingSecrets = []types.NamespacedName{}
	// AzureUpcomingSecrets contains the list of known new Azure credential secrets for the next version of OpenShift
	AzureUpcomingSecrets = []types.NamespacedName{}
	// GCPUpcomingSecrets contains the list of known new GCP credential secrets for the next version of OpenShift
	GCPUpcomingSecrets = []types.NamespacedName{}
	// OpenStackUpcomingSecrets contains the list of known new OpenStack credential secrets for the next version of OpenShift
	OpenStackUpcomingSecrets = []types.NamespacedName{}
	// OvirtUpcomingSecrets contains the list of known new oVirt credential secrets for the next version of OpenShift
	OvirtUpcomingSecrets = []types.NamespacedName{}
	// VsphereUpcomingSecrets contains the list of known new vSphere credential secrets for the next version of OpenShift
	VsphereUpcomingSecrets = []types.NamespacedName{}
)
