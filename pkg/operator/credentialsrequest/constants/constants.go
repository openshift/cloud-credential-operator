package constants

import (
	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
)

// CredentialsMode enumerates the possible modes of operation for CCO
type CredentialsMode string

const (
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
)

var (
	// FailureConditionTypes is a list of all conditions where the overall controller status would not
	// be healthy.
	FailureConditionTypes = []minterv1.CredentialsRequestConditionType{
		minterv1.InsufficientCloudCredentials,
		minterv1.MissingTargetNamespace,
		minterv1.CredentialsProvisionFailure,
		minterv1.CredentialsDeprovisionFailure,
	}

	// CredentialsModeList is a list of all the types of modes CCO can be operating under.
	CredentialsModeList = []CredentialsMode{
		ModeMint,
		ModePassthrough,
		ModeCredsRemoved,
		ModeManual,
		ModeDegraded,
		ModeUnknown,
	}
)
