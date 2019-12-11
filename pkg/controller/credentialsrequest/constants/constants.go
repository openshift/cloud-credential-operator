package constants

import (
	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
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
)
