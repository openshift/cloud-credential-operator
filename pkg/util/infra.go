package util

import (
	configv1 "github.com/openshift/api/config/v1"
)

// GetAzureCloudName gets the Azure cloud name to use given the specified infrastructure status.
func GetAzureCloudName(infraStatus *configv1.InfrastructureStatus) configv1.AzureCloudEnvironment {
	if s := infraStatus.PlatformStatus; s != nil {
		if a := s.Azure; a != nil {
			if c := a.CloudName; c != "" {
				return c
			}
		}
	}
	return configv1.AzurePublicCloud
}
