package util

import (
	"testing"

	"github.com/stretchr/testify/assert"

	configv1 "github.com/openshift/api/config/v1"
)

func TestGetAzureCloudName(t *testing.T) {
	cases := []struct {
		name              string
		infraStatus       *configv1.InfrastructureStatus
		expectedCloudName configv1.AzureCloudEnvironment
	}{
		{
			name:              "no platform status",
			infraStatus:       &configv1.InfrastructureStatus{},
			expectedCloudName: configv1.AzurePublicCloud,
		},
		{
			name: "no azure",
			infraStatus: &configv1.InfrastructureStatus{
				PlatformStatus: &configv1.PlatformStatus{},
			},
			expectedCloudName: configv1.AzurePublicCloud,
		},
		{
			name: "no cloud name",
			infraStatus: &configv1.InfrastructureStatus{
				PlatformStatus: &configv1.PlatformStatus{
					Azure: &configv1.AzurePlatformStatus{},
				},
			},
			expectedCloudName: configv1.AzurePublicCloud,
		},
		{
			name: "default cloud name",
			infraStatus: &configv1.InfrastructureStatus{
				PlatformStatus: &configv1.PlatformStatus{
					Azure: &configv1.AzurePlatformStatus{
						CloudName: configv1.AzurePublicCloud,
					},
				},
			},
			expectedCloudName: configv1.AzurePublicCloud,
		},
		{
			name: "non-default cloud name",
			infraStatus: &configv1.InfrastructureStatus{
				PlatformStatus: &configv1.PlatformStatus{
					Azure: &configv1.AzurePlatformStatus{
						CloudName: configv1.AzureUSGovernmentCloud,
					},
				},
			},
			expectedCloudName: configv1.AzureUSGovernmentCloud,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actualCloudName := GetAzureCloudName(tc.infraStatus)
			assert.Equal(t, tc.expectedCloudName, actualCloudName)
		})
	}
}
