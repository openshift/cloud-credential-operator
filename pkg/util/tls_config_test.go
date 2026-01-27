package util

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/assert"
)

func TestGetTLSConfig(t *testing.T) {
	tests := []struct {
		name           string
		profile        *configv1.TLSSecurityProfile
		expectedMinTLS string
	}{
		{
			name:           "Intermediate Profile (default)",
			profile:        &configv1.TLSSecurityProfile{Type: configv1.TLSProfileIntermediateType},
			expectedMinTLS: "1.2",
		},
		{
			name:           "Old Profile",
			profile:        &configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType},
			expectedMinTLS: "1.0",
		},
		{
			name:           "Modern Profile",
			profile:        &configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType},
			expectedMinTLS: "1.3",
		},
		{
			name: "Custom Profile 1.2",
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS12,
						Ciphers:       []string{"A", "B"},
					},
				},
			},
			expectedMinTLS: "1.2",
		},
		{
			name: "Custom Profile 1.3",
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						MinTLSVersion: configv1.VersionTLS13,
					},
				},
			},
			expectedMinTLS: "1.3",
		},
		{
			name:           "Nil Profile",
			profile:        nil,
			expectedMinTLS: "1.2", // defaults to intermediate
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			minTLS, _, _ := GetTLSConfig(tt.profile)
			assert.Equal(t, tt.expectedMinTLS, minTLS)
		})
	}
}
