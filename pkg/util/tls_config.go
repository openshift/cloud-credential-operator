package util

import (
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/crypto"
)

func GetTLSConfig(profile *configv1.TLSSecurityProfile) (string, string, string) {
	profileType := configv1.TLSProfileIntermediateType
	if profile != nil {
		profileType = profile.Type
	}

	var profileSpec *configv1.TLSProfileSpec
	switch profileType {
	case configv1.TLSProfileCustomType:
		profileSpec = &profile.Custom.TLSProfileSpec
	default:
		profileSpec = configv1.TLSProfiles[profileType]
	}

	if profileSpec == nil {
		profileSpec = configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
	}

	minTLSVersion := string(profileSpec.MinTLSVersion)
	switch profileSpec.MinTLSVersion {
	case configv1.VersionTLS10:
		minTLSVersion = "1.0"
	case configv1.VersionTLS11:
		minTLSVersion = "1.1"
	case configv1.VersionTLS12:
		minTLSVersion = "1.2"
	case configv1.VersionTLS13:
		minTLSVersion = "1.3"
	}

	return minTLSVersion, string(profileSpec.MinTLSVersion), strings.Join(crypto.OpenSSLToIANACipherSuites(profileSpec.Ciphers), ",")
}
