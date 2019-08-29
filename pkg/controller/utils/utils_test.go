package utils

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateName(t *testing.T) {
	tests := []struct {
		name                 string
		infraName            string
		infraNameMaxLen      int
		credentialName       string
		credentialNameMaxLen int
		expectedPrefix       string
		expectedError        bool
	}{
		{
			name:                 "no truncation",
			infraName:            "thisIsTheInfraName",
			infraNameMaxLen:      100,
			credentialName:       "thisIsTheCredentialName",
			credentialNameMaxLen: 100,
			expectedPrefix:       "thisIsTheInfraName-thisIsTheCredentialName",
		},
		{
			name:                 "12-11-5", // 30 total characters (service account id limit)
			infraName:            "thisIsTheInfraName",
			infraNameMaxLen:      12,
			credentialName:       "thisIsTheCredentialName",
			credentialNameMaxLen: 11,
			expectedPrefix:       "thisIsTheInf-thisIsTheCr",
		},
		{
			name:            "error on empty credentialName",
			infraName:       "thisIsTheInfraName",
			infraNameMaxLen: 100,
			expectedError:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			generatedName, err := GenerateUniqueNameWithFieldLimits(test.infraName, test.infraNameMaxLen, test.credentialName, test.credentialNameMaxLen)
			if test.expectedError {
				assert.Error(t, err, "Expected error returned")
			} else {
				assert.NoError(t, err, "Error not expected")

				assert.Regexp(t, regexp.MustCompile("^"+test.expectedPrefix), generatedName)

				//										infraName + '-' + credName + '-' + <random 5>
				assert.True(t, len(generatedName) <= test.infraNameMaxLen+1+test.credentialNameMaxLen+1+5, "generate name has unexpected length")
			}
		})
	}
}
