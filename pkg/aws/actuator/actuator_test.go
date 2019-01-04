/*
Copyright 2018 The OpenShift Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package actuator

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestGenerateUserName(t *testing.T) {
	tests := []struct {
		name           string
		credentialName string
		expectedPrefix string // last part is random
		expectedError  bool
	}{
		{
			name:           "max size no truncating required",
			credentialName: "this-cred-should-be-58-characters-long11111111111111111111",
			expectedPrefix: "this-cred-should-be-58-characters-long11111111111111111111-",
		},
		{
			name:           "credential name truncated to 45 chars",
			credentialName: "this-cred-should-be-45-characters-long11111111111111111111222222222",
			expectedPrefix: "this-cred-should-be-45-characters-long11111111111111111111-",
		},
		{
			name:           "empty credential name",
			credentialName: "",
			expectedError:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			userName, err := generateUserName(test.credentialName)
			if err != nil && !test.expectedError {
				t.Errorf("unexpected error: %v", err)
			} else if err == nil {
				if test.expectedError {
					t.Error("no error returned")
				} else {
					t.Logf("userName: %s, length=%d", userName, len(userName))
					assert.True(t, len(userName) <= 64)
					if test.expectedPrefix != "" {
						assert.True(t, strings.HasPrefix(userName, test.expectedPrefix), "username prefix does not match")
						assert.Equal(t, len(test.expectedPrefix)+5, len(userName), "username length does not match a 5 char random suffix")
					}
				}
			}
		})
	}
}
