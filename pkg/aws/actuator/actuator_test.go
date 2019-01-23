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
		clusterName    string
		credentialName string
		expectedPrefix string // last part is random
		expectedError  bool
	}{
		{
			name:           "max size no truncating required",
			clusterName:    "20charclustername111",                  // max 20 chars
			credentialName: "openshift-cluster-ingress111111111111", // max 37 chars
			expectedPrefix: "20charclustername111-openshift-cluster-ingress111111111111-",
		},
		{
			name:           "credential name truncated to 37 chars",
			clusterName:    "shortcluster",
			credentialName: "openshift-cluster-ingress111111111111333333333333333", // over 37 chars
			expectedPrefix: "shortcluster-openshift-cluster-ingress111111111111-",
		},
		{
			name:           "cluster name truncated to 20 chars",
			clusterName:    "longclustername1111137492374923874928347928374", // over 20 chars
			credentialName: "openshift-cluster-ingress",
			expectedPrefix: "longclustername11111-openshift-cluster-ingress-",
		},
		{
			name:           "empty credential name",
			clusterName:    "shortcluster",
			credentialName: "",
			expectedError:  true,
		},
		{
			name:           "empty cluster name",
			clusterName:    "",
			credentialName: "something",
			expectedError:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			userName, err := generateUserName(test.clusterName, test.credentialName)
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
