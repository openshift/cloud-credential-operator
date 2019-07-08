/*
Copyright 2019 The OpenShift Authors.

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

package gcp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPermissionsFiltering(t *testing.T) {
	tests := []struct {
		name             string
		origPermList     []string
		filterOutList    []string
		expectedPermList []string
	}{
		{
			name: "leave original list untouched",
			origPermList: []string{
				"permA",
				"permB",
				"permC",
			},
			filterOutList: []string{
				"permX",
				"permY",
				"permZ",
			},
			expectedPermList: []string{
				"permA",
				"permB",
				"permC",
			},
		},
		{
			name: "filter out perms",
			origPermList: []string{
				"permA",
				"permB",
				"permC",
				"permD",
			},
			filterOutList: []string{
				"permB",
				"permC",
				"permZ",
			},
			expectedPermList: []string{
				"permA",
				"permD",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			filteredPerms := filterOutPermissions(test.origPermList, test.filterOutList)

			assert.Equal(t, len(test.expectedPermList), len(filteredPerms))

			for _, expectedPerm := range test.expectedPermList {
				found := false
				for _, filteredPerm := range filteredPerms {
					if expectedPerm == filteredPerm {
						found = true
						break
					}
				}
				assert.True(t, found, "Did not find expected perm in list")
			}

		})
	}
}
