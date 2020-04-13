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
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/openshift/cloud-credential-operator/pkg/actuators/gcp/mock"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
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

func perms(low, hi int) []string {
	count := hi - low
	result := make([]string, 0, count)
	for i := 0; i < count; i++ {
		result = append(result, fmt.Sprintf("permission%d", low+i))
	}
	return result
}

func TestCheckPermissionsAgainstPermissionListChunking(t *testing.T) {
	p := perms
	tests := []struct {
		count  int
		chunks [][]string
	}{
		{count: 0, chunks: nil},
		{count: 2, chunks: [][]string{p(0, 2)}},
		{count: 100, chunks: [][]string{p(0, 100)}},
		{count: 101, chunks: [][]string{p(0, 100), p(100, 101)}},
		{count: 230, chunks: [][]string{p(0, 100), p(100, 200), p(200, 230)}},
		{count: 300, chunks: [][]string{p(0, 100), p(100, 200), p(200, 300)}},
		{count: 379, chunks: [][]string{p(0, 100), p(100, 200), p(200, 300), p(300, 379)}},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("count=%d", test.count), func(t *testing.T) {
			mockClient := mock.NewMockClient(gomock.NewController(t))
			logger := log.New()

			mockClient.EXPECT().GetProjectName().AnyTimes().Return("fake")
			permissionsList := perms(0, test.count)

			for _, chunk := range test.chunks {
				permRequest := &cloudresourcemanager.TestIamPermissionsRequest{
					Permissions: chunk,
				}
				mockClient.EXPECT().TestIamPermissions("fake", permRequest).Return(&cloudresourcemanager.TestIamPermissionsResponse{
					Permissions: chunk,
				}, nil)

			}
			hasPermissions, err := CheckPermissionsAgainstPermissionList(mockClient, permissionsList, logger)
			assert.Nil(t, err)
			assert.True(t, hasPermissions)
		})
	}
}
