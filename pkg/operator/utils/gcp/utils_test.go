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
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"google.golang.org/api/cloudresourcemanager/v1"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/cloud-credential-operator/pkg/gcp/mock"
)

func TestPermissionsFiltering(t *testing.T) {
	tests := []struct {
		name             string
		origPermList     []string
		allowedPermsSet  sets.String
		expectedPermList []string
	}{
		{
			name: "leave original list untouched",
			origPermList: []string{
				"permA",
				"permB",
				"permC",
			},
			allowedPermsSet: sets.NewString("permA", "permB", "permC"),
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
			allowedPermsSet: sets.NewString("permA", "permD"),
			expectedPermList: []string{
				"permA",
				"permD",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			logger := log.New()

			testablePerms.lastUpdated = time.Now()
			testablePerms.permSet = test.allowedPermsSet
			filteredPerms, err := filterOutPermissions(nil, "fakeProject", test.origPermList, logger)

			require.NoError(t, err, "unexpected error testing out permissions filtering")

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

			mockClient.EXPECT().GetProjectName().Times(1).Return("fake")

			permissionsList := perms(0, test.count)
			testablePerms.lastUpdated = time.Now()
			testablePerms.permSet = sets.NewString(permissionsList...)

			mockCallList := []*gomock.Call{}

			for _, chunk := range test.chunks {
				permRequest := &cloudresourcemanager.TestIamPermissionsRequest{
					Permissions: chunk,
				}

				chunkCopy := chunk

				mockCall := mockClient.EXPECT().TestIamPermissions("fake", gomock.Any()).Times(1).DoAndReturn(
					func(projectName string, actualRequest *cloudresourcemanager.TestIamPermissionsRequest) (*cloudresourcemanager.TestIamPermissionsResponse, error) {
						origSet := sets.NewString(permRequest.Permissions...)
						actualSet := sets.NewString(actualRequest.Permissions...)
						diff := origSet.Difference(actualSet)

						assert.Zero(t, diff.Len(), "unexpected diff between expected permission list and provided permission list")

						return &cloudresourcemanager.TestIamPermissionsResponse{
							Permissions: chunkCopy,
						}, nil
					},
				)

				mockCallList = append(mockCallList, mockCall)
			}

			gomock.InOrder(mockCallList...)

			hasPermissions, err := CheckPermissionsAgainstPermissionList(mockClient, permissionsList, logger)
			assert.Nil(t, err)
			assert.True(t, hasPermissions)
		})
	}
}

func TestIgnoreInvalidProjectPermissions(t *testing.T) {
	projectName := "fake"

	tests := []struct {
		name             string
		origPermList     []string
		allowed          bool
		setupGCPResponse func(*mock.MockClient)
	}{
		{
			name: "one invalid permission",
			origPermList: []string{
				"allowedPerm",
				"invalidPerm",
			},
			setupGCPResponse: func(mockClient *mock.MockClient) {
				// allow the perm list w/o invalidPerm
				mockCall := mockClient.EXPECT().TestIamPermissions(projectName, gomock.Any()).Times(1).DoAndReturn(
					func(projectName string, permRequest *cloudresourcemanager.TestIamPermissionsRequest) (*cloudresourcemanager.TestIamPermissionsResponse, error) {
						assert.Equal(t, 2, len(permRequest.Permissions), "expected 2 permissions in permissions list")

						return &cloudresourcemanager.TestIamPermissionsResponse{
							Permissions: []string{
								"allowedPerm",
							},
						}, nil
					})

				gomock.InOrder(mockCall)
			},
			allowed: false,
		},
		{
			name: "multiple invalid permissions",
			origPermList: []string{
				"allowedPerm",
				"invalidPerm1",
				"invalidPerm2",
			},
			setupGCPResponse: func(mockClient *mock.MockClient) {
				// allow the perm list w/o invalidPerm1 and invalidPerm2
				mockCall := mockClient.EXPECT().TestIamPermissions(projectName, gomock.Any()).Times(1).DoAndReturn(
					func(projectName string, permRequest *cloudresourcemanager.TestIamPermissionsRequest) (*cloudresourcemanager.TestIamPermissionsResponse, error) {
						assert.Equal(t, 3, len(permRequest.Permissions), "expected 3 permissions in permissions list")

						return &cloudresourcemanager.TestIamPermissionsResponse{
							Permissions: []string{
								"allowedPerm",
							},
						}, nil
					})

				gomock.InOrder(mockCall)
			},
			allowed: false,
		},
		{
			name: "only valid permissions",
			origPermList: []string{
				"allowedPerm1",
				"allowedPerm2",
			},
			setupGCPResponse: func(mockClient *mock.MockClient) {
				// allow the perm list w/o invalidPerm1 and invalidPerm2
				mockCall := mockClient.EXPECT().TestIamPermissions(projectName, gomock.Any()).Times(1).DoAndReturn(
					func(projectName string, permRequest *cloudresourcemanager.TestIamPermissionsRequest) (*cloudresourcemanager.TestIamPermissionsResponse, error) {
						assert.Equal(t, 2, len(permRequest.Permissions), "expected 2 permissions in permissions list")

						return &cloudresourcemanager.TestIamPermissionsResponse{
							Permissions: []string{
								"allowedPerm1",
								"allowedPerm2",
							},
						}, nil
					})

				gomock.InOrder(mockCall)
			},
			allowed: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			mockClient := mock.NewMockClient(mockCtrl)
			logger := log.New()

			mockClient.EXPECT().GetProjectName().Times(1).Return(projectName)

			testablePerms.lastUpdated = time.Now()
			testablePerms.permSet = sets.NewString(test.origPermList...)

			test.setupGCPResponse(mockClient)

			allowed, err := CheckPermissionsAgainstPermissionList(mockClient, test.origPermList, logger)

			assert.NoError(t, err, "unexpected error")

			assert.Equal(t, test.allowed, allowed, "expected invalid permissions to be ignored")

		})
	}
}
