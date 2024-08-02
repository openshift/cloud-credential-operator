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
	"context"
	"fmt"
	"regexp"
	"time"

	log "github.com/sirupsen/logrus"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	iamadminpb "google.golang.org/genproto/googleapis/iam/admin/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	ccgcp "github.com/openshift/cloud-credential-operator/pkg/gcp"
)

type testablePermissions struct {
	permSet     sets.String
	lastUpdated time.Time
}

var (
	// CredMintingPermissions is a list of GCP permissions needed to run in the mode where the
	// cloud-credential-operator can mint new creds to satisfy CredentialsRequest CRDs
	CredMintingPermissions = []string{
		// Query API availability
		"resourcemanager.projects.get",
		"serviceusage.services.list",

		// Create/delete service accounts and keys
		"iam.serviceAccountKeys.create",
		"iam.serviceAccountKeys.delete",
		"iam.serviceAccounts.create",
		"iam.serviceAccounts.delete",
		"iam.serviceAccounts.get",

		// Create/delete role bindings to service accounts
		"iam.roles.get",
		"resourcemanager.projects.getIamPolicy",
		"resourcemanager.projects.setIamPolicy",
	}

	// CredPassthroughPermissions is a list of GCP permissions needed to run in passthrough mode.
	CredPassthroughPermissions = []string{
		// Query API availability
		"serviceusage.services.list",
		// Query getting current project details
		"resourcemanager.projects.get",
		// Query role existence and permissions attached to roles
		"iam.roles.get",
	}

	credentailRequestScheme = runtime.NewScheme()

	testablePerms = testablePermissions{}
)

var (
	// Regexp to catch the first field of a permissions of the form
	// <service>.<category>.<action> so that we can easily create
	// the API name <service>.googleapis.com.
	permToAPIRegexp = regexp.MustCompile(`^([A-Za-z0-9-]*)\..*`)

	// Regexp to find which API permission is being reported as invalid
	// for testing against the Project level.
	invalidProjectPermissionsRegex = regexp.MustCompile(`^Permission (.*) is not valid for this resource.$`)
)

func init() {
	if err := minterv1.AddToScheme(credentailRequestScheme); err != nil {
		panic(err)
	}
}

// CheckCloudCredCreation will see whether we have enough permissions to create new sub-creds, and
// whether the necessary services are enabled.
func CheckCloudCredCreation(gcpClient ccgcp.Client, logger log.FieldLogger) (bool, error) {
	return checkServicesAndPermissions(gcpClient, CredMintingPermissions, logger)
}

// CheckCloudCredPassthrough will see if the provided creds are good enough to determine at
// runtime whether the current credentials are good enough to be passed along as-is to satisfy
// a CredentialsRequest (and validating that the associated APIs are enabled).
func CheckCloudCredPassthrough(gcpClient ccgcp.Client, logger log.FieldLogger) (bool, error) {
	return checkServicesAndPermissions(gcpClient, CredPassthroughPermissions, logger)
}

func checkServicesAndPermissions(gcpClient ccgcp.Client, permissionsList []string, logger log.FieldLogger) (bool, error) {
	allowed, err := CheckPermissionsAgainstPermissionList(gcpClient, permissionsList, logger)
	if err != nil {
		return false, err
	}

	if !allowed {
		return allowed, nil
	}

	servicesEnabled, err := CheckServicesEnabled(gcpClient, permissionsList, logger)
	if err != nil {
		return false, err
	}

	return servicesEnabled, nil
}

func refreshTestablePermissions(gcpClient ccgcp.Client, projectName string, logger log.FieldLogger) error {
	// skip refresh if last update was less than 1 hour ago
	if testablePerms.lastUpdated.Add(time.Hour).After(time.Now()) {
		return nil
	}

	ctx := context.TODO()
	nextPageToken := ""
	projectNamePath := fmt.Sprintf(`//cloudresourcemanager.googleapis.com/projects/%s`, projectName)
	newPermSet := sets.NewString()

	request := &iamadminpb.QueryTestablePermissionsRequest{
		FullResourceName: projectNamePath,
	}

	for {
		request.PageToken = nextPageToken

		resp, err := gcpClient.QueryTestablePermissions(ctx, request)
		if err != nil {
			logger.WithError(err).Error("failed to gather list of testable permissions")
			return err
		}

		for _, perm := range resp.Permissions {
			newPermSet.Insert(perm.Name)
		}

		nextPageToken = resp.NextPageToken

		if nextPageToken == "" {
			break
		}
	}

	testablePerms.permSet = newPermSet
	testablePerms.lastUpdated = time.Now()

	return nil
}

// filterOutPermissions will take a list of GCP permissions to test against and return a list of permissions that
// are valid to test against at the project level
func filterOutPermissions(gcpClient ccgcp.Client, projectName string, permList []string, logger log.FieldLogger) ([]string, error) {

	filteredPerms := []string{}

	if err := refreshTestablePermissions(gcpClient, projectName, logger); err != nil {
		return filteredPerms, err
	}

	for _, perm := range permList {
		if testablePerms.permSet.Has(perm) {
			filteredPerms = append(filteredPerms, perm)
		} else {
			logger.Warnf("Ignoring permission checking of %s at project level", perm)
		}
	}
	return filteredPerms, nil
}

// CheckPermissionsAgainstPermissionList will take the passsed-in list of permissions to check whether the provided
// gcpClient creds have sufficient permissions to perform the actions.
// Will return true/false indicating whether the permissions are sufficient.
func CheckPermissionsAgainstPermissionList(gcpClient ccgcp.Client, permList []string, logger log.FieldLogger) (bool, error) {

	projectName := gcpClient.GetProjectName()

	filteredPermList, err := filterOutPermissions(gcpClient, projectName, permList, logger)
	if err != nil {
		return false, err
	}

	if len(filteredPermList) == 0 {
		return true, nil
	}

	// Split list to only check 100 permissions at a time
	allowedPerms := sets.NewString()
	chunkSize := 100
	permLen := len(filteredPermList)
	for i := 0; i < permLen; i += chunkSize {
		end := i + chunkSize
		if end > permLen {
			end = permLen
		}
		req := &cloudresourcemanager.TestIamPermissionsRequest{Permissions: filteredPermList[i:end]}
		resp, err := gcpClient.TestIamPermissions(projectName, req)
		if err != nil {
			// Sometimes the API responds that a valid permission is invalid.
			// As a workaround, detect when this is the case and remove the problematic
			// permission from the cache.
			invalidProjectPermission := invalidProjectPermissionsRegex.FindString(err.Error())
			if invalidProjectPermission != "" {
				logger.Warnf("removing problematic permission from cache: %s", invalidProjectPermission)
				delete(testablePerms.permSet, invalidProjectPermission)
			}
			return false, fmt.Errorf("error testing permissions: %v", err)
		}
		allowedPerms.Insert(resp.Permissions...)
	}

	requestedPerms := sets.NewString(filteredPermList...)
	disallowedPerms := requestedPerms.Difference(allowedPerms)

	if disallowedPerms.Len() > 0 {
		logger.Warnf("Detected some unallowed permissions: %v", disallowedPerms.List())
	}

	return disallowedPerms.Len() == 0, nil
}

// CheckServicesEnabled will take a list of GCP permissions, and see whether each permissions'
// related API is enabled.
func CheckServicesEnabled(gcpClient ccgcp.Client, permList []string, logger log.FieldLogger) (bool, error) {
	enabledServices, err := gcpClient.ListServicesEnabled()
	if err != nil {
		return false, fmt.Errorf("error retrieving list of enabled APIs: %v", err)
	}

	disabledAPIs := sets.NewString()

	for _, perm := range permList {
		apiName := permToAPIRegexp.ReplaceAllString(perm, "$1.googleapis.com")
		if enabled, ok := enabledServices[apiName]; !ok {
			// the lack of an entry in the enabledServices map means the API isn't enabled
			disabledAPIs.Insert(apiName)
		} else if !enabled {
			disabledAPIs.Insert(apiName)
		}
	}

	if len(disabledAPIs) > 0 {
		logger.Warnf("Detected required APIs that are disabled: %s", disabledAPIs.List())
		return false, nil
	}

	return true, nil
}
