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
	"regexp"

	log "github.com/sirupsen/logrus"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	ccgcp "github.com/openshift/cloud-credential-operator/pkg/gcp"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/sets"
)

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
	credentialRequestCodec  = serializer.NewCodecFactory(credentailRequestScheme)

	invalidPermsForProjectScopedPermissionsTesting = []string{
		// checking whether we have permissions resourcemanager.projects.list returns an error
		// (as it is invalid when checking against a project resource),
		// but listing projects is always allowed (it simply returns a list of projects you
		// have projects.get permissions for)
		"resourcemanager.projects.list",
	}
)

const (
	infrastructureConfigName = "cluster"
)

var (
	// Regexp to catch the first field of a permissions of the form
	// <service>.<category>.<action> so that we can easily create
	// the API name <service>.googleapis.com.
	permToAPIRegexp = regexp.MustCompile(`^([A-Za-z0-9-]*)\..*`)
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

// filterOutPermissions will take a list of GCP permissions and return a list of permissions with any matching the filterOutList removed
func filterOutPermissions(permList, filterOutList []string) []string {
	filteredPerms := []string{}
	for _, perm := range permList {
		filterOut := false
		for _, filterPerm := range filterOutList {
			if perm == filterPerm {
				filterOut = true
				break
			}
		}

		if filterOut {
			continue
		}
		filteredPerms = append(filteredPerms, perm)
	}
	return filteredPerms
}

// CheckPermissionsAgainstPermissionList will take the passsed-in list of permissions to check whether the provided
// gcpClient creds have sufficient permissions to perform the actions.
// Will return true/false indicating whether the permissions are sufficient.
func CheckPermissionsAgainstPermissionList(gcpClient ccgcp.Client, permList []string, logger log.FieldLogger) (bool, error) {
	projectName := gcpClient.GetProjectName()

	filteredPermList := filterOutPermissions(permList, invalidPermsForProjectScopedPermissionsTesting)

	permRequest := &cloudresourcemanager.TestIamPermissionsRequest{
		Permissions: filteredPermList,
	}
	permResponse, err := gcpClient.TestIamPermissions(projectName, permRequest)
	if err != nil {
		return false, fmt.Errorf("error testing permissions: %v", err)
	}

	// check that each perm in our list is actually available
	permMap := map[string]bool{}
	for _, perm := range permResponse.Permissions {
		permMap[perm] = true
	}

	disallowedPerms := sets.NewString()
	for _, perm := range filteredPermList {
		if _, ok := permMap[perm]; !ok {
			disallowedPerms.Insert(perm)
		}
	}

	if len(disallowedPerms) > 0 {
		logger.Warnf("Detected some unallowed permissions: %s", disallowedPerms.List())
	}

	return len(disallowedPerms) == 0, nil

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
