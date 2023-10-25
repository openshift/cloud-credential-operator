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

package actuator

import (
	"context"
	"fmt"
	"log"
	"regexp"

	iamadminpb "google.golang.org/genproto/googleapis/iam/admin/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ccgcp "github.com/openshift/cloud-credential-operator/pkg/gcp"
)

func getPermissionsFromRoles(gcpClient ccgcp.Client, roles []string) ([]string, error) {
	permList := []string{}

	for _, roleName := range roles {
		role, err := gcpClient.GetRole(context.TODO(), &iamadminpb.GetRoleRequest{
			Name: roleName,
		})
		if status.Code(err) == codes.NotFound {
			return permList, fmt.Errorf("role %s not found: %v", roleName, err)
		} else if err != nil {
			return permList, fmt.Errorf("error getting role details: %v", err)
		}

		permList = append(permList, role.IncludedPermissions...)
	}

	return permList, nil
}

// GetRole fetches the role created to satisfy a credentials request
func GetRole(gcpClient ccgcp.Client, roleID, projectName string) (*iamadminpb.Role, error) {
	log.Printf("role id %v", roleID)
	role, err := gcpClient.GetRole(context.TODO(), &iamadminpb.GetRoleRequest{
		Name: fmt.Sprintf("projects/%s/roles/%s", projectName, roleID),
	})
	return role, err
}

// CreateRole creates a new role given permissions
func CreateRole(gcpClient ccgcp.Client, permissions []string, roleName, roleID, roleDescription, projectName string) (*iamadminpb.Role, error) {
	role, err := gcpClient.CreateRole(context.TODO(), &iamadminpb.CreateRoleRequest{
		Role: &iamadminpb.Role{
			Title:               roleName,
			Description:         roleDescription,
			IncludedPermissions: permissions,
			Stage:               iamadminpb.Role_GA,
		},
		Parent: fmt.Sprintf("projects/%s", projectName),
		RoleId: roleID,
	})
	if err != nil {
		return nil, err
	}
	return role, nil
}

// UpdateRole updates an existing role given permissions
func UpdateRole(gcpClient ccgcp.Client, role *iamadminpb.Role, roleName string) (*iamadminpb.Role, error) {
	role, err := gcpClient.UpdateRole(context.TODO(), &iamadminpb.UpdateRoleRequest{
		Name: roleName,
		Role: role,
	})
	if err != nil {
		return nil, err
	}
	return role, nil
}

// DeleteRole deletes the role created to satisfy a credentials request
func DeleteRole(gcpClient ccgcp.Client, roleName string) (*iamadminpb.Role, error) {
	role, err := gcpClient.DeleteRole(context.TODO(), &iamadminpb.DeleteRoleRequest{
		Name: roleName,
	})
	return role, err
}

// GenerateRoleID generates a unique ID for the role given project name and credentials request name.
// The role ID has a max length of 64 chars and can include only letters, numbers, period and underscores
// we sanitize projectName and crName to make them alphanumeric and then
// split role ID into 32_31 where the resulting string becomes:
// <projectName chopped to 32 chars>_<crName chopped to 31 chars>
func GenerateRoleID(projectName string, crName string) (string, error) {
	projectName = makeAlphanumeric(projectName)
	crName = makeAlphanumeric(crName)

	projectNameMaxLenForRoleID := 32
	crNameMaxLenForRoleID := 31

	if projectName == "" {
		return "", fmt.Errorf("empty project name")
	}

	if crName == "" {
		return "", fmt.Errorf("empty credential request name")
	}

	if len(projectName) > projectNameMaxLenForRoleID {
		projectName = projectName[0:projectNameMaxLenForRoleID]
	}
	if len(crName) > crNameMaxLenForRoleID {
		crName = crName[0:crNameMaxLenForRoleID]
	}
	return fmt.Sprintf("%s_%s", projectName, crName), nil
}

// GenerateRoleName generates a unique name for the role given project name and credentials request name.
// The role name has a max length of 100 chars, so we split role ID into 50-49 where the resulting string becomes:
// <projectName chopped to 50 chars>-<crName chopped to 49 chars>
func GenerateRoleName(projectName string, crName string) (string, error) {
	projectNameMaxLenForRoleName := 50
	crNameMaxLenForRoleName := 49

	if projectName == "" {
		return "", fmt.Errorf("empty project name")
	}

	if crName == "" {
		return "", fmt.Errorf("empty credential request name")
	}

	if len(projectName) > projectNameMaxLenForRoleName {
		projectName = projectName[0:projectNameMaxLenForRoleName]
	}
	if len(crName) > crNameMaxLenForRoleName {
		crName = crName[0:crNameMaxLenForRoleName]
	}
	return fmt.Sprintf("%s-%s", projectName, crName), nil
}

// makeAlphanumeric makes a given string alphanumeric
func makeAlphanumeric(str string) string {
	reg, _ := regexp.Compile("[^a-zA-Z0-9]+")
	return reg.ReplaceAllString(str, "")
}
