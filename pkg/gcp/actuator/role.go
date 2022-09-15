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

	utilrand "k8s.io/apimachinery/pkg/util/rand"

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

// GenerateRoleID generates a unique ID for the role given infra name and credentials request name.
// The role ID has a max length of 64 chars and can include only letters, numbers, period and underscores
// we sanitize infraName and crName to make them alphanumeric and then
// split role ID into 29_28_5 where the resulting string becomes:
// <infraName chopped to 29 chars>_<crName chopped to 28 chars>_<random 5 chars>
func GenerateRoleID(infraName string, crName string) (string, error) {
	infraName = makeAlphanumeric(infraName)
	crName = makeAlphanumeric(crName)

	infraNameMaxLenForRoleName := 29
	crNameMaxLenForRoleName := 28

	if crName == "" {
		return "", fmt.Errorf("empty credential request name")
	}

	if infraName != "" {
		if len(infraName) > infraNameMaxLenForRoleName {
			infraName = infraName[0:infraNameMaxLenForRoleName]
		}
	}
	if len(crName) > crNameMaxLenForRoleName {
		crName = crName[0:crNameMaxLenForRoleName]
	}
	return fmt.Sprintf("%s_%s_%s", infraName, crName, utilrand.String(5)), nil
}

// makeAlphanumeric makes a given string alphanumeric
func makeAlphanumeric(str string) string {
	reg, _ := regexp.Compile("[^a-zA-Z0-9]+")
	return reg.ReplaceAllString(str, "")
}
