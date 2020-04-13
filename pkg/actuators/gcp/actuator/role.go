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

	iamadminpb "google.golang.org/genproto/googleapis/iam/admin/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ccgcp "github.com/openshift/cloud-credential-operator/pkg/actuators/gcp"
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
