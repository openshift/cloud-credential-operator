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
	"fmt"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	iamadminpb "google.golang.org/genproto/googleapis/iam/admin/v1"

	ccgcp "github.com/openshift/cloud-credential-operator/pkg/gcp"
)

// ensurePolicyBindings will add and remove any policy bindings for the service account to match the
// roles list provided.
func ensurePolicyBindings(rootClient ccgcp.Client, roles []string, svcAcct *iamadminpb.ServiceAccount) error {
	needPolicyUpdate := false

	projectName := rootClient.GetProjectName()
	policy, err := rootClient.GetProjectIamPolicy(projectName, &cloudresourcemanager.GetIamPolicyRequest{})

	if err != nil {
		return fmt.Errorf("error fetching policy for project: %v", err)
	}

	// Validate that each role exists, and add the policy binding as needed
	for _, definedRole := range roles {
		// Earlier we've verified that the requested roles already exist.

		// Add policy binding
		modified := addPolicyBinding(policy, definedRole, svcAcct)
		if modified {
			needPolicyUpdate = true
		}

	}

	// Remove extra role bindings as needed
	modified := purgeExtraPolicyBindings(policy, roles, svcAcct)
	if modified {
		needPolicyUpdate = true
	}

	if needPolicyUpdate {
		if rootClient == nil {
			return fmt.Errorf("detected need for policy update, but no root creds available")
		}
		return setProjectIamPolicy(rootClient, policy, projectName)
	}

	// If we made it this far there were no updates needed
	return nil
}

func purgeExtraPolicyBindings(policy *cloudresourcemanager.Policy, roleList []string, svcAcct *iamadminpb.ServiceAccount) bool {
	modifiedPolicy := false
	svcAcctBindingName := serviceAccountBindingName(svcAcct)

	for _, binding := range policy.Bindings {
		// find if our service account has an entry in this binding
		for j, member := range binding.Members {
			if member == svcAcctBindingName {
				removeMember := true

				// check if this role is one that should be bound to this service account's roleList
				for _, role := range roleList {
					if role == binding.Role {
						removeMember = false
						break
					}
				}

				if removeMember {
					// It is okay to submit a policy with a binding entry where the member list
					// is empty. The policy will be cleaned up on the GCP-side and it will be
					// as if we had removed the entire binding entry.

					binding.Members = append(binding.Members[:j], binding.Members[j+1:]...)
					modifiedPolicy = true
				}
			}
		}
	}

	return modifiedPolicy
}

func addPolicyBinding(policy *cloudresourcemanager.Policy, roleName string, svcAcct *iamadminpb.ServiceAccount) bool {
	for i, binding := range policy.Bindings {
		if binding.Role == roleName {
			return addServiceAccountToBinding(svcAcct, policy.Bindings[i])
		}
	}

	// if we didn't find an existing binding entry, then make one
	createServiceAccountRoleBinding(policy, roleName, svcAcct)

	return true
}

func createServiceAccountRoleBinding(policy *cloudresourcemanager.Policy, roleName string, svcAcct *iamadminpb.ServiceAccount) {
	svcAcctBindingName := serviceAccountBindingName(svcAcct)
	policy.Bindings = append(policy.Bindings, &cloudresourcemanager.Binding{
		Members: []string{svcAcctBindingName},
		Role:    roleName,
	})
}

// adds svc account entry to existing binding. returns bool indicating if an entry was made
func addServiceAccountToBinding(svcAccount *iamadminpb.ServiceAccount, binding *cloudresourcemanager.Binding) bool {
	svcAcctBindingName := serviceAccountBindingName(svcAccount)
	for _, member := range binding.Members {
		if member == svcAcctBindingName {
			// already present
			return false
		}
	}

	binding.Members = append(binding.Members, svcAcctBindingName)
	return true
}

func serviceAccountNeedsPermissionsUpdate(gcpClient ccgcp.Client, serviceAccountID string, roles []string) (bool, error) {

	projectName := gcpClient.GetProjectName()
	svcAcct, err := getServiceAccount(gcpClient, serviceAccountID)
	if err != nil {
		return true, fmt.Errorf("error fetching service account details: %v", err)
	}
	svcAcctBindingName := serviceAccountBindingName(svcAcct)

	policy, err := gcpClient.GetProjectIamPolicy(projectName, &cloudresourcemanager.GetIamPolicyRequest{})
	if err != nil {
		return true, fmt.Errorf("error fetching current project iam policy: %v", err)
	}

	// check do we have bindings for everything in the credentialsRequest
	for _, roleName := range roles {
		foundRole := false
		for _, binding := range policy.Bindings {
			if binding.Role == roleName {
				foundRole = true
				if !isServiceAccountInBinding(svcAcctBindingName, binding) {
					return true, nil
				}
			}
		}
		if !foundRole {
			// we have a role being requested that we don't have a policy binding for
			return true, nil
		}
	}

	// check whether we have extra policy bindings
	for _, binding := range policy.Bindings {
		if isServiceAccountInBinding(svcAcctBindingName, binding) {
			extraRoleDetected := true
			for _, roleName := range roles {
				if roleName == binding.Role {
					extraRoleDetected = false
					break
				}
			}
			if extraRoleDetected {
				return true, nil
			}
		}
	}

	// if we made it this far, then the existing policy bindings don't need changing
	return false, nil
}

func removeAllPolicyBindingsFromServiceAccount(gcpClient ccgcp.Client, svcAcct *iamadminpb.ServiceAccount) error {
	projectName := gcpClient.GetProjectName()

	svcAcctBindingName := serviceAccountBindingName(svcAcct)

	policy, err := gcpClient.GetProjectIamPolicy(projectName, &cloudresourcemanager.GetIamPolicyRequest{})
	if err != nil {
		return fmt.Errorf("error retrieving current policy: %v", err)
	}

	for _, binding := range policy.Bindings {
		for j, member := range binding.Members {
			if member == svcAcctBindingName {
				// It is okay to submit a policy with a binding entry where the member list
				// is empty. The policy will be cleaned up on the GCP-side and it will be
				// as if we had removed the entire binding entry.
				binding.Members = append(binding.Members[:j], binding.Members[j+1:]...)
			}
		}
	}

	if err := setProjectIamPolicy(gcpClient, policy, projectName); err != nil {
		return fmt.Errorf("error updating policy: %v", err)
	}

	return nil
}

func setProjectIamPolicy(gcpClient ccgcp.Client, policy *cloudresourcemanager.Policy, projectName string) error {
	policyRequest := &cloudresourcemanager.SetIamPolicyRequest{
		Policy: policy,
	}

	_, err := gcpClient.SetProjectIamPolicy(projectName, policyRequest)
	if err != nil {
		return fmt.Errorf("error setting project policy: %v", err)
	}
	return nil
}

func isServiceAccountInBinding(svcAcctBindingName string, binding *cloudresourcemanager.Binding) bool {
	for _, member := range binding.Members {
		if member == svcAcctBindingName {
			return true
		}
	}
	return false
}
