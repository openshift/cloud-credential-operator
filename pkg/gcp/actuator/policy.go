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
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iam/v1"
	iamadminpb "google.golang.org/genproto/googleapis/iam/admin/v1"

	ccgcp "github.com/openshift/cloud-credential-operator/pkg/gcp"
)

// EnsurePolicyBindingsForProject ensures that given roles and member, appropriate binding is added to project
func EnsurePolicyBindingsForProject(rootClient ccgcp.Client, roles []string, member string) error {
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
		modified := addPolicyBindingForProject(policy, definedRole, member)
		if modified {
			needPolicyUpdate = true
		}

	}

	// Remove extra role bindings as needed
	modified := purgeExtraPolicyBindingsForProject(policy, roles, member)
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

// EnsurePolicyBindingsForServiceAccount ensures that given roles and member, appropriate binding is added to IAM service account
func EnsurePolicyBindingsForServiceAccount(rootClient ccgcp.Client, svcAcct *iamadminpb.ServiceAccount, roles []string, member string) error {
	needPolicyUpdate := false

	projectName := rootClient.GetProjectName()
	svcAcctResource := fmt.Sprintf("projects/%s/serviceAccounts/%s", projectName, svcAcct.Email)
	policy, err := rootClient.GetServiceAccountIamPolicy(svcAcctResource)

	if err != nil {
		return fmt.Errorf("error fetching policy for service account: %v", err)
	}

	// Validate that each role exists, and add the policy binding as needed
	for _, definedRole := range roles {
		// Earlier we've verified that the requested roles already exist.

		// Add policy binding
		modified := addPolicyBindingForServiceAccount(policy, definedRole, member)
		if modified {
			needPolicyUpdate = true
		}

	}

	// Remove extra role bindings as needed
	modified := purgeExtraPolicyBindingsForServiceAccount(policy, roles, member)
	if modified {
		needPolicyUpdate = true
	}

	if needPolicyUpdate {
		if rootClient == nil {
			return fmt.Errorf("detected need for policy update, but no root creds available")
		}
		return setServiceAccountIamPolicy(rootClient, policy, svcAcctResource)
	}

	// If we made it this far there were no updates needed
	return nil
}

func purgeExtraPolicyBindingsForProject(policy *cloudresourcemanager.Policy, roleList []string, memberName string) bool {
	modifiedPolicy := false

	for _, binding := range policy.Bindings {
		// find if given member has an entry in this binding
		for j, member := range binding.Members {
			if member == memberName {
				removeMember := true

				// check if this role is one that should be bound to this project's roleList
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

func purgeExtraPolicyBindingsForServiceAccount(policy *iam.Policy, roleList []string, memberName string) bool {
	modifiedPolicy := false

	for _, binding := range policy.Bindings {
		// find if our member has an entry in this binding
		for j, member := range binding.Members {
			if member == memberName {
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

func addPolicyBindingForProject(policy *cloudresourcemanager.Policy, roleName, memberName string) bool {
	for i, binding := range policy.Bindings {
		if binding.Role == roleName {
			return addMemberToBindingForProject(memberName, policy.Bindings[i])
		}
	}

	// if we didn't find an existing binding entry, then make one
	createMemberRoleBindingForProject(policy, roleName, memberName)

	return true
}

func addPolicyBindingForServiceAccount(policy *iam.Policy, roleName, memberName string) bool {
	for i, binding := range policy.Bindings {
		if binding.Role == roleName {
			return addMemberToBindingForServiceAccount(memberName, policy.Bindings[i])
		}
	}

	// if we didn't find an existing binding entry, then make one
	createMemberRoleBindingForServiceAccount(policy, roleName, memberName)

	return true
}

func createMemberRoleBindingForProject(policy *cloudresourcemanager.Policy, roleName, memberName string) {
	policy.Bindings = append(policy.Bindings, &cloudresourcemanager.Binding{
		Members: []string{memberName},
		Role:    roleName,
	})
}

func createMemberRoleBindingForServiceAccount(policy *iam.Policy, roleName, memberName string) {
	policy.Bindings = append(policy.Bindings, &iam.Binding{
		Members: []string{memberName},
		Role:    roleName,
	})
}

// adds member to existing binding. returns bool indicating if an entry was made
func addMemberToBindingForProject(memberName string, binding *cloudresourcemanager.Binding) bool {
	for _, member := range binding.Members {
		if member == memberName {
			// already present
			return false
		}
	}

	binding.Members = append(binding.Members, memberName)
	return true
}

// adds member to existing binding. returns bool indicating if an entry was made
func addMemberToBindingForServiceAccount(memberName string, binding *iam.Binding) bool {
	for _, member := range binding.Members {
		if member == memberName {
			// already present
			return false
		}
	}

	binding.Members = append(binding.Members, memberName)
	return true
}

func serviceAccountNeedsPermissionsUpdate(gcpClient ccgcp.Client, serviceAccountID string, roles []string) (bool, error) {

	projectName := gcpClient.GetProjectName()
	svcAcct, err := GetServiceAccount(gcpClient, serviceAccountID)
	if err != nil {
		return true, fmt.Errorf("error fetching service account details: %v", err)
	}
	svcAcctBindingName := ServiceAccountBindingName(svcAcct)

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

// RemovePolicyBindingsForProject ensures that given member, all the associated bindings for that member are removed
// from the project policy
func RemovePolicyBindingsForProject(gcpClient ccgcp.Client, memberName string) error {
	projectName := gcpClient.GetProjectName()

	policy, err := gcpClient.GetProjectIamPolicy(projectName, &cloudresourcemanager.GetIamPolicyRequest{})
	if err != nil {
		return fmt.Errorf("error retrieving current policy: %v", err)
	}

	for _, binding := range policy.Bindings {
		for j, member := range binding.Members {
			if member == memberName {
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

func setServiceAccountIamPolicy(gcpClient ccgcp.Client, policy *iam.Policy, svcAcctResource string) error {
	policyRequest := &iam.SetIamPolicyRequest{
		Policy: policy,
	}

	_, err := gcpClient.SetServiceAccountIamPolicy(svcAcctResource, policyRequest)
	if err != nil {
		return fmt.Errorf("error setting service account policy: %v", err)
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
