package alibabacloud

import (
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ram"
	"github.com/openshift/cloud-credential-operator/pkg/alibabacloud"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"log"
)

var (
	// DeleteRAMUsersOpts captures the options that affect detaching of ram roles.
	DeleteRAMUsersOpts = options{
		Region:         "",
		Name:           "",
		CredRequestDir: "",
	}
)

//detachComponentPolicy detach the specific ram policy from the ram user
func detachComponentPolicy(client alibabacloud.Client, policyName, userName string) error {
	req := ram.CreateDetachPolicyFromUserRequest()
	req.PolicyName = policyName
	req.PolicyType = ramPolicyType
	req.UserName = userName
	_, err := client.DetachPolicyFromUser(req)
	return err
}

//deleteComponentPolicy delete the specific ram policy
func deleteComponentPolicy(client alibabacloud.Client, policyName string) error {
	req := ram.CreateDeletePolicyRequest()
	req.PolicyName = policyName
	_, err := client.DeletePolicy(req)
	return err
}

//deleteComponentUser delete the specific component ram user
func deleteComponentUser(client alibabacloud.Client, userName string) error {
	//remove all user AccessKeys firstly
	listKeyReq := ram.CreateListAccessKeysRequest()
	listKeyReq.UserName = userName
	listKeyRes, err := client.ListAccessKeys(listKeyReq)
	if err != nil {
		return errors.Wrap(err, "Failed to list accesskeys")
	}
	for _, oneKey := range listKeyRes.AccessKeys.AccessKey {
		log.Printf("Ready to delete user %s accesskey %s", userName, oneKey.AccessKeyId)
		deleteKeyReq := ram.CreateDeleteAccessKeyRequest()
		deleteKeyReq.UserName = userName
		deleteKeyReq.UserAccessKeyId = oneKey.AccessKeyId
		_, err := client.DeleteAccessKey(deleteKeyReq)
		if err != nil {
			return err
		}
	}
	req := ram.CreateDeleteUserRequest()
	req.UserName = userName
	_, err = client.DeleteUser(req)
	return err
}

func deleteRAMUsers(client alibabacloud.Client, name, credReqDir string) error {
	// Process directory
	credRequests, err := provisioning.GetListOfCredentialsRequests(credReqDir)
	if err != nil {
		return errors.Wrap(err, "Failed to process files containing CredentialsRequests")
	}

	for _, credReq := range credRequests {
		userName, _ := generateRAMUserName(fmt.Sprintf("%s-%s-%s", name, credReq.Spec.SecretRef.Namespace, credReq.Spec.SecretRef.Name))
		listPoliciesReq := ram.CreateListPoliciesForUserRequest()
		listPoliciesReq.UserName = userName
		listPoliciesRes, err := client.ListPoliciesForUser(listPoliciesReq)
		if err != nil {
			return errors.Wrap(err, "Failed to list ram policies for component user")
		}
		//detach each policy from user
		for _, userPolicy := range listPoliciesRes.Policies.Policy {
			//detach component policy from the existing ram user
			err := detachComponentPolicy(client, userPolicy.PolicyName, userName)
			if err != nil {
				return errors.Wrap(err, "Failed to detach ram policy from user")
			}
			//delete component ram policy
			err = deleteComponentPolicy(client, userPolicy.PolicyName)
			if err != nil {
				return errors.Wrap(err, "Failed to delete component ram policy after detaching from user please clean up leaked policy manually")
			}
		}
		//delete component ram user
		err = deleteComponentUser(client, userName)
		if err != nil {
			return errors.Wrap(err, "Failed to delete component user")
		}
	}
	return nil
}

func deleteRAMUsersCmd(cmd *cobra.Command, args []string) {
	client, err := alibabacloud.NewClient(DeleteRAMUsersOpts.Region)
	if err != nil {
		log.Fatalf("Failed to create a client: %v", err)
	}

	err = deleteRAMUsers(client, DeleteRAMUsersOpts.Name, DeleteRAMUsersOpts.CredRequestDir)
	if err != nil {
		log.Fatalf(err.Error())
	}
}

// NewDeleteRAMUsersCmd provides the "delete-ram-users" subcommand
func NewDeleteRAMUsersCmd() *cobra.Command {
	detachCmd := &cobra.Command{
		Use:   "delete-ram-users",
		Short: "Detach RAM Policy from existing user",
		Run:   deleteRAMUsersCmd,
	}

	detachCmd.PersistentFlags().StringVar(&DeleteRAMUsersOpts.Name, "name", "", "User-defined name for all created Alibaba Cloud resources (can be separate from the cluster's infra-id)")
	detachCmd.MarkPersistentFlagRequired("name")
	detachCmd.PersistentFlags().StringVar(&DeleteRAMUsersOpts.CredRequestDir, "credentials-requests-dir", "", "Directory containing files of CredentialsRequests to create RAM AK for (can be created by running 'oc adm release extract --credentials-requests --cloud=alibabacloud' against an OpenShift release image)")
	detachCmd.MarkPersistentFlagRequired("credentials-requests-dir")
	detachCmd.PersistentFlags().StringVar(&DeleteRAMUsersOpts.Region, "region", "", "Alibaba Cloud region endpoint only required for GovCloud")

	return detachCmd
}
