package ibmcloud

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflect"

	"github.com/pkg/errors"

	"k8s.io/apimachinery/pkg/runtime"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/iamidentityv1"
	"github.com/IBM/platform-services-go-sdk/iampolicymanagementv1"

	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/ibmcloud"
)

const (
	//TODO(mkumatag): Remove the entry for ibmcloud_api_key once all the in-cluster components migrate to use the GetAuthenticatorFromEnvironment method
	secretManifestsTemplate = `apiVersion: v1
stringData:
  ibmcloud_api_key: %s
  ibm-credentials.env: |
    IBMCLOUD_APIKEY=%s
    IBMCLOUD_AUTHTYPE=iam
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque`

	manifestsDirName      = "manifests"
	secretFileNamePattern = "%s-%s-credentials.yaml"
)

var _ Provision = &ServiceID{}

type Provision interface {
	Validate() error

	Do() error
	UnDo(string) error

	Dump(string) error
}

type ServiceID struct {
	ibmcloud.Client
	*iamidentityv1.ServiceID

	name            string
	accountID       string
	resourceGroupID string
	cr              *credreqv1.CredentialsRequest
	apiKey          *string
}

func (s *ServiceID) Validate() error {
	codec, err := credreqv1.NewCodec()
	if err != nil {
		return errors.Wrap(err, "Failed to create credReq codec")
	}

	var unknown runtime.Unknown
	err = codec.DecodeProviderSpec(s.cr.Spec.ProviderSpec, &unknown)
	if err != nil {
		return errors.Wrapf(err, "failed to DecodeProviderSpec")
	}

	if unknown.Kind != reflect.TypeOf(credreqv1.IBMCloudProviderSpec{}).Name() &&
		unknown.Kind != reflect.TypeOf(credreqv1.IBMCloudPowerVSProviderSpec{}).Name() {
		return fmt.Errorf("not supported of kind: %s", unknown.Kind)
	}

	options := &iamidentityv1.ListServiceIdsOptions{
		AccountID: &s.accountID,
		Name:      &s.name,
	}
	list, _, err := s.Client.ListServiceID(options)
	if err != nil {
		return errors.Wrapf(err, "failed to list the serviceIDs")
	}
	if len(list.Serviceids) != 0 {
		return errors.Errorf("exists with the same name: %s, please delete the entries or create with a different name", s.name)
	}
	return nil
}

func (s *ServiceID) Do() error {
	serviceIDOptions := &iamidentityv1.CreateServiceIDOptions{
		AccountID: &s.accountID,
		Name:      &s.name,
	}
	id, _, err := s.Client.CreateServiceID(serviceIDOptions)
	if err != nil {
		return err
	}
	s.ServiceID = id
	policies, err := s.extractPolicies()
	if err != nil {
		return errors.Wrapf(err, "Failed to extract the policies: %+v", err)
	}
	// Create a new Access Policy for each policy in the CredReq.
	for _, policy := range policies {
		err = s.createPolicy(&policy)
		if err != nil {
			return errors.Wrapf(err, "Failed to create access policy with: %+v", policy)
		}
	}

	if err := s.createAPIKey(); err != nil {
		return errors.Wrapf(err, "Failed to create an API Key for ServiceID Name: %s, ID: %s", *s.ServiceID.Name, *s.ServiceID.ID)
	}
	return nil
}

func (s *ServiceID) Dump(targetDir string) error {
	if s.apiKey == nil || s.cr == nil {
		return errors.New("apiKey or credentialRequest can't be nil")
	}
	manifestsDir := filepath.Join(targetDir, manifestsDirName)

	fileName := fmt.Sprintf(secretFileNamePattern, s.cr.Spec.SecretRef.Namespace, s.cr.Spec.SecretRef.Name)
	filePath := filepath.Join(manifestsDir, fileName)

	fileData := fmt.Sprintf(secretManifestsTemplate, *s.apiKey, *s.apiKey, s.cr.Spec.SecretRef.Name, s.cr.Spec.SecretRef.Namespace)

	if err := ioutil.WriteFile(filePath, []byte(fileData), 0600); err != nil {
		return errors.Wrap(err, "Failed to save Secret file")
	}

	log.Printf("Saved credentials configuration to: %s", filePath)

	return nil
}

func (s *ServiceID) createAPIKey() error {
	// Create a new API Key for the Service ID.
	apiKeyOptions := &iamidentityv1.CreateAPIKeyOptions{
		Name:  &APIKeyName,
		IamID: s.IamID,
	}
	apiKey, _, err := s.Client.CreateAPIKey(apiKeyOptions)
	if err != nil {
		return errors.Wrap(err, "Failed to create Service ID API key")
	}
	s.apiKey = apiKey.Apikey
	return nil
}

func (s *ServiceID) createPolicy(policy *credreqv1.AccessPolicy) error {
	// Construct the subjects with the newly created Service ID.
	subjects := []iampolicymanagementv1.PolicySubject{
		{
			Attributes: []iampolicymanagementv1.SubjectAttribute{
				{
					Name:  core.StringPtr("iam_id"),
					Value: core.StringPtr(*s.IamID),
				},
			},
		},
	}

	// Construct the access policy's roles.
	roles := make([]iampolicymanagementv1.PolicyRole, len(policy.Roles))
	for i, role := range policy.Roles {
		roles[i] = iampolicymanagementv1.PolicyRole{
			RoleID: core.StringPtr(role),
		}
	}

	// Construct the access policy's resource attributes.
	resourceAttributes := make([]iampolicymanagementv1.ResourceAttribute, len(policy.Attributes))
	for i, attr := range policy.Attributes {
		resourceAttributes[i] = iampolicymanagementv1.ResourceAttribute{
			Name:  core.StringPtr(attr.Name),
			Value: core.StringPtr(attr.Value),
		}
	}

	// Append the resource group attribute if specified as a command line argument.
	if s.resourceGroupID != "" {
		resourceGroupAttrName := "resourceGroupId"
		for _, attr := range resourceAttributes {
			if *attr.Name == "resourceType" && *attr.Value == "resource-group" {
				resourceGroupAttrName = "resource"
				break
			}
		}
		resourceAttributes = append(resourceAttributes, iampolicymanagementv1.ResourceAttribute{
			Name:  &resourceGroupAttrName,
			Value: &s.resourceGroupID,
		})
	}

	// Append the required accountId attribute.
	resourceAttributes = append(resourceAttributes, iampolicymanagementv1.ResourceAttribute{
		Name:  core.StringPtr("accountId"),
		Value: &s.accountID,
	})

	resources := []iampolicymanagementv1.PolicyResource{{
		Attributes: resourceAttributes,
	}}

	// Create the access policy.
	policyOptions := &iampolicymanagementv1.CreatePolicyOptions{
		Type:      core.StringPtr("access"),
		Subjects:  subjects,
		Roles:     roles,
		Resources: resources,
	}
	iamAccessPolicy, _, err := s.Client.CreatePolicy(policyOptions)
	if err != nil {
		return errors.Wrap(err, "Failed to create policy")
	}

	apJSON, _ := json.MarshalIndent(iamAccessPolicy, "", "  ")
	log.Printf("Created IAM Access Policy:\n%s", apJSON)

	return nil
}

func (s *ServiceID) extractPolicies() (policies []credreqv1.AccessPolicy, err error) {
	codec, err := credreqv1.NewCodec()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create credReq codec")
	}
	var unknown runtime.Unknown
	err = codec.DecodeProviderSpec(s.cr.Spec.ProviderSpec, &unknown)
	if err != nil {
		return nil, err
	}

	switch unknown.Kind {
	case reflect.TypeOf(credreqv1.IBMCloudProviderSpec{}).Name():
		ibmcloudProviderSpec := &credreqv1.IBMCloudProviderSpec{}
		if err := codec.DecodeProviderSpec(s.cr.Spec.ProviderSpec, ibmcloudProviderSpec); err != nil {
			return nil, errors.Wrap(err, "Failed to decode the provider spec")
		}
		policies = ibmcloudProviderSpec.Policies
	case reflect.TypeOf(credreqv1.IBMCloudPowerVSProviderSpec{}).Name():
		ibmCloudPowerVSProviderSpec := &credreqv1.IBMCloudPowerVSProviderSpec{}
		if err := codec.DecodeProviderSpec(s.cr.Spec.ProviderSpec, ibmCloudPowerVSProviderSpec); err != nil {
			return nil, errors.Wrap(err, "Failed to decode the provider spec")
		}
		policies = ibmCloudPowerVSProviderSpec.Policies
	default:
		return nil, fmt.Errorf("not supported of kind: %s", unknown.Kind)
	}
	return
}

func (s *ServiceID) UnDo(targetDir string) error {
	if s.ServiceID == nil {
		return fmt.Errorf("no ServiceID present for: %s", s.name)
	}

	log.Printf("Deleting the ServiceID, Name:%s, ID: %s", *s.Name, *s.ID)
	options := &iamidentityv1.DeleteServiceIDOptions{
		ID: s.ID}
	_, err := s.Client.DeleteServiceID(options)
	if err != nil {
		log.Printf("Failed to delete the Service ID: %s", *s.ID)
	} else {
		log.Printf("Successfully deleted the Service ID: %s", *s.ID)
	}

	secretFileName := filepath.Join(targetDir, manifestsDirName, fmt.Sprintf(secretFileNamePattern, s.cr.Spec.SecretRef.Namespace, s.cr.Spec.SecretRef.Name))
	if _, err := os.Stat(secretFileName); err == nil {
		log.Printf("Deleting the generated secret, file:%s", secretFileName)
		err = os.Remove(secretFileName)
		if err != nil {
			log.Printf("failed to delete file: %s", secretFileName)
		}
	}

	return nil
}

func NewServiceID(client ibmcloud.Client, prefix, accountID, resourceGroupID string, cr *credreqv1.CredentialsRequest) *ServiceID {
	return &ServiceID{
		Client:          client,
		name:            prefix + "-" + cr.Spec.SecretRef.Namespace + "-" + cr.Spec.SecretRef.Name,
		cr:              cr,
		accountID:       accountID,
		resourceGroupID: resourceGroupID,
	}
}
