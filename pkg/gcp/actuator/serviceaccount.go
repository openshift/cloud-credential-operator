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
	"regexp"

	log "github.com/sirupsen/logrus"

	iamadminpb "google.golang.org/genproto/googleapis/iam/admin/v1"

	ccgcp "github.com/openshift/cloud-credential-operator/pkg/gcp"
)

var (
	// key names have the form projects/<projectName>/serviceAccounts/<serviceAccountID>@<projectName>.iam.gserviceaccount.com/keys/<keyID>
	// so just match up to the final /
	keyIDFromKeyName = regexp.MustCompile(`.*/`)
)

func getServiceAccount(gcpClient ccgcp.Client, svcAcctID string) (*iamadminpb.ServiceAccount, error) {
	projectName := gcpClient.GetProjectName()

	restString := fmt.Sprintf("projects/%s/serviceAccounts/%s@%s.iam.gserviceaccount.com", projectName, svcAcctID, projectName)
	request := &iamadminpb.GetServiceAccountRequest{
		Name: restString,
	}
	svcAcct, err := gcpClient.GetServiceAccount(context.TODO(), request)
	if err != nil {
		return nil, err
	}
	return svcAcct, nil
}

func createServiceAccount(gcpClient ccgcp.Client, svcAcctID, svcAcctName, projectName string) (*iamadminpb.ServiceAccount, error) {
	request := &iamadminpb.CreateServiceAccountRequest{
		Name:      fmt.Sprintf("projects/%s", projectName),
		AccountId: svcAcctID,
		ServiceAccount: &iamadminpb.ServiceAccount{
			DisplayName: svcAcctName,
		},
	}
	svcAcct, err := gcpClient.CreateServiceAccount(context.TODO(), request)
	if err != nil {
		return nil, err
	}
	return svcAcct, nil
}

func ensureServiceAccountKeys(rootClient ccgcp.Client, svcAcct *iamadminpb.ServiceAccount, projectName, keyID string, logger log.FieldLogger) (*iamadminpb.ServiceAccountKey, error) {
	restString := fmt.Sprintf("projects/%s/serviceAccounts/%s", projectName, svcAcct.UniqueId)
	listKeysRequest := &iamadminpb.ListServiceAccountKeysRequest{
		Name: restString,
	}

	listKeysResponse, err := rootClient.ListServiceAccountKeys(context.TODO(), listKeysRequest)
	if err != nil {
		return nil, fmt.Errorf("error getting list of keys for service account: %v", err)
	}

	if keyID != "" {
		// Check if one of the listed keys is the current one in use
		for _, key := range listKeysResponse.Keys {
			testKeyID := extractKeyIDFromKeyName(key.Name)
			if testKeyID == keyID {
				// keyid in secret is available on serviceaccount
				// no need to create a new key
				return nil, nil
			}
		}
	}

	// Create a key, but first remove any extra keys on the service account
	for _, key := range listKeysResponse.Keys {
		deleteKeyRequest := &iamadminpb.DeleteServiceAccountKeyRequest{
			Name: key.Name,
		}
		if err := rootClient.DeleteServiceAccountKey(context.TODO(), deleteKeyRequest); err != nil {
			// GCP will return an extra hidden key that we cannot delete
			logger.Warningf("failed to remove extra service account key: %v", err)
		}
	}

	createKeyRequest := &iamadminpb.CreateServiceAccountKeyRequest{
		Name: restString,
	}
	key, err := rootClient.CreateServiceAccountKey(context.TODO(), createKeyRequest)
	if err != nil {
		return nil, fmt.Errorf("error creating key: %v", err)
	}

	return key, err
}

func serviceAccountKeyExists(gcpClient ccgcp.Client, svcAcctID, keyID string, logger log.FieldLogger) (bool, error) {

	if keyID == "" {
		// empty keyID means there must be no key
		return false, nil
	}

	projectName := gcpClient.GetProjectName()
	svcAcctEmail := serviceAccountEmail(svcAcctID, projectName)
	restString := fmt.Sprintf("projects/%s/serviceAccounts/%s", projectName, svcAcctEmail)

	listKeysRequest := &iamadminpb.ListServiceAccountKeysRequest{
		Name: restString,
	}

	listKeysResponse, err := gcpClient.ListServiceAccountKeys(context.TODO(), listKeysRequest)
	if err != nil {
		return false, fmt.Errorf("error getting list of keys for service account: %v", err)
	}

	for _, key := range listKeysResponse.Keys {
		testKeyID := extractKeyIDFromKeyName(key.Name)
		if testKeyID == keyID {
			return true, nil
		}
	}

	return false, nil
}

func deleteServiceAccount(gcpClient ccgcp.Client, svcAcct *iamadminpb.ServiceAccount) error {
	req := &iamadminpb.DeleteServiceAccountRequest{
		Name: svcAcct.Name,
	}
	if err := gcpClient.DeleteServiceAccount(context.TODO(), req); err != nil {
		return err
	}

	return nil
}

func serviceAccountBindingName(svcAccount *iamadminpb.ServiceAccount) string {
	return fmt.Sprintf("serviceAccount:%s", svcAccount.Email)
}

func serviceAccountEmail(svcAccountID, projectName string) string {
	return fmt.Sprintf("%s@%s.iam.gserviceaccount.com", svcAccountID, projectName)
}
