/*
Copyright 2018 The OpenShift Authors.

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

package aws

import (
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"

	ccv1 "github.com/openshift/cloud-creds/pkg/apis/cloudcreds/v1beta1"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"

	corev1 "k8s.io/api/core/v1"
)

// CredSyncer allows idempotently creating a user and policy in AWS, generating an AWS access key if required and
// storing it in the requested secret.
type CredSyncer struct {
	awsClient         Client
	userName          string
	entries           []ccv1.StatementEntry
	logger            log.FieldLogger
	existingAccessKey string
}

// NewCredSyncer creates a new CredSyncer.
func NewCredSyncer(awsClient Client, secret corev1.ObjectReference, username string, entries []ccv1.StatementEntry, existingAccessKey string) *CredSyncer {
	logger := log.WithFields(log.Fields{
		"userName": username,
	})
	return &CredSyncer{
		awsClient:         awsClient,
		userName:          username,
		entries:           entries,
		logger:            logger,
		existingAccessKey: existingAccessKey,
	}
}

// Sync idempotently ensures the user exists with the given permissions, and the expected activation key is present.
// Returns the access key ID in AWS, only if one had to be created.
func (cs *CredSyncer) Sync(forceNewAccessKey bool) (*iam.AccessKey, error) {
	cs.logger.Info("syncing credential to AWS")

	// Check if the user already exists:
	user, err := cs.awsClient.GetUser(&iam.GetUserInput{UserName: aws.String(cs.userName)})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				cs.logger.Info("user does not exist, creating")
				err := cs.createUser()
				if err != nil {
					return nil, err
				}
				cs.logger.Info("successfully created user")
			default:
				return nil, formatAWSErr(aerr)
			}
		} else {
			return nil, fmt.Errorf("unknown error getting user from AWS: %v", err)
		}
	} else {
		cs.logger.Debug("user exists: %v", user)
	}

	// TODO: check if user policy needs to be set? user generation and last set time.
	err = cs.setUserPolicy()
	if err != nil {
		return nil, err
	}
	cs.logger.Info("successfully set user policy")

	allUserKeys, err := cs.awsClient.ListAccessKeys(&iam.ListAccessKeysInput{UserName: aws.String(cs.userName)})
	if err != nil {
		cs.logger.WithError(err).Error("error listing all access keys for user")
		return nil, err
	}

	var accessKey *iam.AccessKey
	// TODO: also check if the access key ID on the request is still valid in AWS
	accessKeyExists, err := cs.accessKeyExists(allUserKeys)
	if err != nil {
		return nil, err
	}
	if forceNewAccessKey || !accessKeyExists {
		cs.logger.Info("generating new AWS access key")

		// Users are allowed a max of two keys, if we decided we need to generate one, we should cleanup all pre-existing access keys.
		// This will allow deleting the secret in Kubernetes to revoke old credentials and create new.
		err := cs.deleteAllAccessKeys(allUserKeys)
		if err != nil {
			return nil, err
		}

		accessKey, err = cs.createAccessKey()
		if err != nil {
			cs.logger.WithError(err).Error("error creating AWS access key")
			return nil, err
		}
	}

	return accessKey, nil
}

func (cs *CredSyncer) accessKeyExists(allUserKeys *iam.ListAccessKeysOutput) (bool, error) {
	if cs.existingAccessKey == "" {
		return false, nil
	}

	for _, key := range allUserKeys.AccessKeyMetadata {
		if *key.AccessKeyId == cs.existingAccessKey {
			return true, nil
		}
	}
	cs.logger.WithField("accessKeyID", cs.existingAccessKey).Warn("access key no longer exists")
	return false, nil
}

func (cs *CredSyncer) deleteAllAccessKeys(allUserKeys *iam.ListAccessKeysOutput) error {
	log.Info("deleting all AWS access keys")
	for _, kmd := range allUserKeys.AccessKeyMetadata {
		akLog := cs.logger.WithFields(log.Fields{
			"accessKeyID": *kmd.AccessKeyId,
			"createDate":  *kmd.CreateDate,
		})
		akLog.Info("deleting access key")
		_, err := cs.awsClient.DeleteAccessKey(&iam.DeleteAccessKeyInput{AccessKeyId: kmd.AccessKeyId, UserName: aws.String(cs.userName)})
		if err != nil {
			akLog.WithError(err).Error("error deleting access key")
			return err
		}
	}
	log.Info("all access keys deleted")
	return nil
}

// Delete ensures the given credential is deleted from AWS.
func (cs *CredSyncer) Delete() error {
	cs.logger.Info("deleting credential from AWS")

	_, err := cs.awsClient.DeleteUserPolicy(&iam.DeleteUserPolicyInput{
		UserName:   aws.String(cs.userName),
		PolicyName: aws.String(cs.getPolicyName()),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				cs.logger.Warn("user policy does not exist, ignoring error")
			default:
				return formatAWSErr(aerr)
			}
		} else {
			return fmt.Errorf("unknown error deleting user policy from AWS: %v", err)
		}
	}
	cs.logger.Info("user policy deleted")

	allUserKeys, err := cs.awsClient.ListAccessKeys(&iam.ListAccessKeysInput{UserName: aws.String(cs.userName)})
	if err != nil {
		cs.logger.WithError(err).Error("error listing all access keys for user")
		return err
	}

	err = cs.deleteAllAccessKeys(allUserKeys)
	if err != nil {
		return err
	}

	_, err = cs.awsClient.DeleteUser(&iam.DeleteUserInput{
		UserName: aws.String(cs.userName),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case iam.ErrCodeNoSuchEntityException:
				cs.logger.Warn("user does not exist, returning success")
			default:
				return formatAWSErr(aerr)
			}
		} else {
			return fmt.Errorf("unknown error deleting user from AWS: %v", err)
		}
	}
	cs.logger.Info("user deleted")

	return nil
}

func (cs *CredSyncer) createUser() error {
	input := &iam.CreateUserInput{
		UserName: aws.String(cs.userName),
	}

	_, err := cs.awsClient.CreateUser(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return formatAWSErr(aerr)
		}
		return fmt.Errorf("unknown error creating user in AWS: %v", err)
	}

	return nil
}

func (cs *CredSyncer) getPolicyName() string {
	return cs.userName + "-policy"
}

func (cs *CredSyncer) setUserPolicy() error {
	policyName := cs.getPolicyName()

	policyDoc := PolicyDocument{
		Version:   "2012-10-17",
		Statement: []StatementEntry{},
	}
	for _, se := range cs.entries {
		policyDoc.Statement = append(policyDoc.Statement, StatementEntry{
			Effect:   se.Effect,
			Action:   se.Action,
			Resource: se.Resource,
		})
	}
	b, err := json.Marshal(&policyDoc)
	if err != nil {
		return fmt.Errorf("error marshalling policy: %v", err)
	}

	// This call appears to be idempotent:
	_, err = cs.awsClient.PutUserPolicy(&iam.PutUserPolicyInput{
		UserName:       aws.String(cs.userName),
		PolicyDocument: aws.String(string(b)),
		PolicyName:     aws.String(policyName),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return formatAWSErr(aerr)
		}
		return fmt.Errorf("unknown error setting user policy in AWS: %v", err)
	}

	return nil
}

func (cs *CredSyncer) createAccessKey() (*iam.AccessKey, error) {
	// Check if we need to generate an access key:
	// Create secret and access key for user:
	accessKeyResult, err := cs.awsClient.CreateAccessKey(&iam.CreateAccessKeyInput{
		UserName: &cs.userName,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating access key for user %s: %v", cs.userName, err)
	}
	cs.logger.WithField("accessKeyID", *accessKeyResult.AccessKey.AccessKeyId).Info("access key created")
	return accessKeyResult.AccessKey, err
}

func formatAWSErr(aerr awserr.Error) error {
	switch aerr.Code() {
	case iam.ErrCodeLimitExceededException:
		log.Error(iam.ErrCodeLimitExceededException, aerr.Error())
		return fmt.Errorf("AWS Error: %s - %s", iam.ErrCodeLimitExceededException, aerr.Error())
	case iam.ErrCodeEntityAlreadyExistsException:
		return fmt.Errorf("AWS Error: %s - %s", iam.ErrCodeEntityAlreadyExistsException, aerr.Error())
	case iam.ErrCodeNoSuchEntityException:
		return fmt.Errorf("AWS Error: %s - %s", iam.ErrCodeNoSuchEntityException, aerr.Error())
	case iam.ErrCodeServiceFailureException:
		return fmt.Errorf("AWS Error: %s - %s", iam.ErrCodeServiceFailureException, aerr.Error())
	default:
		log.Error(aerr.Error())
		return fmt.Errorf("AWS Error: %v", aerr)
	}
}

// PolicyDocument is a simple type used to serialize to AWS' PolicyDocument format.
type PolicyDocument struct {
	Version   string
	Statement []StatementEntry
}

// StatementEntry is a simple type used to serialize to AWS' PolicyDocument format. We cannot
// re-use ccv1.StatementEntry due to different conventions for the serialization keys. (caps)
type StatementEntry struct {
	Effect   string
	Action   []string
	Resource string
}
