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

package credentialsrequest

import (
	"context"
	"encoding/base64"
	"fmt"

	log "github.com/sirupsen/logrus"

	ccv1 "github.com/openshift/cloud-creds/pkg/apis/cloudcreds/v1beta1"
	ccaws "github.com/openshift/cloud-creds/pkg/aws"

	"github.com/aws/aws-sdk-go/service/iam"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
)

const (
	awsCredsNamespace = "kube-system"
	awsCredsSecret    = "aws-creds"
)

func (r *ReconcileCredentialsRequest) reconcileAWS(cr *ccv1.CredentialsRequest, logger log.FieldLogger) error {
	if cr.Status.AWS == nil {
		cr.Status.AWS = &ccv1.AWSStatus{}
	}

	// Generate a randomized User for the credentials:
	// TODO: check if the generated name is free
	if cr.Status.AWS.User == "" {
		cr.Status.AWS.User = fmt.Sprintf("%s-%s-%s", cr.Spec.ClusterName, cr.Name, utilrand.String(5))
		if len(cr.Status.AWS.User) > 64 {
			return fmt.Errorf("generated user name is too long for AWS: %s", cr.Status.AWS.User)
		}
		logger.WithField("user", cr.Status.AWS.User).Debug("generated random name for AWS user and policy")
		err := r.Status().Update(context.TODO(), cr)
		if err != nil {
			logger.WithError(err).Error("error updating credentials request")
			return err
		}
	}

	logger.Debug("loading AWS credentials from secret")
	// TODO: Running in a 4.0 cluster we expect this secret to exist. When we run in a Hive
	// cluster, we need to load different secrets for each cluster.
	accessKeyID, secretAccessKey, err := ccaws.LoadCredsFromSecret(r.Client, awsCredsNamespace, awsCredsSecret)
	if err != nil {
		return err
	}

	logger.Debug("creating AWS client")
	awsClient, err := r.awsClientBuilder(accessKeyID, secretAccessKey)
	if err != nil {
		return err
	}

	// Check if the credentials secret exists, if not we need to inform the syncer to generate a new one:
	existingSecret := &corev1.Secret{}
	err = r.Client.Get(context.TODO(), types.NamespacedName{Namespace: cr.Spec.Secret.Namespace, Name: cr.Spec.Secret.Name}, existingSecret)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Debug("secret does not exist")
		}
	}

	syncer := ccaws.NewCredSyncer(awsClient, cr.Spec.Secret, cr.Status.AWS.User, cr.Spec.AWS.StatementEntries, cr.Status.AWS.AccessKeyID)

	if cr.DeletionTimestamp != nil {
		err := syncer.Delete()
		if err != nil {
			logger.WithError(err).Error("error deleting credentails in AWS")
			return err
		}
		return r.removeDeprovisionFinalizer(cr)
	}

	forceNewAccessKey := existingSecret == nil || existingSecret.Name == ""
	userAccessKey, err := syncer.Sync(forceNewAccessKey)
	if err != nil {
		log.WithError(err).Error("error syncing credential to AWS")
		return err
	}

	if userAccessKey != nil {
		err := r.syncAccessKeySecret(cr, userAccessKey, existingSecret, logger)
		if err != nil {
			log.WithError(err).Error("error saving access key to secret")
			return err
		}

		// Save the access key ID to status
		// TODO Necessary or jsut use the secret data?
		cr.Status.AWS.AccessKeyID = *userAccessKey.AccessKeyId
	}

	return nil
}

func (r *ReconcileCredentialsRequest) syncAccessKeySecret(cr *ccv1.CredentialsRequest, accessKey *iam.AccessKey, existingSecret *corev1.Secret, logger log.FieldLogger) error {

	if existingSecret == nil || existingSecret.Name == "" {
		logger.Info("creating secret")
		b64AccessKeyID := base64.StdEncoding.EncodeToString([]byte(*accessKey.AccessKeyId))
		b64SecretAccessKey := base64.StdEncoding.EncodeToString([]byte(*accessKey.SecretAccessKey))
		err := r.Client.Create(context.TODO(), &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cr.Spec.Secret.Name,
				Namespace: cr.Spec.Secret.Namespace,
			},
			Data: map[string][]byte{
				"aws_access_key_id":     []byte(b64AccessKeyID),
				"aws_secret_access_key": []byte(b64SecretAccessKey),
			},
		})
		if err != nil {
			logger.WithError(err).Error("error creating secret")
			return err
		}
		logger.Info("secret created successfully")
		return nil
	}

	// Update the existing secret:
	logger.Info("updating secret: %v", existingSecret)
	existingSecret.Data["aws_access_key_id"] = []byte(base64.StdEncoding.EncodeToString([]byte(*accessKey.AccessKeyId)))
	existingSecret.Data["aws_secret_access_key"] = []byte(base64.StdEncoding.EncodeToString([]byte(*accessKey.SecretAccessKey)))
	err := r.Client.Update(context.TODO(), existingSecret)
	if err != nil {
		logger.WithError(err).Error("error updating secret")
		return err
	}

	return nil
}
