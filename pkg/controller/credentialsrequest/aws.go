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
	"fmt"

	log "github.com/sirupsen/logrus"

	ccv1 "github.com/openshift/cloud-creds/pkg/apis/cloudcreds/v1beta1"
	ccaws "github.com/openshift/cloud-creds/pkg/aws"

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
	awsClient, err := ccaws.NewClient(accessKeyID, secretAccessKey)
	if err != nil {
		return err
	}

	logger.Debug("aws client = %v", awsClient)
	syncer := ccaws.NewCredSyncer(awsClient, r.Client, cr.Spec.Secret, cr.Status.AWS.User, cr.Spec.AWS.Actions)

	if cr.DeletionTimestamp != nil {
		err := syncer.Delete()
		if err != nil {
			logger.WithError(err).Error("error deleting credentails in AWS")
			return err
		}
		return r.removeDeprovisionFinalizer(cr)
	}

	userAccessKeyID, err := syncer.Sync()
	if err != nil {
		log.WithError(err).Error("error syncing credential to AWS")
	}

	if userAccessKeyID != "" {
		cr.Status.AWS.AccessKeyID = userAccessKeyID
	}

	return nil
}
