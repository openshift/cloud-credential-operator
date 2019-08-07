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

package secretannotator

import (
	configv1 "github.com/openshift/api/config/v1"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/openshift/cloud-credential-operator/pkg/controller/platform"
	"github.com/openshift/cloud-credential-operator/pkg/controller/secretannotator/aws"
	"github.com/openshift/cloud-credential-operator/pkg/controller/secretannotator/azure"
	"github.com/openshift/cloud-credential-operator/pkg/controller/secretannotator/gcp"
	log "github.com/sirupsen/logrus"
)

func Add(mgr manager.Manager) error {
	infraStatus, err := platform.GetInfraStatus(mgr)
	if err != nil {
		log.Fatal(err)
	}
	platformType := platform.GetType(infraStatus)

	log.Infof("Setting up secret annotator. Platform Type is %s", platformType)

	switch platformType {
	case configv1.AzurePlatformType:
		return azure.Add(mgr, azure.NewReconciler(mgr))
	case configv1.AWSPlatformType:
		return aws.Add(mgr, aws.NewReconciler(mgr))
	case configv1.GCPPlatformType:
		if infraStatus.PlatformStatus == nil || infraStatus.PlatformStatus.GCP == nil {
			log.Fatalf("Missing GCP configuration in infrastructure platform status")
		}
		return gcp.Add(mgr, gcp.NewReconciler(mgr, infraStatus.PlatformStatus.GCP.ProjectID))
	default: // returning the AWS implementation for default to avoid changing any behavior
		return aws.Add(mgr, aws.NewReconciler(mgr))
	}
}
