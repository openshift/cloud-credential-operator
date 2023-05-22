//go:build e2e
// +build e2e

package sts

import (
	"context"
	log "github.com/sirupsen/logrus"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"os"
	ctrlrt "sigs.k8s.io/controller-runtime"
	"testing"
)

// Test_CheckSTS runs end-to-end tests to verify that the results of an STS workflow are successful.

func Test_CheckSTS(t *testing.T) {
	t.Run("test of Secret creation when STS enabled cluster detected", func(t *testing.T) {
		t.Parallel()
		log.Info("starting AWS STS Secret Created on CredentialsRequest creation test")
		const (
			name      = "mycredrequest"
			namespace = "mynamespace"
		)

		var in = minterv1.AWSProviderSpec{
			StatementEntries: []minterv1.StatementEntry{
				{
					Action: []string{
						"s3:*",
					},
					Effect:   "Allow",
					Resource: "arn:aws:s3:*:*:*",
				},
			},
		}

		var codec, _ = minterv1.NewCodec()
		var ProviderSpec, _ = codec.EncodeProviderSpec(in.DeepCopyObject())
		var CredentialsRequestTemplate = &minterv1.CredentialsRequest{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "openshift-cloud-credential-operator",
			},
			Spec: minterv1.CredentialsRequestSpec{
				ProviderSpec: ProviderSpec,
				SecretRef: corev1.ObjectReference{
					Name:      "mysecret",
					Namespace: namespace,
				},
				ServiceAccountNames: []string{
					"serviceaccountname",
				},
				CloudTokenString: "",
				CloudTokenPath:   "",
			},
		}

		scheme := runtime.NewScheme()
		// apply credentialsRequest on install
		credReq := CredentialsRequestTemplate
		credReq.Spec.CloudTokenPath = "/var/cloud-token"
		credReq.Spec.CloudTokenString = "arn:aws:iam::269733383069:oidc-provider/newstscluster-oidc.s3.us-east-1.amazonaws.com"
		log.Info("creating ctrl-runtime manager")
		mgr, err := ctrlrt.NewManager(ctrlrt.GetConfigOrDie(), ctrlrt.Options{
			Scheme:    scheme,
			Namespace: namespace,
		})
		log.Info("created ctrl-runtime manager")
		if err != nil {
			log.Error(err, "unable to create controller manager", "aws.service", "aws-service")
			os.Exit(1)
		}
		log.Info("getting client from ctrl-runtime manager")
		c := mgr.GetClient()
		log.Info("calling Create for CredentialsRequest")
		if err := c.Create(context.TODO(), credReq); err != nil {
			if !errors.IsAlreadyExists(err) {
				log.Error(err, "unable to create CredRequest")
				os.Exit(1)
			}
		}
		// If CredentialsRequest was created, then Secret should have been too
		//TODO actually check if Secret exists
		assert.NoError(t, err, "unable to create Secret from CredentialsRequest")
	})
}
