package sts

import (
	"context"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/types"

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
			name       = "test-sts-creds-req"
			namespace  = "default"
			secretName = "test-sts-secret"
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
					Name:      secretName,
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
		log.Info("trying to call AddToScheme method")
		minterv1.AddToScheme(scheme)
		corev1.AddToScheme(scheme)

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
		err = mgr.Start(context.TODO())
		if err != nil {
			log.Error(err, "unable to start controller manager", "aws.service", "aws-service")
			os.Exit(1)
		}
		log.Info("started ctrl-runtime manager")
		c := mgr.GetClient()
		log.Info("calling Create for CredentialsRequest")
		if err := c.Create(context.TODO(), credReq); err != nil {
			if !errors.IsAlreadyExists(err) {
				log.Error(err, "unable to create CredRequest")
				os.Exit(1)
			}
		}
		log.Info("got client from ctrl-runtime manager")
		// If CredentialsRequest was created, then Secret should have been too
		err = c.Get(context.TODO(),
			types.NamespacedName{Namespace: credReq.Spec.SecretRef.Namespace, Name: credReq.Spec.SecretRef.Name},
			&corev1.Secret{})
		//TODO actually check if Secret contains the right STS items
		assert.NoError(t, err, "unable to create Secret from CredentialsRequest")
	})
}
