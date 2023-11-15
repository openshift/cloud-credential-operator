//go:build e2e
// +build e2e

package azident

import (
	"context"
	"os"
	"testing"
	"time"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/klient/conf"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

var testenv env.Environment
var secret = &corev1.Secret{}

const (
	name       = "test-azident-creds-req"
	namespace  = "default"
	secretName = "test-azident-secret"
)

func TestMain(m *testing.M) {
	testenv = env.New()
	path := conf.ResolveKubeConfigFile()
	cfg := envconf.NewWithKubeConfig(path)
	testenv = env.NewWithConfig(cfg)
	namespace := envconf.RandomName("sample-ns", 16)
	testenv.Setup(
		envfuncs.CreateNamespace(namespace),
	)
	testenv.Finish(
		envfuncs.DeleteNamespace(namespace),
	)
	os.Exit(testenv.Run(m))
}

func TestSecretCreationOnCredsRequestWithAzIdentInfo(t *testing.T) {
	t.Logf("About to create a CredentialsRequest for testing Secret creation")
	cr := newCredentialsRequest()
	credReqFeature := features.New("minterv1.CredentialsRequest").
		Setup(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			// create a CredentialsRequest
			client := cfg.Client()
			util.SetupScheme(scheme.Scheme)
			if err := client.Resources().Create(ctx, cr); err != nil {
				t.Fatal(err)
			}
			// watch for the Secret and trigger action based on the event received.
			client.Resources().Watch(
				&corev1.SecretList{},
				resources.WithFieldSelector(
					labels.FormatLabels(map[string]string{"metadata.name": secretName}))).
				WithAddFunc(onAdd(t, *cfg, ctx)).
				Start(ctx)
			return ctx
		}).
		Assess("secret creation", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			time.Sleep(2 * time.Minute)
			if secretName != secret.GetName() {
				t.Errorf("Secret name is incorrect. Expected: `%s`", secretName)
			}
			return context.WithValue(ctx, "test-secret", secret)
		}).
		Teardown(func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			if err := cfg.Client().Resources().Delete(ctx, cr); err != nil {
				t.Fatal(err)
			}
			return ctx
		}).Feature()
	testenv.Test(t, credReqFeature)
}

func onAdd(t *testing.T, cfg envconf.Config, ctx context.Context) func(obj interface{}) {
	time.Sleep(2 * time.Minute)
	if err := cfg.Client().Resources().Get(ctx, secretName, namespace, secret); err != nil {
		t.Fatal(err)
	}
	if secretName != secret.GetName() {
		t.Errorf("onAdd watch: Secret name is incorrect. Expected: `%s`", secretName)
	}
	klog.InfoS("Found Secret with name %s", secretName)
	return nil
}

func newCredentialsRequest() *minterv1.CredentialsRequest {
	var in = minterv1.AzureProviderSpec{
		RoleBindings: []minterv1.RoleBinding{
			{
				Role: "Owner",
			},
		},
		AzureClientID:       "0420bfd1-ab26-4b80-a9ac-deadbeeff1f9",
		AzureTenantID:       "6047c7e9-b2ad-488d-a54e-deadbeefa7ee",
		AzureRegion:         "centralus",
		AzureSubscriptionID: "8c20ec23-8478-4f46-96f4-deadbeeff185",
	}

	var ProviderSpec, _ = minterv1.Codec.EncodeProviderSpec(in.DeepCopyObject())
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
			CloudTokenPath: "",
		},
	}

	credReq := CredentialsRequestTemplate
	credReq.Spec.CloudTokenPath = "/var/cloud-token"
	return credReq
}
