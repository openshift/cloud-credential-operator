package aws

import (
	"context"
	"io"
	"reflect"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	awsclient "github.com/openshift/cloud-credential-operator/pkg/aws"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/rotation"
)

func TestNewAWSCmdRegistersRotateSigningKey(t *testing.T) {
	t.Parallel()

	command := NewAWSCmd()
	for _, child := range command.Commands() {
		if child.Name() == "rotate-signing-key" {
			return
		}
	}
	t.Fatal("AWS command does not register rotate-signing-key")
}

func TestAWSRotateSigningKeyCommandWiresStandardS3DirectRunner(t *testing.T) {
	t.Parallel()

	type contextKey string
	const key contextKey = "aws-rotation-command"
	ctx := context.WithValue(context.Background(), key, "context-value")

	cluster := &awsRotationTestCluster{}
	target := &awsRotationTestTarget{}
	publisher := &awsRotationTestPublisher{}
	client := &awsRotationTestClient{}
	runner := &awsRotationTestRunner{result: rotation.RunResult{Phase: rotation.PhaseComplete, Complete: true}}

	var clusterKubeconfig string
	var configContext context.Context
	var configRegion string
	var clientConfig awssdk.Config
	var targetRegion, targetBucket string
	var publisherRegion, publisherBucket, publisherOwner string
	var runnerCluster rotation.ClusterRotation
	var runnerTarget rotation.TargetResolver
	var runnerPublisher rotation.ConditionalJWKSBackend

	dependencies := awsRotationDependencies{
		loadAWSConfig: func(receivedContext context.Context, region string) (awssdk.Config, error) {
			configContext = receivedContext
			configRegion = region
			return awssdk.Config{Region: region}, nil
		},
		newAWSClient: func(cfg awssdk.Config) (awsclient.Client, error) {
			clientConfig = cfg
			return client, nil
		},
		newCluster: func(kubeconfig string) (rotation.ClusterRotation, error) {
			clusterKubeconfig = kubeconfig
			return cluster, nil
		},
		newTarget: func(region, bucket string) (rotation.TargetResolver, error) {
			targetRegion = region
			targetBucket = bucket
			return target, nil
		},
		newPublisher: func(receivedClient awsclient.Client, region, bucket, owner string) (rotation.ConditionalJWKSBackend, error) {
			if receivedClient != client {
				t.Fatal("publisher constructor received a different AWS client")
			}
			publisherRegion = region
			publisherBucket = bucket
			publisherOwner = owner
			return publisher, nil
		},
		newOrchestrator: func(receivedCluster rotation.ClusterRotation, receivedTarget rotation.TargetResolver, receivedPublisher rotation.ConditionalJWKSBackend) rotation.Runner {
			runnerCluster = receivedCluster
			runnerTarget = receivedTarget
			runnerPublisher = receivedPublisher
			return runner
		},
	}

	command := newRotateSigningKeyCmd(dependencies)
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{
		"--name", "example-cluster",
		"--region", "us-east-1",
		"--kubeconfig", "/tmp/example.kubeconfig",
		"--output-dir", "/tmp/rotation-output",
		"--resume",
	})

	if err := command.ExecuteContext(ctx); err != nil {
		t.Fatalf("ExecuteContext() returned unexpected error: %v", err)
	}

	if clusterKubeconfig != "/tmp/example.kubeconfig" {
		t.Fatalf("cluster kubeconfig = %q, want /tmp/example.kubeconfig", clusterKubeconfig)
	}
	if configContext != ctx || configContext.Value(key) != "context-value" {
		t.Fatal("AWS configuration loader did not receive the command context")
	}
	if configRegion != "us-east-1" || clientConfig.Region != "us-east-1" {
		t.Fatalf("AWS configuration regions = %q and %q, want us-east-1", configRegion, clientConfig.Region)
	}
	if targetRegion != "us-east-1" || targetBucket != "example-cluster-oidc" {
		t.Fatalf("target arguments = (%q, %q), want (us-east-1, example-cluster-oidc)", targetRegion, targetBucket)
	}
	if publisherRegion != "us-east-1" || publisherBucket != "example-cluster-oidc" || publisherOwner != "example-cluster" {
		t.Fatalf("publisher arguments = (%q, %q, %q), want (us-east-1, example-cluster-oidc, example-cluster)", publisherRegion, publisherBucket, publisherOwner)
	}
	if runnerCluster != cluster || runnerTarget != target || runnerPublisher != publisher {
		t.Fatal("orchestrator constructor did not receive the constructed adapters")
	}
	wantOptions := rotation.RunOptions{
		Provider:        rotation.ProviderAWS,
		PublicationMode: rotation.PublicationModeDirect,
		OutputDir:       "/tmp/rotation-output",
		Resume:          true,
	}
	if !reflect.DeepEqual(runner.options, wantOptions) {
		t.Fatalf("runner options = %+v, want %+v", runner.options, wantOptions)
	}
	if runner.ctx != ctx || runner.calls != 1 {
		t.Fatalf("runner received context %v and %d calls, want command context and 1 call", runner.ctx, runner.calls)
	}
}

func TestAWSRotateSigningKeyCommandRequiresProviderFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		args      []string
		wantError string
	}{
		{
			name:      "name",
			args:      []string{"--region", "us-east-1", "--kubeconfig", "/tmp/kubeconfig", "--output-dir", "/tmp/output"},
			wantError: "required flag(s) \"name\" not set",
		},
		{
			name:      "region",
			args:      []string{"--name", "example-cluster", "--kubeconfig", "/tmp/kubeconfig", "--output-dir", "/tmp/output"},
			wantError: "required flag(s) \"region\" not set",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			command := newRotateSigningKeyCmd(awsRotationDependencies{})
			command.SilenceErrors = true
			command.SilenceUsage = true
			command.SetArgs(test.args)
			err := command.Execute()
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Execute() error = %v, want error containing %q", err, test.wantError)
			}
		})
	}
}

func TestAWSRotateSigningKeyCommandRejectsManualPublicationBeforeConstruction(t *testing.T) {
	t.Parallel()

	command := newRotateSigningKeyCmd(awsRotationDependencies{})
	command.SilenceErrors = true
	command.SilenceUsage = true
	command.SetArgs([]string{
		"--name", "example-cluster",
		"--region", "us-east-1",
		"--kubeconfig", "/tmp/kubeconfig",
		"--output-dir", "/tmp/output",
		"--publication-mode", "manual",
	})

	err := command.Execute()
	if err == nil || !strings.Contains(err.Error(), "supports only direct publication") {
		t.Fatalf("Execute() error = %v, want direct-publication-only error", err)
	}
}

type awsRotationTestClient struct {
	awsclient.Client
}

type awsRotationTestCluster struct {
	rotation.ClusterRotation
}

type awsRotationTestTarget struct {
	rotation.TargetResolver
}

type awsRotationTestPublisher struct {
	rotation.ConditionalJWKSBackend
}

type awsRotationTestRunner struct {
	ctx     context.Context
	options rotation.RunOptions
	calls   int
	result  rotation.RunResult
}

func (r *awsRotationTestRunner) Run(ctx context.Context, options rotation.RunOptions) (rotation.RunResult, error) {
	r.ctx = ctx
	r.options = options
	r.calls++
	return r.result, nil
}
