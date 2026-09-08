package aws

import (
	"context"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/spf13/cobra"

	awsclient "github.com/openshift/cloud-credential-operator/pkg/aws"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/rotation"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/rotation/kubeadapter"
)

type rotateSigningKeyOptions struct {
	name   string
	region string
}

type awsRotationDependencies struct {
	loadAWSConfig   func(context.Context, string) (awssdk.Config, error)
	newAWSClient    func(awssdk.Config) (awsclient.Client, error)
	newCluster      func(string) (rotation.ClusterRotation, error)
	newTarget       func(string, string) (rotation.TargetResolver, error)
	newPublisher    func(awsclient.Client, string, string, string) (rotation.ConditionalJWKSBackend, error)
	newOrchestrator func(rotation.ClusterRotation, rotation.TargetResolver, rotation.ConditionalJWKSBackend) rotation.Runner
}

// NewRotateSigningKeyCmd returns the AWS direct-publication signing-key
// rotation command for the standard ccoctl-managed S3 issuer layout.
func NewRotateSigningKeyCmd() *cobra.Command {
	return newRotateSigningKeyCmd(defaultAWSRotationDependencies())
}

func newRotateSigningKeyCmd(dependencies awsRotationDependencies) *cobra.Command {
	options := rotateSigningKeyOptions{}
	command := rotation.NewCommand(rotation.ProviderAWS, newAWSRotationRunnerFactory(&options, dependencies))

	flags := command.Flags()
	flags.StringVar(&options.name, "name", "", "Name used to identify and own the AWS resources")
	flags.StringVar(&options.region, "region", "", "AWS region containing the OIDC issuer bucket")
	mustMarkAWSRotationFlagRequired(command, "name")
	mustMarkAWSRotationFlagRequired(command, "region")

	return command
}

func newAWSRotationRunnerFactory(options *rotateSigningKeyOptions, dependencies awsRotationDependencies) rotation.RunnerFactory {
	return func(ctx context.Context, kubeconfig string, runOptions rotation.RunOptions) (rotation.RunnerSetup, error) {
		if runOptions.PublicationMode != rotation.PublicationModeDirect {
			return rotation.RunnerSetup{}, fmt.Errorf("AWS signing-key rotation supports only direct publication")
		}
		if options == nil {
			return rotation.RunnerSetup{}, fmt.Errorf("AWS signing-key rotation options must not be nil")
		}
		if strings.TrimSpace(options.name) == "" || strings.TrimSpace(options.name) != options.name {
			return rotation.RunnerSetup{}, fmt.Errorf("AWS resource name must not be empty or contain surrounding whitespace")
		}
		if strings.TrimSpace(options.region) == "" || strings.TrimSpace(options.region) != options.region {
			return rotation.RunnerSetup{}, fmt.Errorf("AWS region must not be empty or contain surrounding whitespace")
		}
		if err := validateAWSRotationDependencies(dependencies); err != nil {
			return rotation.RunnerSetup{}, err
		}

		bucket := options.name + "-oidc"
		target, err := dependencies.newTarget(options.region, bucket)
		if err != nil {
			return rotation.RunnerSetup{}, fmt.Errorf("construct AWS S3 rotation target: %w", err)
		}
		cluster, err := dependencies.newCluster(kubeconfig)
		if err != nil {
			return rotation.RunnerSetup{}, fmt.Errorf("construct cluster rotation adapter: %w", err)
		}
		cfg, err := dependencies.loadAWSConfig(ctx, options.region)
		if err != nil {
			return rotation.RunnerSetup{}, fmt.Errorf("load AWS configuration: %w", err)
		}
		client, err := dependencies.newAWSClient(cfg)
		if err != nil {
			return rotation.RunnerSetup{}, fmt.Errorf("construct AWS client: %w", err)
		}
		publisher, err := dependencies.newPublisher(client, options.region, bucket, options.name)
		if err != nil {
			return rotation.RunnerSetup{}, fmt.Errorf("construct AWS S3 JWKS publisher: %w", err)
		}
		runner := dependencies.newOrchestrator(cluster, target, publisher)
		if runner == nil {
			return rotation.RunnerSetup{}, fmt.Errorf("construct AWS signing-key rotation runner: returned nil runner")
		}

		return rotation.RunnerSetup{Runner: runner}, nil
	}
}

func defaultAWSRotationDependencies() awsRotationDependencies {
	return awsRotationDependencies{
		loadAWSConfig: func(ctx context.Context, region string) (awssdk.Config, error) {
			return config.LoadDefaultConfig(ctx, config.WithRegion(region))
		},
		newAWSClient: func(cfg awssdk.Config) (awsclient.Client, error) {
			return awsclient.NewClientFromConfig(cfg, "")
		},
		newCluster: func(kubeconfig string) (rotation.ClusterRotation, error) {
			return kubeadapter.New(kubeconfig)
		},
		newTarget: func(region, bucket string) (rotation.TargetResolver, error) {
			return NewS3TargetResolver(region, bucket)
		},
		newPublisher: func(client awsclient.Client, region, bucket, ownerName string) (rotation.ConditionalJWKSBackend, error) {
			return NewS3JWKSBackend(client, region, bucket, ownerName)
		},
		newOrchestrator: func(cluster rotation.ClusterRotation, target rotation.TargetResolver, publisher rotation.ConditionalJWKSBackend) rotation.Runner {
			return &rotation.Orchestrator{Cluster: cluster, Target: target, Publisher: publisher}
		},
	}
}

func validateAWSRotationDependencies(dependencies awsRotationDependencies) error {
	switch {
	case dependencies.loadAWSConfig == nil:
		return fmt.Errorf("AWS configuration loader must not be nil")
	case dependencies.newAWSClient == nil:
		return fmt.Errorf("AWS client constructor must not be nil")
	case dependencies.newCluster == nil:
		return fmt.Errorf("cluster rotation adapter constructor must not be nil")
	case dependencies.newTarget == nil:
		return fmt.Errorf("AWS S3 target constructor must not be nil")
	case dependencies.newPublisher == nil:
		return fmt.Errorf("AWS S3 publisher constructor must not be nil")
	case dependencies.newOrchestrator == nil:
		return fmt.Errorf("rotation orchestrator constructor must not be nil")
	default:
		return nil
	}
}

func mustMarkAWSRotationFlagRequired(command *cobra.Command, name string) {
	if err := command.MarkFlagRequired(name); err != nil {
		panic(err)
	}
}
