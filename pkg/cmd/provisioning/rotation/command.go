package rotation

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// Runner executes one new or resumed rotation operation.
type Runner interface {
	Run(context.Context, RunOptions) (RunResult, error)
}

// RunnerSetup contains the concrete runner and any provider-owned manual input
// collected by its command wrapper.
type RunnerSetup struct {
	Runner      Runner
	ManualInput ManualInput
}

// RunnerFactory constructs the provider and cluster adapters for one explicit
// kubeconfig and a validated set of common run options. Provider wrappers may
// add their own manual-input or acknowledgement flags and capture those values
// in this factory; the shared command intentionally does not declare them.
type RunnerFactory func(context.Context, string, RunOptions) (RunnerSetup, error)

type commandOptions struct {
	kubeconfig      string
	outputDir       string
	publicationMode string
	resume          bool
}

// NewCommand returns the provider-neutral signing-key rotation command. It is
// deliberately not registered by this package; provider packages own that
// integration after constructing their concrete adapters. Provider wrappers
// may add provider-owned flags and capture their values in runnerFactory.
func NewCommand(provider Provider, runnerFactory RunnerFactory) *cobra.Command {
	options := commandOptions{
		publicationMode: string(PublicationModeDirect),
	}

	command := &cobra.Command{
		Use:   "rotate-signing-key",
		Short: "Rotate the bound service account signing key",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return options.run(command.Context(), provider, runnerFactory)
		},
	}

	flags := command.Flags()
	flags.StringVar(&options.kubeconfig, "kubeconfig", "", "Absolute path to the kubeconfig file")
	flags.StringVar(&options.outputDir, "output-dir", "", "Directory for public rotation artifacts and checkpoint state")
	flags.StringVar(&options.publicationMode, "publication-mode", string(PublicationModeDirect), "JWKS publication mode: direct or manual")
	flags.BoolVar(&options.resume, "resume", false, "Resume the rotation recorded in the output directory")
	mustMarkRequired(command, "kubeconfig")
	mustMarkRequired(command, "output-dir")

	return command
}

func (o commandOptions) run(ctx context.Context, provider Provider, runnerFactory RunnerFactory) error {
	if strings.TrimSpace(o.kubeconfig) == "" {
		return fmt.Errorf("kubeconfig must not be empty")
	}
	if strings.TrimSpace(o.outputDir) == "" {
		return fmt.Errorf("output directory must not be empty")
	}
	if !isSupportedProvider(provider) {
		return fmt.Errorf("unsupported rotation provider %q", provider)
	}
	publicationMode := PublicationMode(o.publicationMode)
	if !isSupportedPublicationMode(publicationMode) {
		return fmt.Errorf("unsupported rotation publication mode %q", o.publicationMode)
	}
	if runnerFactory == nil {
		return fmt.Errorf("rotation runner factory must not be nil")
	}

	runOptions := RunOptions{
		Provider:        provider,
		PublicationMode: publicationMode,
		OutputDir:       o.outputDir,
		Resume:          o.resume,
	}
	setup, err := runnerFactory(ctx, o.kubeconfig, runOptions)
	if err != nil {
		return fmt.Errorf("construct rotation runner: %w", err)
	}
	if setup.Runner == nil {
		return fmt.Errorf("rotation runner factory returned a nil runner")
	}

	runOptions.Manual = setup.ManualInput
	result, err := setup.Runner.Run(ctx, runOptions)
	if err != nil {
		return err
	}
	if !result.Complete || result.Phase != PhaseComplete {
		return fmt.Errorf("rotation runner returned incomplete result at phase %q", result.Phase)
	}
	return nil
}

func mustMarkRequired(command *cobra.Command, flagName string) {
	if err := command.MarkFlagRequired(flagName); err != nil {
		panic(err)
	}
}
