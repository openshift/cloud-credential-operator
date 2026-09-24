package rotation

import (
	"context"
	"errors"
	"io"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

func TestNewCommandPassesValidatedOptionsAndManualInputToRunner(t *testing.T) {
	t.Parallel()

	type contextKey string
	const key contextKey = "command-test"
	ctx := context.WithValue(context.Background(), key, "context-value")

	runner := &commandTestRunner{result: completeCommandRunResult()}
	manualInput := ManualInput{CurrentJWKS: []byte(`{"keys":[]}`)}
	var factoryContext context.Context
	var factoryKubeconfig string
	var factoryOptions RunOptions
	command := NewCommand(ProviderAzure, func(ctx context.Context, kubeconfig string, options RunOptions) (RunnerSetup, error) {
		factoryContext = ctx
		factoryKubeconfig = kubeconfig
		factoryOptions = options
		return RunnerSetup{Runner: runner, ManualInput: manualInput}, nil
	})
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{
		"--kubeconfig", "/tmp/cluster.kubeconfig",
		"--output-dir", "/tmp/rotation-state",
		"--publication-mode", "manual",
		"--resume",
	})

	if err := command.ExecuteContext(ctx); err != nil {
		t.Fatalf("ExecuteContext() returned unexpected error: %v", err)
	}
	if factoryContext != ctx {
		t.Fatal("runner factory did not receive the command context")
	}
	if factoryKubeconfig != "/tmp/cluster.kubeconfig" {
		t.Fatalf("factory kubeconfig = %q, want %q", factoryKubeconfig, "/tmp/cluster.kubeconfig")
	}
	if runner.runContext != ctx {
		t.Fatal("runner did not receive the command context")
	}
	if got := runner.runContext.Value(key); got != "context-value" {
		t.Fatalf("runner context value = %v, want context-value", got)
	}
	wantBaseOptions := RunOptions{
		Provider:        ProviderAzure,
		PublicationMode: PublicationModeManual,
		OutputDir:       "/tmp/rotation-state",
		Resume:          true,
	}
	if !reflect.DeepEqual(factoryOptions, wantBaseOptions) {
		t.Fatalf("factory options = %+v, want %+v", factoryOptions, wantBaseOptions)
	}
	wantRunnerOptions := wantBaseOptions
	wantRunnerOptions.Manual = manualInput
	if !reflect.DeepEqual(runner.options, wantRunnerOptions) {
		t.Fatalf("runner options = %+v, want %+v", runner.options, wantRunnerOptions)
	}
	if runner.calls != 1 {
		t.Fatalf("runner calls = %d, want 1", runner.calls)
	}
}

func TestNewCommandValidatesArgumentsAndCommonFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		provider  Provider
		args      []string
		factory   RunnerFactory
		wantError string
	}{
		{
			name:      "requires kubeconfig",
			provider:  ProviderAWS,
			args:      []string{"--output-dir", "/tmp/output"},
			factory:   successfulCommandRunnerFactory(),
			wantError: "required flag(s) \"kubeconfig\" not set",
		},
		{
			name:      "requires output directory",
			provider:  ProviderAWS,
			args:      []string{"--kubeconfig", "/tmp/kubeconfig"},
			factory:   successfulCommandRunnerFactory(),
			wantError: "required flag(s) \"output-dir\" not set",
		},
		{
			name:      "rejects explicitly empty kubeconfig",
			provider:  ProviderAWS,
			args:      []string{"--kubeconfig=", "--output-dir", "/tmp/output"},
			factory:   successfulCommandRunnerFactory(),
			wantError: "kubeconfig must not be empty",
		},
		{
			name:      "rejects explicitly empty output directory",
			provider:  ProviderAWS,
			args:      []string{"--kubeconfig", "/tmp/kubeconfig", "--output-dir="},
			factory:   successfulCommandRunnerFactory(),
			wantError: "output directory must not be empty",
		},
		{
			name:      "rejects positional arguments",
			provider:  ProviderAWS,
			args:      []string{"--kubeconfig", "/tmp/kubeconfig", "--output-dir", "/tmp/output", "unexpected"},
			factory:   successfulCommandRunnerFactory(),
			wantError: "unknown command \"unexpected\" for \"rotate-signing-key\"",
		},
		{
			name:      "rejects unsupported publication mode",
			provider:  ProviderAWS,
			args:      []string{"--kubeconfig", "/tmp/kubeconfig", "--output-dir", "/tmp/output", "--publication-mode", "automatic"},
			factory:   successfulCommandRunnerFactory(),
			wantError: "unsupported rotation publication mode \"automatic\"",
		},
		{
			name:      "rejects unsupported provider",
			provider:  Provider("unsupported"),
			args:      []string{"--kubeconfig", "/tmp/kubeconfig", "--output-dir", "/tmp/output"},
			factory:   successfulCommandRunnerFactory(),
			wantError: "unsupported rotation provider \"unsupported\"",
		},
		{
			name:      "rejects nil runner factory",
			provider:  ProviderAWS,
			args:      []string{"--kubeconfig", "/tmp/kubeconfig", "--output-dir", "/tmp/output"},
			wantError: "rotation runner factory must not be nil",
		},
		{
			name:     "rejects nil runner",
			provider: ProviderAWS,
			args:     []string{"--kubeconfig", "/tmp/kubeconfig", "--output-dir", "/tmp/output"},
			factory: func(context.Context, string, RunOptions) (RunnerSetup, error) {
				return RunnerSetup{}, nil
			},
			wantError: "rotation runner factory returned a nil runner",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			command := NewCommand(test.provider, test.factory)
			command.SilenceErrors = true
			command.SilenceUsage = true
			command.SetOut(io.Discard)
			command.SetErr(io.Discard)
			command.SetArgs(test.args)

			err := command.Execute()
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Execute() error = %v, want error containing %q", err, test.wantError)
			}
		})
	}
}

func TestNewCommandHasOnlyCommonFlagsAndIndependentDefaults(t *testing.T) {
	t.Parallel()

	firstRunner := &commandTestRunner{result: completeCommandRunResult()}
	first := NewCommand(ProviderGCP, func(context.Context, string, RunOptions) (RunnerSetup, error) {
		return RunnerSetup{Runner: firstRunner}, nil
	})
	first.SetOut(io.Discard)
	first.SetErr(io.Discard)
	first.SetArgs([]string{
		"--kubeconfig", "/tmp/first-kubeconfig",
		"--output-dir", "/tmp/first-output",
		"--publication-mode", "manual",
		"--resume",
	})
	if err := first.Execute(); err != nil {
		t.Fatalf("first Execute() returned unexpected error: %v", err)
	}

	secondRunner := &commandTestRunner{result: completeCommandRunResult()}
	second := NewCommand(ProviderGCP, func(context.Context, string, RunOptions) (RunnerSetup, error) {
		return RunnerSetup{Runner: secondRunner}, nil
	})
	second.SetOut(io.Discard)
	second.SetErr(io.Discard)
	second.SetArgs([]string{
		"--kubeconfig", "/tmp/second-kubeconfig",
		"--output-dir", "/tmp/second-output",
	})
	if err := second.Execute(); err != nil {
		t.Fatalf("second Execute() returned unexpected error: %v", err)
	}

	if secondRunner.options.PublicationMode != PublicationModeDirect {
		t.Fatalf("second command publication mode = %q, want default %q", secondRunner.options.PublicationMode, PublicationModeDirect)
	}
	if secondRunner.options.Resume {
		t.Fatal("second command inherited resume from the first command")
	}

	var flagNames []string
	second.LocalNonPersistentFlags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "help" {
			return
		}
		flagNames = append(flagNames, flag.Name)
	})
	sort.Strings(flagNames)
	wantFlagNames := []string{"kubeconfig", "output-dir", "publication-mode", "resume"}
	if !reflect.DeepEqual(flagNames, wantFlagNames) {
		t.Fatalf("local flags = %v, want %v", flagNames, wantFlagNames)
	}
}

func TestNewCommandPropagatesFactoryAndRunnerErrors(t *testing.T) {
	t.Parallel()

	factoryError := errors.New("factory failed")
	factoryCommand := NewCommand(ProviderAWS, func(context.Context, string, RunOptions) (RunnerSetup, error) {
		return RunnerSetup{}, factoryError
	})
	factoryCommand.SilenceErrors = true
	factoryCommand.SilenceUsage = true
	factoryCommand.SetArgs([]string{"--kubeconfig", "/tmp/kubeconfig", "--output-dir", "/tmp/output"})
	if err := factoryCommand.Execute(); !errors.Is(err, factoryError) {
		t.Fatalf("factory command error = %v, want %v", err, factoryError)
	}

	runnerError := errors.New("runner failed")
	runnerCommand := NewCommand(ProviderAWS, func(context.Context, string, RunOptions) (RunnerSetup, error) {
		return RunnerSetup{Runner: &commandTestRunner{err: runnerError}}, nil
	})
	runnerCommand.SilenceErrors = true
	runnerCommand.SilenceUsage = true
	runnerCommand.SetArgs([]string{"--kubeconfig", "/tmp/kubeconfig", "--output-dir", "/tmp/output"})
	if err := runnerCommand.Execute(); !errors.Is(err, runnerError) {
		t.Fatalf("runner command error = %v, want %v", err, runnerError)
	}
}

func TestNewCommandRejectsIncompleteRunnerResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		result RunResult
	}{
		{
			name:   "incomplete flag at complete phase",
			result: RunResult{Phase: PhaseComplete, Complete: false},
		},
		{
			name:   "complete flag before complete phase",
			result: RunResult{Phase: PhasePostRebootStable, Complete: true},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			command := NewCommand(ProviderAWS, func(context.Context, string, RunOptions) (RunnerSetup, error) {
				return RunnerSetup{Runner: &commandTestRunner{result: test.result}}, nil
			})
			command.SilenceErrors = true
			command.SilenceUsage = true
			command.SetArgs([]string{"--kubeconfig", "/tmp/kubeconfig", "--output-dir", "/tmp/output"})

			err := command.Execute()
			if err == nil || !strings.Contains(err.Error(), "rotation runner returned incomplete result") {
				t.Fatalf("Execute() error = %v, want incomplete-result error", err)
			}
		})
	}
}

type commandTestRunner struct {
	runContext context.Context
	options    RunOptions
	calls      int
	result     RunResult
	err        error
}

func (r *commandTestRunner) Run(ctx context.Context, options RunOptions) (RunResult, error) {
	r.runContext = ctx
	r.options = options
	r.calls++
	return r.result, r.err
}

func successfulCommandRunnerFactory() RunnerFactory {
	return func(context.Context, string, RunOptions) (RunnerSetup, error) {
		return RunnerSetup{Runner: &commandTestRunner{result: completeCommandRunResult()}}, nil
	}
}

func completeCommandRunResult() RunResult {
	return RunResult{Phase: PhaseComplete, Complete: true}
}
