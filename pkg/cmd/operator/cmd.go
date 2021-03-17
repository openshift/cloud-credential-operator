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

package cmd

import (
	"context"
	"flag"
	golog "log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	minterv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	controller "github.com/openshift/cloud-credential-operator/pkg/operator"
	"github.com/openshift/cloud-credential-operator/pkg/util"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/runtime/signals"
)

const (
	defaultLogLevel         = "info"
	leaderElectionConfigMap = "cloud-credential-operator-leader"
)

type ControllerManagerOptions struct {
	LogLevel string
}

func NewOperator() *cobra.Command {
	opts := &ControllerManagerOptions{}
	cmd := &cobra.Command{
		Use:   "operator",
		Short: "Run cloud credential operator",
		Run: func(cmd *cobra.Command, args []string) {
			// Set log level
			level, err := log.ParseLevel(opts.LogLevel)
			if err != nil {
				log.WithError(err).Fatal("Cannot parse log level")
			}
			log.SetLevel(level)
			log.Debug("debug logging enabled")

			// Get a config to talk to the apiserver
			log.Info("setting up client for manager")
			cfg, err := config.GetConfig()
			if err != nil {
				log.WithError(err).Fatal("unable to set up client config")
			}

			run := func(ctx context.Context) {
				// Create a new Cmd to provide shared dependencies and start components
				log.Info("setting up manager")
				mgr, err := manager.New(cfg, manager.Options{
					MetricsBindAddress: ":2112",
				})
				if err != nil {
					log.WithError(err).Fatal("unable to set up overall controller manager")
				}

				log.Info("registering components")

				// Setup Scheme for all resources
				util.SetupScheme(mgr.GetScheme())

				// Setup all Controllers
				log.Info("setting up controller")
				kubeconfigCommandLinePath := cmd.PersistentFlags().Lookup("kubeconfig").Value.String()
				if err := controller.AddToManager(mgr, kubeconfigCommandLinePath); err != nil {
					log.WithError(err).Fatal("unable to register controllers to the manager")
				}

				// Start the Cmd
				log.Info("starting the cmd")
				if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
					log.WithError(err).Fatal("unable to run the manager")
				}
			}

			// Leader election code based on:
			// https://github.com/kubernetes/kubernetes/blob/f7e3bcdec2e090b7361a61e21c20b3dbbb41b7f0/staging/src/k8s.io/client-go/examples/leader-election/main.go#L92-L154
			// This gives us ReleaseOnCancel which is not presently exposed in controller-runtime.

			// use a Go context so we can tell the leaderelection code when we want to step down
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// listen for interrupts or the Linux SIGTERM signal and cancel
			// our context, which the leader election code will observe and
			// step down
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
			go func() {
				<-ch
				log.Info("received termination, signaling shutdown")
				cancel()
			}()

			id := uuid.New().String()
			leLog := log.WithField("id", id)
			leLog.Info("generated leader election ID")

			lock := &resourcelock.ConfigMapLock{
				ConfigMapMeta: metav1.ObjectMeta{
					Namespace: minterv1.CloudCredOperatorNamespace,
					Name:      leaderElectionConfigMap,
				},
				Client: kubernetes.NewForConfigOrDie(cfg).CoreV1(),
				LockConfig: resourcelock.ResourceLockConfig{
					Identity: id,
				},
			}

			if os.Getenv("CCO_SKIP_LEADER_ELECTION") != "" {
				run(ctx)
			} else {
				// start the leader election code loop
				leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
					Lock:            lock,
					ReleaseOnCancel: true,
					LeaseDuration:   360 * time.Second,
					RenewDeadline:   270 * time.Second,
					RetryPeriod:     90 * time.Second,
					Callbacks: leaderelection.LeaderCallbacks{
						OnStartedLeading: func(ctx context.Context) {
							run(ctx)
						},
						OnStoppedLeading: func() {
							// we can do cleanup here if necessary
							leLog.Infof("leader lost")
							cancel()
						},
						OnNewLeader: func(identity string) {
							if identity == id {
								// We just became the leader
								leLog.Info("became leader")
								return
							}
							log.Infof("current leader: %s", identity)
						},
					},
				})
			}
		},
	}

	cmd.PersistentFlags().StringVar(&opts.LogLevel, "log-level", defaultLogLevel, "Log level (debug,info,warn,error,fatal)")
	cmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)
	initializeGlog(cmd.PersistentFlags())
	flag.CommandLine.Parse([]string{})

	return cmd
}

func initializeGlog(flags *pflag.FlagSet) {
	golog.SetOutput(glogWriter{}) // Redirect all regular go log output to glog
	golog.SetFlags(0)
	go wait.Forever(glog.Flush, 5*time.Second) // Periodically flush logs
	f := flags.Lookup("logtostderr")           // Default to logging to stderr
	if f != nil {
		f.Value.Set("true")
	}
}

type glogWriter struct{}

func (writer glogWriter) Write(data []byte) (n int, err error) {
	glog.Info(string(data))
	return len(data), nil
}
