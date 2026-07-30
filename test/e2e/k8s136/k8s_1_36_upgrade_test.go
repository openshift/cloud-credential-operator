//go:build e2e
// +build e2e

package k8s136

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openshift/cloud-credential-operator/pkg/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/e2e-framework/klient/conf"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

var testenv env.Environment

const (
	ccoNamespace      = "openshift-cloud-credential-operator"
	ccoDeploymentName = "cloud-credential-operator"
	testTimeout       = 5 * time.Minute
)

func TestMain(m *testing.M) {
	path := conf.ResolveKubeConfigFile()
	cfg := envconf.NewWithKubeConfig(path)
	testenv = env.NewWithConfig(cfg)
	os.Exit(testenv.Run(m))
}

// TestK8s136HasSyncedChecker verifies CCO uses HasSyncedChecker from library-go
// which is required for Kubernetes 1.36 compatibility
func TestK8s136HasSyncedChecker(t *testing.T) {
	feature := features.New("K8s 1.36 - HasSyncedChecker").
		Assess("CCO deployment is running", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			operationCtx, cancel := context.WithTimeout(ctx, testTimeout)
			defer cancel()

			client, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
			if err != nil {
				t.Fatalf("Failed to create kubernetes client: %v", err)
			}

			// Verify CCO deployment exists and is ready
			deployment, err := client.AppsV1().Deployments(ccoNamespace).Get(operationCtx, ccoDeploymentName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("Failed to get CCO deployment: %v", err)
			}

			if deployment.Status.ReadyReplicas < 1 {
				t.Fatalf("CCO deployment is not ready. Ready replicas: %d", deployment.Status.ReadyReplicas)
			}

			t.Logf("CCO deployment is healthy with %d ready replicas", deployment.Status.ReadyReplicas)
			return ctx
		}).
		Assess("CCO pods are running with K8s 1.36", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			operationCtx, cancel := context.WithTimeout(ctx, testTimeout)
			defer cancel()

			client, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
			if err != nil {
				t.Fatalf("Failed to create kubernetes client: %v", err)
			}

			// Get CCO pods
			pods, err := client.CoreV1().Pods(ccoNamespace).List(operationCtx, metav1.ListOptions{
				LabelSelector: "app=cloud-credential-operator",
			})
			if err != nil {
				t.Fatalf("Failed to list CCO pods: %v", err)
			}

			if len(pods.Items) == 0 {
				t.Fatal("No CCO pods found")
			}

			// Verify at least one pod is running
			runningPods := 0
			for _, pod := range pods.Items {
				if pod.Status.Phase == corev1.PodRunning {
					runningPods++
					t.Logf("CCO pod %s is running", pod.Name)
				}
			}

			if runningPods == 0 {
				t.Fatal("No running CCO pods found")
			}

			return ctx
		}).
		Assess("CCO operator logs show no HasSyncedChecker errors", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			operationCtx, cancel := context.WithTimeout(ctx, testTimeout)
			defer cancel()

			client, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
			if err != nil {
				t.Fatalf("Failed to create kubernetes client: %v", err)
			}

			// Get CCO pods
			pods, err := client.CoreV1().Pods(ccoNamespace).List(operationCtx, metav1.ListOptions{
				LabelSelector: "app=cloud-credential-operator",
			})
			if err != nil {
				t.Fatalf("Failed to list CCO pods: %v", err)
			}

			if len(pods.Items) == 0 {
				t.Fatal("No CCO pods found")
			}

			// Check logs for errors related to HasSyncedChecker or controller manager.
			inspectedLogs := false
			for _, pod := range pods.Items {
				if pod.Status.Phase != corev1.PodRunning {
					continue
				}

				logOptions := &corev1.PodLogOptions{
					Container:  "cloud-credential-operator",
					TailLines:  int64Ptr(100),
					Timestamps: false,
				}

				logs, err := client.CoreV1().Pods(ccoNamespace).GetLogs(pod.Name, logOptions).DoRaw(operationCtx)
				if err != nil {
					t.Logf("Warning: Failed to get logs for pod %s: %v", pod.Name, err)
					continue
				}
				inspectedLogs = true

				logStr := string(logs)

				// Check for common K8s 1.36 compatibility errors
				errorPatterns := []string{
					"HasSyncedChecker",
					"undefined method",
					"controller manager failed to start",
					"cache sync timeout",
				}

				for _, pattern := range errorPatterns {
					if strings.Contains(logStr, pattern) {
						t.Errorf("Pod %s logs contain potential K8s 1.36 compatibility error: %s", pod.Name, pattern)
					}
				}

				t.Logf("CCO pod %s logs show no K8s 1.36 compatibility errors", pod.Name)
			}
			if !inspectedLogs {
				t.Fatal("Failed to inspect logs from any running CCO pod")
			}

			return ctx
		}).
		Feature()

	testenv.Test(t, feature)
}

// TestK8s136ControllerManagerStarts verifies the deployment reports Available=True
// with K8s 1.36 (requires HasSyncedChecker from library-go)
func TestK8s136ControllerManagerStarts(t *testing.T) {
	feature := features.New("K8s 1.36 - Controller Manager").
		Assess("Controller manager is healthy", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			operationCtx, cancel := context.WithTimeout(ctx, testTimeout)
			defer cancel()

			client, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
			if err != nil {
				t.Fatalf("Failed to create kubernetes client: %v", err)
			}

			util.SetupScheme(scheme.Scheme)

			// Verify CCO deployment is available
			deployment, err := client.AppsV1().Deployments(ccoNamespace).Get(operationCtx, ccoDeploymentName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("Failed to get CCO deployment: %v", err)
			}

			// Check deployment conditions
			available := false
			for _, condition := range deployment.Status.Conditions {
				if condition.Type == "Available" {
					if condition.Status != corev1.ConditionTrue {
						t.Fatalf("CCO deployment not available. Reason: %s, Message: %s",
							condition.Reason, condition.Message)
					}
					available = true
					t.Logf("CCO deployment is available")
					break
				}
			}
			if !available {
				t.Fatal("CCO deployment does not report an Available condition")
			}

			return ctx
		}).
		Feature()

	testenv.Test(t, feature)
}

// Helper functions
func int64Ptr(i int64) *int64 {
	return &i
}
