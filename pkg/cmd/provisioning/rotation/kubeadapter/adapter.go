package kubeadapter

import (
	"context"
	"fmt"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	configclient "github.com/openshift/client-go/config/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/rotation"
)

const (
	cloudCredentialOperatorNamespace = "openshift-cloud-credential-operator"
	kubeAPIServerOperatorNamespace   = "openshift-kube-apiserver-operator"
	kubeAPIServerNamespace           = "openshift-kube-apiserver"

	nextSignerSecretName = "next-bound-service-account-signing-key"
	publicSignerCMName   = "bound-sa-token-signing-certs"

	defaultPollInterval          = 10 * time.Second
	defaultPreflightStablePeriod = 5 * time.Second
	defaultStablePeriod          = 5 * time.Minute
)

var (
	kubeAPIServerGVR = schema.GroupVersionResource{
		Group: "operator.openshift.io", Version: "v1", Resource: "kubeapiservers",
	}
	machineConfigPoolGVR = schema.GroupVersionResource{
		Group: "machineconfiguration.openshift.io", Version: "v1", Resource: "machineconfigpools",
	}
	machineConfigGVR = schema.GroupVersionResource{
		Group: "machineconfiguration.openshift.io", Version: "v1", Resource: "machineconfigs",
	}
)

// Options controls polling and continuous-stability windows. New uses the
// production defaults; NewWithOptions exists so callers can select a stricter
// policy and unit tests can avoid wall-clock waits.
type Options struct {
	PollInterval          time.Duration
	PreflightStablePeriod time.Duration
	StablePeriod          time.Duration
}

// DefaultOptions returns the stability windows used by the documented manual
// rotation procedure.
func DefaultOptions() Options {
	return Options{
		PollInterval:          defaultPollInterval,
		PreflightStablePeriod: defaultPreflightStablePeriod,
		StablePeriod:          defaultStablePeriod,
	}
}

type clusterVersionGetter interface {
	Get(context.Context, string, metav1.GetOptions) (*configv1.ClusterVersion, error)
}

type clusterOperatorLister interface {
	List(context.Context, metav1.ListOptions) (*configv1.ClusterOperatorList, error)
}

type secretMetadataGetter interface {
	Get(context.Context, string, string) (*metav1.PartialObjectMetadata, error)
}

type resourceClient interface {
	Get(context.Context, schema.GroupVersionResource, string, metav1.GetOptions) (*unstructured.Unstructured, error)
	List(context.Context, schema.GroupVersionResource, metav1.ListOptions) (*unstructured.UnstructuredList, error)
	Create(context.Context, schema.GroupVersionResource, *unstructured.Unstructured, metav1.CreateOptions) (*unstructured.Unstructured, error)
	Update(context.Context, schema.GroupVersionResource, *unstructured.Unstructured, metav1.UpdateOptions) (*unstructured.Unstructured, error)
}

type dynamicResourceClient struct {
	client dynamic.Interface
}

func (c dynamicResourceClient) Get(ctx context.Context, resource schema.GroupVersionResource, name string, options metav1.GetOptions) (*unstructured.Unstructured, error) {
	return c.client.Resource(resource).Get(ctx, name, options)
}

func (c dynamicResourceClient) List(ctx context.Context, resource schema.GroupVersionResource, options metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	return c.client.Resource(resource).List(ctx, options)
}

func (c dynamicResourceClient) Create(ctx context.Context, resource schema.GroupVersionResource, object *unstructured.Unstructured, options metav1.CreateOptions) (*unstructured.Unstructured, error) {
	return c.client.Resource(resource).Create(ctx, object, options)
}

func (c dynamicResourceClient) Update(ctx context.Context, resource schema.GroupVersionResource, object *unstructured.Unstructured, options metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	return c.client.Resource(resource).Update(ctx, object, options)
}

// Adapter implements the provider-independent cluster half of signer-key
// rotation. It never reads a signer Secret payload.
type Adapter struct {
	kube             kubernetes.Interface
	clusterVersions  clusterVersionGetter
	clusterOperators clusterOperatorLister
	resources        resourceClient
	secretMetadata   secretMetadataGetter
	options          Options
	now              func() time.Time
}

var _ rotation.ClusterRotation = (*Adapter)(nil)

// New constructs an adapter from one explicit kubeconfig path.
func New(kubeconfig string) (*Adapter, error) {
	return NewWithOptions(kubeconfig, DefaultOptions())
}

// NewWithOptions constructs an adapter with explicit polling and stability
// settings. An empty kubeconfig is rejected; rotation never falls back to an
// ambient or in-cluster identity.
func NewWithOptions(kubeconfig string, options Options) (*Adapter, error) {
	if strings.TrimSpace(kubeconfig) == "" {
		return nil, fmt.Errorf("rotation kubeconfig path must not be empty")
	}
	if options.PollInterval <= 0 {
		return nil, fmt.Errorf("rotation poll interval must be greater than zero")
	}
	if options.PreflightStablePeriod < 0 || options.StablePeriod < 0 {
		return nil, fmt.Errorf("rotation stability periods must not be negative")
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load rotation kubeconfig: %w", err)
	}
	config = rest.CopyConfig(config)
	config.UserAgent = "ccoctl-signer-key-rotation"

	httpClient, err := rest.HTTPClientFor(config)
	if err != nil {
		return nil, fmt.Errorf("build rotation Kubernetes transport: %w", err)
	}
	kube, err := kubernetes.NewForConfigAndClient(config, httpClient)
	if err != nil {
		return nil, fmt.Errorf("build rotation Kubernetes client: %w", err)
	}
	configClient, err := configclient.NewForConfigAndClient(config, httpClient)
	if err != nil {
		return nil, fmt.Errorf("build rotation OpenShift config client: %w", err)
	}
	dynamicClient, err := dynamic.NewForConfigAndClient(config, httpClient)
	if err != nil {
		return nil, fmt.Errorf("build rotation dynamic client: %w", err)
	}

	return newAdapter(
		kube,
		configClient.ConfigV1().ClusterVersions(),
		configClient.ConfigV1().ClusterOperators(),
		dynamicResourceClient{client: dynamicClient},
		&strictSecretMetadataClient{restClient: kube.CoreV1().RESTClient()},
		options,
	), nil
}

func newAdapter(kube kubernetes.Interface, versions clusterVersionGetter, operators clusterOperatorLister, resources resourceClient, metadata secretMetadataGetter, options Options) *Adapter {
	return &Adapter{
		kube:             kube,
		clusterVersions:  versions,
		clusterOperators: operators,
		resources:        resources,
		secretMetadata:   metadata,
		options:          options,
		now:              time.Now,
	}
}

func (a *Adapter) waitUntil(ctx context.Context, condition func(context.Context) (bool, error)) error {
	for {
		done, err := condition(ctx)
		if err != nil {
			return err
		}
		if done {
			return nil
		}

		timer := time.NewTimer(a.options.PollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (a *Adapter) waitForContinuousStability(ctx context.Context, period time.Duration, check func(context.Context) (bool, error)) error {
	var stableSince time.Time
	return a.waitUntil(ctx, func(ctx context.Context) (bool, error) {
		stable, err := check(ctx)
		if err != nil {
			return false, err
		}
		if !stable {
			stableSince = time.Time{}
			return false, nil
		}
		if period == 0 {
			return true, nil
		}
		if stableSince.IsZero() {
			stableSince = a.now()
			return false, nil
		}
		return a.now().Sub(stableSince) >= period, nil
	})
}

func mutationOutcome(err error) rotation.EffectOutcome {
	if err == nil {
		return rotation.EffectSubmitted
	}
	if isDefinitiveMutationRejection(err) {
		return rotation.EffectNotApplied
	}
	return rotation.EffectUnknown
}
