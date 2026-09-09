package kubeadapter

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type staticClusterVersionGetter struct {
	version *configv1.ClusterVersion
	err     error
}

func (s staticClusterVersionGetter) Get(context.Context, string, metav1.GetOptions) (*configv1.ClusterVersion, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.version.DeepCopy(), nil
}

type staticClusterOperatorLister struct {
	operators *configv1.ClusterOperatorList
	err       error
}

func (s staticClusterOperatorLister) List(context.Context, metav1.ListOptions) (*configv1.ClusterOperatorList, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.operators.DeepCopy(), nil
}

type staticSecretMetadataGetter struct {
	metadata *metav1.PartialObjectMetadata
	err      error
}

func (s staticSecretMetadataGetter) Get(context.Context, string, string) (*metav1.PartialObjectMetadata, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.metadata.DeepCopy(), nil
}

type memoryResourceClient struct {
	mu sync.Mutex

	objects             map[schema.GroupVersionResource]map[string]*unstructured.Unstructured
	failCreateOnce      map[string]error
	createCalls         map[string]int
	updateCalls         map[string]int
	beforeCreate        func(schema.GroupVersionResource, *unstructured.Unstructured) error
	nextResourceVersion int
}

func newMemoryResourceClient(objects ...*unstructured.Unstructured) *memoryResourceClient {
	client := &memoryResourceClient{
		objects:             map[schema.GroupVersionResource]map[string]*unstructured.Unstructured{},
		failCreateOnce:      map[string]error{},
		createCalls:         map[string]int{},
		updateCalls:         map[string]int{},
		nextResourceVersion: 1,
	}
	for _, object := range objects {
		client.putLocked(gvrForObject(object), object)
	}
	return client
}

func (c *memoryResourceClient) Get(_ context.Context, resource schema.GroupVersionResource, name string, _ metav1.GetOptions) (*unstructured.Unstructured, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	object := c.objects[resource][name]
	if object == nil {
		return nil, apierrors.NewNotFound(resource.GroupResource(), name)
	}
	return object.DeepCopy(), nil
}

func (c *memoryResourceClient) List(_ context.Context, resource schema.GroupVersionResource, _ metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	list := &unstructured.UnstructuredList{}
	names := make([]string, 0, len(c.objects[resource]))
	for name := range c.objects[resource] {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		list.Items = append(list.Items, *c.objects[resource][name].DeepCopy())
	}
	return list, nil
}

func (c *memoryResourceClient) Create(_ context.Context, resource schema.GroupVersionResource, object *unstructured.Unstructured, _ metav1.CreateOptions) (*unstructured.Unstructured, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := resource.String() + "/" + object.GetName()
	c.createCalls[key]++
	if c.beforeCreate != nil {
		if err := c.beforeCreate(resource, object.DeepCopy()); err != nil {
			return nil, err
		}
	}
	if err := c.failCreateOnce[key]; err != nil {
		delete(c.failCreateOnce, key)
		return nil, err
	}
	if c.objects[resource][object.GetName()] != nil {
		return nil, apierrors.NewAlreadyExists(resource.GroupResource(), object.GetName())
	}
	created := object.DeepCopy()
	created.SetResourceVersion(fmt.Sprintf("%d", c.nextResourceVersion))
	c.nextResourceVersion++
	c.putLocked(resource, created)
	return created.DeepCopy(), nil
}

func (c *memoryResourceClient) Update(_ context.Context, resource schema.GroupVersionResource, object *unstructured.Unstructured, _ metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := resource.String() + "/" + object.GetName()
	c.updateCalls[key]++
	current := c.objects[resource][object.GetName()]
	if current == nil {
		return nil, apierrors.NewNotFound(resource.GroupResource(), object.GetName())
	}
	if object.GetResourceVersion() != current.GetResourceVersion() {
		return nil, apierrors.NewConflict(resource.GroupResource(), object.GetName(), fmt.Errorf("resourceVersion changed"))
	}
	updated := object.DeepCopy()
	updated.SetResourceVersion(fmt.Sprintf("%d", c.nextResourceVersion))
	c.nextResourceVersion++
	c.putLocked(resource, updated)
	return updated.DeepCopy(), nil
}

func (c *memoryResourceClient) put(resource schema.GroupVersionResource, object *unstructured.Unstructured) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.putLocked(resource, object)
}

func (c *memoryResourceClient) putLocked(resource schema.GroupVersionResource, object *unstructured.Unstructured) {
	if c.objects[resource] == nil {
		c.objects[resource] = map[string]*unstructured.Unstructured{}
	}
	copy := object.DeepCopy()
	if copy.GetResourceVersion() == "" {
		copy.SetResourceVersion(fmt.Sprintf("%d", c.nextResourceVersion))
		c.nextResourceVersion++
	}
	c.objects[resource][copy.GetName()] = copy
}

func (c *memoryResourceClient) actionCount(resource schema.GroupVersionResource, name string) (creates, updates int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := resource.String() + "/" + name
	return c.createCalls[key], c.updateCalls[key]
}

func gvrForObject(object *unstructured.Unstructured) schema.GroupVersionResource {
	switch object.GetKind() {
	case "MachineConfigPool":
		return machineConfigPoolGVR
	case "MachineConfig":
		return machineConfigGVR
	case "KubeAPIServer":
		return kubeAPIServerGVR
	default:
		panic(fmt.Sprintf("unsupported test object kind %q", object.GetKind()))
	}
}

func testOptions() Options {
	return Options{PollInterval: time.Millisecond, PreflightStablePeriod: 0, StablePeriod: 0}
}

func stableClusterOperators() *configv1.ClusterOperatorList {
	return &configv1.ClusterOperatorList{Items: []configv1.ClusterOperator{{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-apiserver"},
		Status: configv1.ClusterOperatorStatus{Conditions: []configv1.ClusterOperatorStatusCondition{
			{Type: configv1.OperatorAvailable, Status: configv1.ConditionTrue},
			{Type: configv1.OperatorProgressing, Status: configv1.ConditionFalse},
			{Type: configv1.OperatorDegraded, Status: configv1.ConditionFalse},
		}},
	}}}
}

func stableMachineConfigPool(name string, machineCount int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "machineconfiguration.openshift.io/v1",
		"kind":       "MachineConfigPool",
		"metadata": map[string]any{
			"name":       name,
			"generation": int64(2),
		},
		"spec": map[string]any{
			"paused": false,
			"nodeSelector": map[string]any{
				"matchLabels": map[string]any{"node-role.kubernetes.io/" + name: ""},
			},
			"machineConfigSelector": map[string]any{
				"matchLabels": map[string]any{"machineconfiguration.openshift.io/role": name},
			},
			"configuration": map[string]any{"name": "rendered-" + name + "-old"},
		},
		"status": map[string]any{
			"observedGeneration":      int64(2),
			"configuration":           map[string]any{"name": "rendered-" + name + "-old"},
			"machineCount":            machineCount,
			"updatedMachineCount":     machineCount,
			"readyMachineCount":       machineCount,
			"unavailableMachineCount": int64(0),
			"degradedMachineCount":    int64(0),
			"conditions": []any{
				map[string]any{"type": "Updated", "status": "True"},
				map[string]any{"type": "Updating", "status": "False"},
				map[string]any{"type": "Degraded", "status": "False"},
			},
		},
	}}
}

func testNodeRole(name string) string {
	if strings.HasPrefix(name, "master") {
		return "master"
	}
	return "worker"
}

func testKubeAPIServer(revisions ...int64) *unstructured.Unstructured {
	statuses := make([]any, 0, len(revisions))
	for index, revision := range revisions {
		statuses = append(statuses, map[string]any{"nodeName": fmt.Sprintf("master-%d", index), "currentRevision": revision})
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "operator.openshift.io/v1",
		"kind":       "KubeAPIServer",
		"metadata":   map[string]any{"name": "cluster"},
		"status":     map[string]any{"nodeStatuses": statuses},
	}}
}
