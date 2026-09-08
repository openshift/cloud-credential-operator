package kubeadapter

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/rotation"
)

type requiredAccess struct {
	verb      string
	group     string
	resource  string
	namespace string
	name      string
}

var preflightAccess = []requiredAccess{
	{verb: "get", group: "config.openshift.io", resource: "clusterversions", name: "version"},
	{verb: "list", group: "config.openshift.io", resource: "clusteroperators"},
	{verb: "get", group: "", resource: "namespaces", name: cloudCredentialOperatorNamespace},
	{verb: "get", group: "", resource: "secrets", namespace: kubeAPIServerOperatorNamespace, name: nextSignerSecretName},
	{verb: "delete", group: "", resource: "secrets", namespace: kubeAPIServerOperatorNamespace, name: nextSignerSecretName},
	{verb: "get", group: "", resource: "configmaps", namespace: kubeAPIServerNamespace, name: publicSignerCMName},
	// Revision ConfigMap names are discovered only after the kube-apiserver
	// operator rolls out a new revision, so this access cannot be name-scoped.
	{verb: "get", group: "", resource: "configmaps", namespace: kubeAPIServerNamespace},
	{verb: "get", group: "", resource: "configmaps", namespace: cloudCredentialOperatorNamespace},
	{verb: "create", group: "", resource: "configmaps", namespace: cloudCredentialOperatorNamespace},
	{verb: "update", group: "", resource: "configmaps", namespace: cloudCredentialOperatorNamespace},
	{verb: "get", group: "", resource: "nodes"},
	{verb: "list", group: "", resource: "nodes"},
	{verb: "get", group: "operator.openshift.io", resource: "kubeapiservers", name: "cluster"},
	{verb: "get", group: "machineconfiguration.openshift.io", resource: "machineconfigpools"},
	{verb: "list", group: "machineconfiguration.openshift.io", resource: "machineconfigpools"},
	{verb: "get", group: "machineconfiguration.openshift.io", resource: "machineconfigs"},
	{verb: "create", group: "machineconfiguration.openshift.io", resource: "machineconfigs"},
	{verb: "update", group: "machineconfiguration.openshift.io", resource: "machineconfigs"},
}

func (a *Adapter) Preflight(ctx context.Context) (rotation.ClusterPreflight, error) {
	if err := a.validateClients(); err != nil {
		return rotation.ClusterPreflight{}, err
	}
	for _, access := range preflightAccess {
		if err := a.requireAccess(ctx, access); err != nil {
			return rotation.ClusterPreflight{}, err
		}
	}
	if _, err := a.kube.CoreV1().Namespaces().Get(ctx, cloudCredentialOperatorNamespace, metav1.GetOptions{}); err != nil {
		return rotation.ClusterPreflight{}, fmt.Errorf("read rotation guard namespace: %w", err)
	}

	clusterIdentity, err := a.clusterIdentity(ctx)
	if err != nil {
		return rotation.ClusterPreflight{}, err
	}
	metadata, err := a.secretMetadata.Get(ctx, kubeAPIServerOperatorNamespace, nextSignerSecretName)
	if err != nil {
		return rotation.ClusterPreflight{}, fmt.Errorf("verify strict signer Secret metadata access: %w", err)
	}
	if metadata.UID == "" || metadata.ResourceVersion == "" {
		return rotation.ClusterPreflight{}, fmt.Errorf("next signer Secret metadata is missing UID or resourceVersion")
	}
	if _, err := a.ObservePublicSignerBundle(ctx, nil); err != nil {
		return rotation.ClusterPreflight{}, fmt.Errorf("verify public signer ConfigMap access: %w", err)
	}
	if _, err := a.resources.Get(ctx, kubeAPIServerGVR, "cluster", metav1.GetOptions{}); err != nil {
		return rotation.ClusterPreflight{}, fmt.Errorf("read kube-apiserver operator status: %w", err)
	}

	err = a.waitForContinuousStability(ctx, a.options.PreflightStablePeriod, func(ctx context.Context) (bool, error) {
		operatorsStable, err := a.clusterOperatorsStable(ctx)
		if err != nil || !operatorsStable {
			return false, err
		}
		return a.allMachineConfigPoolsStable(ctx)
	})
	if err != nil {
		return rotation.ClusterPreflight{}, fmt.Errorf("wait for stable cluster preflight: %w", err)
	}
	if _, err := a.prepareRebootPlan(ctx); err != nil {
		return rotation.ClusterPreflight{}, fmt.Errorf("validate node reboot topology during preflight: %w", err)
	}
	return rotation.ClusterPreflight{ClusterIdentity: clusterIdentity}, nil
}

func (a *Adapter) Reconcile(ctx context.Context, guard rotation.RotationGuardReference, expectation rotation.ClusterExpectation) error {
	if err := a.requireGuardHeld(ctx, guard); err != nil {
		return err
	}
	identity, err := a.clusterIdentity(ctx)
	if err != nil {
		return err
	}
	if identity != expectation.ClusterIdentity {
		return fmt.Errorf("cluster identity %q does not match checkpoint identity %q", identity, expectation.ClusterIdentity)
	}
	if expectation.RotationGuard != guard {
		return fmt.Errorf("cluster expectation contains a different signer-rotation guard")
	}
	if expectation.Phase == rotation.PhaseSignerRolloutStable {
		if expectation.ReplacementSigner == nil {
			return fmt.Errorf("signer-rollout checkpoint is missing replacement signer evidence")
		}
		stable, err := a.signerRolloutStable(ctx, expectation.ReplacementSigner.Entry.KeyID)
		if err != nil {
			return fmt.Errorf("reconcile signer rollout stability: %w", err)
		}
		if !stable {
			return fmt.Errorf("checkpoint records signer rollout stability but the cluster is not currently stable")
		}
	}

	if expectation.RebootIntent != nil {
		observation, err := a.ObserveReboot(ctx, guard, expectation.RebootIntent.ID)
		if err != nil {
			return err
		}
		if observation.CanonicalIntent != nil && !reflect.DeepEqual(*observation.CanonicalIntent, *expectation.RebootIntent) {
			return fmt.Errorf("cluster-canonical reboot intent differs from checkpoint intent")
		}
		if phaseAtLeast(expectation.Phase, rotation.PhaseNodesRebooted) && observation.Status != rotation.RebootComplete {
			return fmt.Errorf("checkpoint records reboot completion but cluster observes %q", observation.Status)
		}
	}

	if phaseAtLeast(expectation.Phase, rotation.PhasePostRebootStable) {
		if expectation.RebootIntent == nil {
			return fmt.Errorf("post-reboot checkpoint is missing a reboot intent")
		}
		stable, err := a.postRebootStateStable(ctx, guard, *expectation.RebootIntent)
		if err != nil {
			return err
		}
		if !stable {
			return fmt.Errorf("checkpoint records post-reboot stability but the cluster is not currently stable")
		}
	}
	return nil
}

func (a *Adapter) validateClients() error {
	if a == nil || a.kube == nil || a.clusterVersions == nil || a.clusterOperators == nil || a.resources == nil || a.secretMetadata == nil {
		return fmt.Errorf("rotation Kubernetes adapter is not fully configured")
	}
	if a.options.PollInterval <= 0 || a.options.PreflightStablePeriod < 0 || a.options.StablePeriod < 0 {
		return fmt.Errorf("rotation Kubernetes adapter has invalid polling options")
	}
	if a.now == nil {
		return fmt.Errorf("rotation Kubernetes adapter clock is not configured")
	}
	return nil
}

func (a *Adapter) requireAccess(ctx context.Context, access requiredAccess) error {
	review, err := a.kube.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: access.namespace,
				Verb:      access.verb,
				Group:     access.group,
				Resource:  access.resource,
				Name:      access.name,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("check %s access to %s/%s: %w", access.verb, access.group, access.resource, err)
	}
	if review.Status.EvaluationError != "" {
		return fmt.Errorf("check %s access to %s/%s: %s", access.verb, access.group, access.resource, review.Status.EvaluationError)
	}
	if !review.Status.Allowed {
		reason := strings.TrimSpace(review.Status.Reason)
		if reason == "" {
			reason = "access denied"
		}
		return fmt.Errorf("required %s access to %s/%s is not allowed: %s", access.verb, access.group, access.resource, reason)
	}
	return nil
}

func (a *Adapter) clusterIdentity(ctx context.Context) (string, error) {
	version, err := a.clusterVersions.Get(ctx, "version", metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("read cluster identity: %w", err)
	}
	identity := string(version.Spec.ClusterID)
	if strings.TrimSpace(identity) == "" || strings.TrimSpace(identity) != identity {
		return "", fmt.Errorf("ClusterVersion/version has an invalid empty cluster ID")
	}
	return identity, nil
}

func (a *Adapter) clusterOperatorsStable(ctx context.Context) (bool, error) {
	operators, err := a.clusterOperators.List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("list ClusterOperators: %w", err)
	}
	if len(operators.Items) == 0 {
		return false, nil
	}
	for i := range operators.Items {
		operator := &operators.Items[i]
		if clusterOperatorCondition(operator.Status.Conditions, configv1.OperatorAvailable) != configv1.ConditionTrue ||
			clusterOperatorCondition(operator.Status.Conditions, configv1.OperatorProgressing) != configv1.ConditionFalse ||
			clusterOperatorCondition(operator.Status.Conditions, configv1.OperatorDegraded) != configv1.ConditionFalse {
			return false, nil
		}
	}
	return true, nil
}

func clusterOperatorCondition(conditions []configv1.ClusterOperatorStatusCondition, conditionType configv1.ClusterStatusConditionType) configv1.ConditionStatus {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return condition.Status
		}
	}
	return configv1.ConditionUnknown
}

func (a *Adapter) allMachineConfigPoolsStable(ctx context.Context) (bool, error) {
	pools, err := a.resources.List(ctx, machineConfigPoolGVR, metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("list MachineConfigPools: %w", err)
	}
	if len(pools.Items) == 0 {
		return false, nil
	}
	for i := range pools.Items {
		stable, err := machineConfigPoolStable(&pools.Items[i])
		if err != nil {
			return false, err
		}
		if !stable {
			return false, nil
		}
	}
	return true, nil
}

func machineConfigPoolStable(pool *unstructured.Unstructured) (bool, error) {
	if pool == nil || pool.GetName() == "" {
		return false, fmt.Errorf("MachineConfigPool has no name")
	}
	paused, found, err := unstructured.NestedBool(pool.Object, "spec", "paused")
	if err != nil {
		return false, fmt.Errorf("read MachineConfigPool %q paused state: %w", pool.GetName(), err)
	}
	if found && paused {
		return false, nil
	}
	observedGeneration, found, err := unstructured.NestedInt64(pool.Object, "status", "observedGeneration")
	if err != nil || !found {
		return false, nil
	}
	if observedGeneration != pool.GetGeneration() {
		return false, nil
	}
	specConfiguration, _, _ := unstructured.NestedString(pool.Object, "spec", "configuration", "name")
	statusConfiguration, _, _ := unstructured.NestedString(pool.Object, "status", "configuration", "name")
	if specConfiguration == "" || specConfiguration != statusConfiguration {
		return false, nil
	}

	machineCount, ok := nestedInteger(pool, "status", "machineCount")
	if !ok {
		return false, nil
	}
	updatedCount, ok := nestedInteger(pool, "status", "updatedMachineCount")
	if !ok {
		return false, nil
	}
	readyCount, ok := nestedInteger(pool, "status", "readyMachineCount")
	if !ok {
		return false, nil
	}
	unavailableCount, ok := nestedInteger(pool, "status", "unavailableMachineCount")
	if !ok {
		return false, nil
	}
	degradedCount, ok := nestedInteger(pool, "status", "degradedMachineCount")
	if !ok {
		return false, nil
	}
	if updatedCount != machineCount || readyCount != machineCount || unavailableCount != 0 || degradedCount != 0 {
		return false, nil
	}
	conditions, found, err := unstructuredSlice(pool, "status", "conditions")
	if err != nil || !found {
		return false, err
	}
	if conditionStatus(conditions, "Updated") != string(corev1.ConditionTrue) ||
		conditionStatus(conditions, "Updating") != string(corev1.ConditionFalse) ||
		conditionStatus(conditions, "Degraded") != string(corev1.ConditionFalse) {
		return false, nil
	}
	return true, nil
}

func conditionStatus(conditions []any, conditionType string) string {
	for _, item := range conditions {
		condition, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if condition["type"] == conditionType {
			status, _ := condition["status"].(string)
			return status
		}
	}
	return "Unknown"
}

func unstructuredSlice(object *unstructured.Unstructured, fields ...string) ([]any, bool, error) {
	items, found, err := unstructured.NestedSlice(object.Object, fields...)
	if err != nil {
		return nil, false, fmt.Errorf("read %s from %q: %w", strings.Join(fields, "."), object.GetName(), err)
	}
	return items, found, nil
}

func nestedInteger(object *unstructured.Unstructured, fields ...string) (int64, bool) {
	value, found, err := unstructured.NestedFieldNoCopy(object.Object, fields...)
	if err != nil || !found {
		return 0, false
	}
	return integerValue(value)
}

func integerValue(value any) (int64, bool) {
	switch typed := value.(type) {
	case int64:
		return typed, true
	case int32:
		return int64(typed), true
	case int:
		return int64(typed), true
	case float64:
		if typed != float64(int64(typed)) {
			return 0, false
		}
		return int64(typed), true
	default:
		return 0, false
	}
}

func phaseAtLeast(phase, required rotation.Phase) bool {
	positions := make(map[rotation.Phase]int)
	for index, candidate := range rotation.OrderedPhases() {
		positions[candidate] = index
	}
	return positions[phase] >= positions[required]
}
