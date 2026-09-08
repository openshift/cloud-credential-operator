package kubeadapter

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/jwks"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/rotation"
)

func (a *Adapter) ObserveSignerReference(ctx context.Context, guard *rotation.RotationGuardReference) (*rotation.SignerObjectReference, error) {
	if guard != nil {
		if err := a.requireGuardHeld(ctx, *guard); err != nil {
			return nil, err
		}
	}
	metadata, err := a.secretMetadata.Get(ctx, kubeAPIServerOperatorNamespace, nextSignerSecretName)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read next signer Secret metadata: %w", err)
	}
	if metadata.UID == "" || metadata.ResourceVersion == "" {
		return nil, fmt.Errorf("next signer Secret metadata is missing UID or resourceVersion")
	}
	return &rotation.SignerObjectReference{
		UID:             string(metadata.UID),
		ResourceVersion: metadata.ResourceVersion,
	}, nil
}

func (a *Adapter) ObservePublicSignerBundle(ctx context.Context, guard *rotation.RotationGuardReference) (rotation.PublicSignerBundleObservation, error) {
	if guard != nil {
		if err := a.requireGuardHeld(ctx, *guard); err != nil {
			return rotation.PublicSignerBundleObservation{}, err
		}
	}
	configMap, err := a.kube.CoreV1().ConfigMaps(kubeAPIServerNamespace).Get(ctx, publicSignerCMName, metav1.GetOptions{})
	if err != nil {
		return rotation.PublicSignerBundleObservation{}, fmt.Errorf("read public signer ConfigMap: %w", err)
	}
	if configMap.UID == "" || configMap.ResourceVersion == "" {
		return rotation.PublicSignerBundleObservation{}, fmt.Errorf("public signer ConfigMap is missing UID or resourceVersion")
	}
	if len(configMap.BinaryData) != 0 {
		return rotation.PublicSignerBundleObservation{}, fmt.Errorf("public signer ConfigMap contains unsupported binary data")
	}
	names := make([]string, 0, len(configMap.Data))
	for name := range configMap.Data {
		names = append(names, name)
	}
	slices.Sort(names)
	signers := make([]rotation.PublicSignerObservation, 0, len(names))
	for _, name := range names {
		signers = append(signers, rotation.PublicSignerObservation{
			Name:         name,
			PublicKeyPEM: []byte(configMap.Data[name]),
		})
	}
	return rotation.PublicSignerBundleObservation{
		ConfigMapUID:             string(configMap.UID),
		ConfigMapResourceVersion: configMap.ResourceVersion,
		Signers:                  signers,
	}, nil
}

func (a *Adapter) RequestReplacement(ctx context.Context, guard rotation.RotationGuardReference, reference rotation.SignerObjectReference) (rotation.EffectOutcome, error) {
	if err := a.requireGuardHeld(ctx, guard); err != nil {
		return rotation.EffectNotApplied, err
	}
	if strings.TrimSpace(reference.UID) == "" || strings.TrimSpace(reference.ResourceVersion) == "" {
		return rotation.EffectNotApplied, fmt.Errorf("signer Secret deletion requires UID and resourceVersion preconditions")
	}
	uid := types.UID(reference.UID)
	resourceVersion := reference.ResourceVersion
	err := a.kube.CoreV1().Secrets(kubeAPIServerOperatorNamespace).Delete(ctx, nextSignerSecretName, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{
			UID:             &uid,
			ResourceVersion: &resourceVersion,
		},
	})
	return mutationOutcome(err), err
}

func (a *Adapter) WaitForReplacement(ctx context.Context, guard rotation.RotationGuardReference, previous rotation.SignerObjectReference) error {
	if strings.TrimSpace(previous.UID) == "" {
		return fmt.Errorf("previous signer Secret UID must not be empty")
	}
	return a.waitUntil(ctx, func(ctx context.Context) (bool, error) {
		reference, err := a.ObserveSignerReference(ctx, &guard)
		if err != nil {
			return false, err
		}
		if reference == nil || reference.UID == previous.UID {
			return false, nil
		}
		bundle, err := a.ObservePublicSignerBundle(ctx, &guard)
		if err != nil {
			return false, err
		}
		return len(bundle.Signers) != 0, nil
	})
}

func (a *Adapter) WaitForSignerRollout(ctx context.Context, guard rotation.RotationGuardReference, replacementKeyID string) error {
	if strings.TrimSpace(replacementKeyID) == "" || strings.TrimSpace(replacementKeyID) != replacementKeyID {
		return fmt.Errorf("replacement signer key ID must not be empty or contain surrounding whitespace")
	}
	return a.waitForContinuousStability(ctx, a.options.StablePeriod, func(ctx context.Context) (bool, error) {
		if err := a.requireGuardHeld(ctx, guard); err != nil {
			return false, err
		}
		return a.signerRolloutStable(ctx, replacementKeyID)
	})
}

func (a *Adapter) signerRolloutStable(ctx context.Context, replacementKeyID string) (bool, error) {
	entryName, publicKey, found, err := a.findPublicSignerByKeyID(ctx, replacementKeyID)
	if err != nil || !found {
		return false, err
	}
	distributed, err := a.signerDistributedToCurrentKubeAPIServerRevisions(ctx, entryName, publicKey)
	if err != nil || !distributed {
		return false, err
	}
	return a.clusterOperatorsStable(ctx)
}

func (a *Adapter) findPublicSignerByKeyID(ctx context.Context, keyID string) (string, []byte, bool, error) {
	configMap, err := a.kube.CoreV1().ConfigMaps(kubeAPIServerNamespace).Get(ctx, publicSignerCMName, metav1.GetOptions{})
	if err != nil {
		return "", nil, false, fmt.Errorf("read public signer ConfigMap during rollout: %w", err)
	}
	if len(configMap.BinaryData) != 0 {
		return "", nil, false, fmt.Errorf("public signer ConfigMap contains unsupported binary data")
	}
	for name, value := range configMap.Data {
		set, err := jwks.NewSigner([]byte(value))
		if err != nil {
			return "", nil, false, fmt.Errorf("parse public signer ConfigMap entry %q: %w", name, err)
		}
		if len(set.Keys) != 1 {
			return "", nil, false, fmt.Errorf("public signer ConfigMap entry %q did not produce exactly one key", name)
		}
		if set.Keys[0].KeyID == keyID {
			return name, []byte(value), true, nil
		}
	}
	return "", nil, false, nil
}

func (a *Adapter) signerDistributedToCurrentKubeAPIServerRevisions(ctx context.Context, entryName string, publicKey []byte) (bool, error) {
	kubeAPIServer, err := a.resources.Get(ctx, kubeAPIServerGVR, "cluster", metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("read kube-apiserver operator status: %w", err)
	}
	nodeStatuses, found, err := unstructuredSlice(kubeAPIServer, "status", "nodeStatuses")
	if err != nil {
		return false, err
	}
	if !found || len(nodeStatuses) == 0 {
		return false, nil
	}
	revisions := make(map[int64]struct{})
	for _, item := range nodeStatuses {
		status, ok := item.(map[string]any)
		if !ok {
			return false, fmt.Errorf("kube-apiserver node status has type %T", item)
		}
		revision, ok := integerValue(status["currentRevision"])
		if !ok || revision <= 0 {
			return false, nil
		}
		revisions[revision] = struct{}{}
	}
	for revision := range revisions {
		name := fmt.Sprintf("%s-%d", publicSignerCMName, revision)
		configMap, err := a.kube.CoreV1().ConfigMaps(kubeAPIServerNamespace).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("read kube-apiserver signer revision ConfigMap %q: %w", name, err)
		}
		if len(configMap.BinaryData) != 0 || !bytes.Equal([]byte(configMap.Data[entryName]), publicKey) {
			return false, nil
		}
	}
	return true, nil
}
