package kubeadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

const partialObjectMetadataAccept = "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"

type strictSecretMetadataClient struct {
	restClient rest.Interface
}

// Get intentionally does not use client-go's metadata client. That client
// advertises plain application/json as a fallback, which permits a server to
// return the full Secret. This request accepts only PartialObjectMetadata and
// validates the returned envelope before exposing metadata to the adapter.
func (c *strictSecretMetadataClient) Get(ctx context.Context, namespace, name string) (*metav1.PartialObjectMetadata, error) {
	if c == nil || c.restClient == nil {
		return nil, fmt.Errorf("strict Secret metadata client is not configured")
	}
	result := c.restClient.Get().
		Namespace(namespace).
		Resource("secrets").
		Name(name).
		SetHeader("Accept", partialObjectMetadataAccept).
		Do(ctx)

	var contentType string
	result.ContentType(&contentType)
	raw, err := result.Raw()
	if err != nil {
		return nil, err
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		return nil, fmt.Errorf("Secret metadata request returned unsupported content type %q", contentType)
	}

	var metadata metav1.PartialObjectMetadata
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return nil, fmt.Errorf("decode strict PartialObjectMetadata response: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode strict PartialObjectMetadata response: %w", err)
	}
	if metadata.APIVersion != metav1.SchemeGroupVersion.String() || metadata.Kind != "PartialObjectMetadata" {
		return nil, fmt.Errorf("Secret metadata request returned %s %q instead of meta.k8s.io/v1 PartialObjectMetadata", metadata.APIVersion, metadata.Kind)
	}
	if metadata.Name != name || metadata.Namespace != namespace {
		return nil, fmt.Errorf("Secret metadata response identified %q/%q instead of %q/%q", metadata.Namespace, metadata.Name, namespace, name)
	}
	return metadata.DeepCopy(), nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return fmt.Errorf("response contains trailing JSON values")
	}
	return err
}
