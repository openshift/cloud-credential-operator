package aws

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	awsclient "github.com/openshift/cloud-credential-operator/pkg/aws"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/rotation"
)

const (
	maxS3JWKSBytes          = 1 << 20
	maxS3ETagBytes          = 1 << 10
	maxS3VersionIDBytes     = 2 << 10
	s3RevisionPrefix        = "s3-object-v1."
	maxS3RevisionPayloadLen = 32 << 10
)

var (
	s3BucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`)
	awsRegionPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*[a-z0-9]$`)
)

// S3TargetResolver returns one canonical identity for the configured keys.json
// object. The region is part of the identity so identically named buckets in
// different AWS partitions cannot share rotation state.
type S3TargetResolver struct {
	target string
}

// NewS3TargetResolver constructs a resolver for a ccoctl-managed S3 issuer.
func NewS3TargetResolver(region, bucket string) (*S3TargetResolver, error) {
	target, err := s3TargetIdentity(region, bucket)
	if err != nil {
		return nil, err
	}
	return &S3TargetResolver{target: target}, nil
}

// ResolveTarget implements rotation.TargetResolver.
func (r *S3TargetResolver) ResolveTarget(ctx context.Context) (string, error) {
	if r == nil {
		return "", fmt.Errorf("AWS S3 target resolver must not be nil")
	}
	if ctx == nil {
		return "", fmt.Errorf("AWS S3 target resolution requires a context")
	}
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("resolve AWS S3 JWKS target: %w", err)
	}
	return r.target, nil
}

// S3JWKSBackend reads and conditionally replaces a ccoctl-managed keys.json
// object. Its opaque revision carries the predecessor ETag plus the observed
// version ID and exact tag set used by a subsequent write.
type S3JWKSBackend struct {
	client          awsclient.Client
	bucket          string
	key             string
	target          string
	ownershipTagKey string
}

// NewS3JWKSBackend constructs the direct-publication backend for one S3 issuer.
func NewS3JWKSBackend(client awsclient.Client, region, bucket, ownerName string) (*S3JWKSBackend, error) {
	if client == nil {
		return nil, fmt.Errorf("AWS client must not be nil")
	}
	target, err := s3TargetIdentity(region, bucket)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(ownerName) == "" || strings.TrimSpace(ownerName) != ownerName {
		return nil, fmt.Errorf("AWS resource owner name must not be empty or contain surrounding whitespace")
	}
	if containsControl(ownerName) {
		return nil, fmt.Errorf("AWS resource owner name must not contain control characters")
	}
	ownershipTagKey := fmt.Sprintf("%s/%s", ccoctlAWSResourceTagKeyPrefix, ownerName)
	if utf8.RuneCountInString(ownershipTagKey) > 128 {
		return nil, fmt.Errorf("AWS resource ownership tag key exceeds the S3 limit")
	}

	return &S3JWKSBackend{
		client:          client,
		bucket:          bucket,
		key:             provisioning.KeysURI,
		target:          target,
		ownershipTagKey: ownershipTagKey,
	}, nil
}

// CheckAccess verifies that the exact object and its tags are readable and
// that the object is owned by the configured ccoctl resource. S3 has no
// mutation-free probe for PutObject authorization, so the eventual write is
// still guarded by If-Match and returns an actionable authorization failure.
// Versioned objects also require s3:GetObjectVersionTagging.
func (b *S3JWKSBackend) CheckAccess(ctx context.Context, target string) error {
	if _, err := b.ReadJWKS(ctx, target); err != nil {
		return fmt.Errorf("validate AWS S3 JWKS read and tagging access: %w", err)
	}
	return nil
}

// ReadJWKS returns the public keys.json bytes and an opaque revision that
// records the exact object tags for publication.
func (b *S3JWKSBackend) ReadJWKS(ctx context.Context, target string) (rotation.VersionedJWKS, error) {
	var versioned rotation.VersionedJWKS
	if err := b.validateRequest(ctx, target); err != nil {
		return versioned, err
	}

	output, err := b.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: awssdk.String(b.bucket),
		Key:    awssdk.String(b.key),
	})
	if err != nil {
		return versioned, fmt.Errorf("read AWS S3 JWKS object %q (requires s3:GetObject): %w", b.target, err)
	}
	if output == nil || output.Body == nil {
		return versioned, fmt.Errorf("read AWS S3 JWKS object %q: response body is missing", b.target)
	}

	data, err := readBoundedS3Object(output.Body)
	if err != nil {
		return versioned, fmt.Errorf("read AWS S3 JWKS object %q body: %w", b.target, err)
	}
	etag := awssdk.ToString(output.ETag)
	if strings.TrimSpace(etag) == "" || strings.TrimSpace(etag) != etag || containsControl(etag) {
		return versioned, fmt.Errorf("read AWS S3 JWKS object %q: response ETag is missing or invalid", b.target)
	}

	tagOutput, tags, err := b.readObjectTags(ctx, output.VersionId)
	if err != nil {
		return versioned, err
	}
	if !sameOptionalString(output.VersionId, tagOutput.VersionId) {
		return versioned, fmt.Errorf("read AWS S3 JWKS object %q: object and tag version IDs differ", b.target)
	}
	if err := b.requireOwnershipTag(tags); err != nil {
		return versioned, err
	}

	revision, err := encodeS3Revision(s3ObjectRevision{
		ETag:      etag,
		VersionID: awssdk.ToString(output.VersionId),
		Tags:      tags,
	})
	if err != nil {
		return versioned, fmt.Errorf("encode AWS S3 JWKS object revision: %w", err)
	}
	return rotation.VersionedJWKS{Data: data, Revision: revision}, nil
}

// PublishIfVersion replaces keys.json only when the current ETag still matches
// the predecessor revision. It performs best-effort version and tag drift
// checks immediately before the write, then copies the last-observed exact tag
// set to the new object, including the required OpenShift ownership tag. S3's
// atomic write precondition covers the object ETag, not tags or version IDs.
func (b *S3JWKSBackend) PublishIfVersion(ctx context.Context, target, revision string, data []byte) (rotation.EffectOutcome, error) {
	if err := b.validateRequest(ctx, target); err != nil {
		return rotation.EffectNotApplied, err
	}
	if len(data) == 0 {
		return rotation.EffectNotApplied, fmt.Errorf("refusing to publish an empty AWS S3 JWKS object")
	}
	if len(data) > maxS3JWKSBytes {
		return rotation.EffectNotApplied, fmt.Errorf("refusing to publish an AWS S3 JWKS object larger than the %d-byte limit", maxS3JWKSBytes)
	}

	decoded, err := decodeS3Revision(revision)
	if err != nil {
		return rotation.EffectNotApplied, fmt.Errorf("decode AWS S3 JWKS object revision: %w", err)
	}
	if err := b.requireOwnershipTag(decoded.Tags); err != nil {
		return rotation.EffectNotApplied, err
	}

	currentTagOutput, currentTags, err := b.readObjectTags(ctx, nil)
	if err != nil {
		return rotation.EffectNotApplied, fmt.Errorf("recheck AWS S3 JWKS tags before publication: %w", err)
	}
	if awssdk.ToString(currentTagOutput.VersionId) != decoded.VersionID {
		return rotation.EffectNotApplied, fmt.Errorf("AWS S3 JWKS object version changed before conditional publication")
	}
	if !equalS3RevisionTags(currentTags, decoded.Tags) {
		return rotation.EffectNotApplied, fmt.Errorf("AWS S3 JWKS object tags changed before conditional publication")
	}

	encodedTags := encodeS3ObjectTags(decoded.Tags)
	_, putErr := b.client.PutObject(ctx, &s3.PutObjectInput{
		Body:        bytes.NewReader(data),
		Bucket:      awssdk.String(b.bucket),
		ContentType: awssdk.String("application/json"),
		IfMatch:     awssdk.String(decoded.ETag),
		Key:         awssdk.String(b.key),
		Tagging:     awssdk.String(encodedTags),
	}, func(options *s3.Options) {
		// A conditional replacement is not safe for transparent retry. If the
		// first response is lost after S3 commits the write, a replay uses the
		// stale ETag and can return a misleading precondition failure.
		options.Retryer = awssdk.NopRetryer{}
	})
	if putErr == nil {
		return rotation.EffectSubmitted, nil
	}

	err = fmt.Errorf("conditionally publish AWS S3 JWKS object %q (requires s3:PutObject and s3:PutObjectTagging): %w", b.target, putErr)
	if s3WriteDefinitelyNotApplied(putErr) {
		return rotation.EffectNotApplied, err
	}
	return rotation.EffectUnknown, err
}

func (b *S3JWKSBackend) validateRequest(ctx context.Context, target string) error {
	if b == nil || b.client == nil {
		return fmt.Errorf("AWS S3 JWKS backend must not be nil")
	}
	if ctx == nil {
		return fmt.Errorf("AWS S3 JWKS operation requires a context")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("AWS S3 JWKS operation cancelled before submission: %w", err)
	}
	if target != b.target {
		return fmt.Errorf("AWS S3 JWKS target does not match configured target %q", b.target)
	}
	return nil
}

func (b *S3JWKSBackend) readObjectTags(ctx context.Context, versionID *string) (*s3.GetObjectTaggingOutput, []s3RevisionTag, error) {
	permission := "s3:GetObjectTagging"
	if awssdk.ToString(versionID) != "" {
		permission = "s3:GetObjectVersionTagging"
	}
	output, err := b.client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
		Bucket:    awssdk.String(b.bucket),
		Key:       awssdk.String(b.key),
		VersionId: versionID,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("read AWS S3 JWKS object tags %q (requires %s): %w", b.target, permission, err)
	}
	if output == nil {
		return nil, nil, fmt.Errorf("read AWS S3 JWKS object tags %q: response is missing", b.target)
	}
	tags, err := normalizeS3Tags(output.TagSet)
	if err != nil {
		return nil, nil, fmt.Errorf("read AWS S3 JWKS object tags %q: %w", b.target, err)
	}
	return output, tags, nil
}

func (b *S3JWKSBackend) requireOwnershipTag(tags []s3RevisionTag) error {
	for _, tag := range tags {
		if tag.Key == b.ownershipTagKey && tag.Value == ownedCcoctlAWSResourceTagValue {
			return nil
		}
	}
	return fmt.Errorf("AWS S3 JWKS object %q is missing ownership tag %q=%q", b.target, b.ownershipTagKey, ownedCcoctlAWSResourceTagValue)
}

func s3TargetIdentity(region, bucket string) (string, error) {
	if err := validateAWSRegion(region); err != nil {
		return "", err
	}
	if err := validateS3BucketName(bucket); err != nil {
		return "", err
	}
	target := url.URL{
		Scheme:   "s3",
		Host:     bucket,
		Path:     "/" + provisioning.KeysURI,
		RawQuery: url.Values{"region": []string{region}}.Encode(),
	}
	return target.String(), nil
}

func validateAWSRegion(region string) error {
	if strings.TrimSpace(region) == "" || strings.TrimSpace(region) != region || len(region) > 63 || !awsRegionPattern.MatchString(region) {
		return fmt.Errorf("AWS region %q is invalid", region)
	}
	return nil
}

func validateS3BucketName(bucket string) error {
	if len(bucket) < 3 || len(bucket) > 63 || !s3BucketNamePattern.MatchString(bucket) || strings.Contains(bucket, "..") || net.ParseIP(bucket) != nil {
		return fmt.Errorf("AWS S3 bucket name %q is invalid", bucket)
	}
	return nil
}

func readBoundedS3Object(body io.ReadCloser) ([]byte, error) {
	limited := &io.LimitedReader{R: body, N: maxS3JWKSBytes + 1}
	data, readErr := io.ReadAll(limited)
	closeErr := body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if len(data) > maxS3JWKSBytes {
		return nil, fmt.Errorf("object exceeds the %d-byte JWKS limit", maxS3JWKSBytes)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return data, nil
}

type s3ObjectRevision struct {
	ETag      string          `json:"etag"`
	VersionID string          `json:"versionID,omitempty"`
	Tags      []s3RevisionTag `json:"tags"`
}

type s3RevisionTag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func encodeS3Revision(revision s3ObjectRevision) (string, error) {
	if err := validateS3Revision(&revision); err != nil {
		return "", err
	}
	raw, err := json.Marshal(revision)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	if len(payload) > maxS3RevisionPayloadLen {
		return "", fmt.Errorf("revision payload exceeds the supported size")
	}
	return s3RevisionPrefix + payload, nil
}

func decodeS3Revision(encoded string) (s3ObjectRevision, error) {
	var revision s3ObjectRevision
	if !strings.HasPrefix(encoded, s3RevisionPrefix) {
		return revision, fmt.Errorf("revision has an unsupported format")
	}
	payload := strings.TrimPrefix(encoded, s3RevisionPrefix)
	if payload == "" || len(payload) > maxS3RevisionPayloadLen {
		return revision, fmt.Errorf("revision payload is empty or too large")
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return revision, fmt.Errorf("revision payload is invalid: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&revision); err != nil {
		return revision, fmt.Errorf("revision payload is invalid: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return revision, fmt.Errorf("revision payload contains trailing data")
	}
	if err := validateS3Revision(&revision); err != nil {
		return revision, err
	}
	return revision, nil
}

func validateS3Revision(revision *s3ObjectRevision) error {
	if revision == nil || strings.TrimSpace(revision.ETag) == "" || strings.TrimSpace(revision.ETag) != revision.ETag || len(revision.ETag) > maxS3ETagBytes || containsControl(revision.ETag) {
		return fmt.Errorf("revision ETag is missing or invalid")
	}
	if len(revision.VersionID) > maxS3VersionIDBytes || containsControl(revision.VersionID) {
		return fmt.Errorf("revision version ID is invalid")
	}
	if len(revision.Tags) > 10 {
		return fmt.Errorf("revision contains more than 10 S3 object tags")
	}
	seen := make(map[string]struct{}, len(revision.Tags))
	for _, tag := range revision.Tags {
		if tag.Key == "" || utf8.RuneCountInString(tag.Key) > 128 || containsControl(tag.Key) {
			return fmt.Errorf("revision contains an invalid S3 object tag key")
		}
		if utf8.RuneCountInString(tag.Value) > 256 || containsControl(tag.Value) {
			return fmt.Errorf("revision contains an invalid S3 object tag value")
		}
		if _, exists := seen[tag.Key]; exists {
			return fmt.Errorf("revision contains duplicate S3 object tag %q", tag.Key)
		}
		seen[tag.Key] = struct{}{}
	}
	sort.Slice(revision.Tags, func(i, j int) bool {
		return revision.Tags[i].Key < revision.Tags[j].Key
	})
	return nil
}

func normalizeS3Tags(tagSet []s3types.Tag) ([]s3RevisionTag, error) {
	tags := make([]s3RevisionTag, 0, len(tagSet))
	for _, tag := range tagSet {
		if tag.Key == nil || tag.Value == nil {
			return nil, fmt.Errorf("S3 object tag has a missing key or value")
		}
		tags = append(tags, s3RevisionTag{Key: *tag.Key, Value: *tag.Value})
	}
	revision := s3ObjectRevision{ETag: "placeholder", Tags: tags}
	if err := validateS3Revision(&revision); err != nil {
		return nil, err
	}
	return revision.Tags, nil
}

func encodeS3ObjectTags(tags []s3RevisionTag) string {
	values := make(url.Values, len(tags))
	for _, tag := range tags {
		values.Set(tag.Key, tag.Value)
	}
	return values.Encode()
}

func equalS3RevisionTags(left, right []s3RevisionTag) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sameOptionalString(left, right *string) bool {
	return awssdk.ToString(left) == awssdk.ToString(right)
}

func containsControl(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func s3WriteDefinitelyNotApplied(err error) bool {
	var apiError smithy.APIError
	if !errors.As(err, &apiError) {
		return false
	}
	if apiError.ErrorCode() == "PreconditionFailed" || apiError.ErrorCode() == "ConditionalRequestConflict" {
		return true
	}
	return apiError.ErrorFault() == smithy.FaultClient
}

var _ rotation.TargetResolver = (*S3TargetResolver)(nil)
var _ rotation.ConditionalJWKSBackend = (*S3JWKSBackend)(nil)
