package aws

import (
	"context"
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"go.uber.org/mock/gomock"

	mockaws "github.com/openshift/cloud-credential-operator/pkg/aws/mock"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning/rotation"
)

const (
	testRotationRegion = "us-gov-west-1"
	testRotationBucket = "test-cluster-oidc"
	testRotationOwner  = "test-cluster"
)

func TestS3TargetResolver(t *testing.T) {
	resolver, err := NewS3TargetResolver(testRotationRegion, testRotationBucket)
	if err != nil {
		t.Fatalf("NewS3TargetResolver() error = %v", err)
	}
	target, err := resolver.ResolveTarget(context.Background())
	if err != nil {
		t.Fatalf("ResolveTarget() error = %v", err)
	}
	want := "s3://test-cluster-oidc/keys.json?region=us-gov-west-1"
	if target != want {
		t.Fatalf("ResolveTarget() = %q, want %q", target, want)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.ResolveTarget(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("ResolveTarget(cancelled) error = %v, want context cancellation", err)
	}
}

func TestS3TargetResolverRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		region string
		bucket string
	}{
		{name: "empty region", bucket: testRotationBucket},
		{name: "surrounding region whitespace", region: " us-east-1", bucket: testRotationBucket},
		{name: "empty bucket", region: testRotationRegion},
		{name: "uppercase bucket", region: testRotationRegion, bucket: "Test-Cluster-OIDC"},
		{name: "IP address bucket", region: testRotationRegion, bucket: "192.0.2.1"},
		{name: "adjacent bucket periods", region: testRotationRegion, bucket: "test..bucket"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewS3TargetResolver(test.region, test.bucket); err == nil {
				t.Fatal("NewS3TargetResolver() error = nil, want invalid configuration error")
			}
		})
	}
}

func TestS3JWKSBackendReadReturnsBoundedDataAndTagBoundRevision(t *testing.T) {
	controller := gomock.NewController(t)
	client := mockaws.NewMockClient(controller)
	backend, target := newTestS3JWKSBackend(t, client)
	tags := []s3types.Tag{
		{Key: awssdk.String("custom.example/note"), Value: awssdk.String("keep this value")},
		{Key: awssdk.String(testS3OwnershipTagKey()), Value: awssdk.String(ownedCcoctlAWSResourceTagValue)},
	}

	client.EXPECT().GetObject(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
			assertS3ObjectInput(t, input.Bucket, input.Key)
			return &s3.GetObjectOutput{
				Body:      io.NopCloser(strings.NewReader(`{"keys":[{"kid":"old"}]}`)),
				ETag:      awssdk.String(`"etag-1"`),
				VersionId: awssdk.String("version-1"),
			}, nil
		},
	)
	client.EXPECT().GetObjectTagging(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, input *s3.GetObjectTaggingInput, _ ...func(*s3.Options)) (*s3.GetObjectTaggingOutput, error) {
			assertS3ObjectInput(t, input.Bucket, input.Key)
			if got := awssdk.ToString(input.VersionId); got != "version-1" {
				t.Fatalf("GetObjectTagging VersionId = %q, want version-1", got)
			}
			return &s3.GetObjectTaggingOutput{TagSet: tags, VersionId: awssdk.String("version-1")}, nil
		},
	)

	observed, err := backend.ReadJWKS(context.Background(), target)
	if err != nil {
		t.Fatalf("ReadJWKS() error = %v", err)
	}
	if got, want := string(observed.Data), `{"keys":[{"kid":"old"}]}`; got != want {
		t.Fatalf("ReadJWKS() data = %q, want %q", got, want)
	}
	revision, err := decodeS3Revision(observed.Revision)
	if err != nil {
		t.Fatalf("decodeS3Revision() error = %v", err)
	}
	if revision.ETag != `"etag-1"` || revision.VersionID != "version-1" {
		t.Fatalf("ReadJWKS() revision = %#v", revision)
	}
	wantTags := []s3RevisionTag{
		{Key: "custom.example/note", Value: "keep this value"},
		{Key: testS3OwnershipTagKey(), Value: ownedCcoctlAWSResourceTagValue},
	}
	if !equalS3RevisionTags(revision.Tags, wantTags) {
		t.Fatalf("ReadJWKS() revision tags = %#v, want %#v", revision.Tags, wantTags)
	}
}

func TestS3JWKSBackendReadRejectsOversizedObject(t *testing.T) {
	controller := gomock.NewController(t)
	client := mockaws.NewMockClient(controller)
	backend, target := newTestS3JWKSBackend(t, client)
	client.EXPECT().GetObject(gomock.Any(), gomock.Any()).Return(&s3.GetObjectOutput{
		Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxS3JWKSBytes+1))),
		ETag: awssdk.String(`"etag-1"`),
	}, nil)

	_, err := backend.ReadJWKS(context.Background(), target)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("ReadJWKS() error = %v, want size-limit error", err)
	}
}

func TestS3JWKSBackendReadReportsVersionTaggingPermission(t *testing.T) {
	controller := gomock.NewController(t)
	client := mockaws.NewMockClient(controller)
	backend, target := newTestS3JWKSBackend(t, client)
	client.EXPECT().GetObject(gomock.Any(), gomock.Any()).Return(&s3.GetObjectOutput{
		Body:      io.NopCloser(strings.NewReader(`{"keys":[]}`)),
		ETag:      awssdk.String(`"etag-1"`),
		VersionId: awssdk.String("version-1"),
	}, nil)
	client.EXPECT().GetObjectTagging(gomock.Any(), gomock.Any()).Return(nil, &smithy.GenericAPIError{
		Code: "AccessDenied", Message: "missing version-tag permission", Fault: smithy.FaultClient,
	})

	_, err := backend.ReadJWKS(context.Background(), target)
	if err == nil || !strings.Contains(err.Error(), "s3:GetObjectVersionTagging") {
		t.Fatalf("ReadJWKS() error = %v, want version-tagging permission context", err)
	}
}

func TestS3JWKSBackendCheckAccessRejectsUnownedObject(t *testing.T) {
	controller := gomock.NewController(t)
	client := mockaws.NewMockClient(controller)
	backend, target := newTestS3JWKSBackend(t, client)
	client.EXPECT().GetObject(gomock.Any(), gomock.Any()).Return(&s3.GetObjectOutput{
		Body: io.NopCloser(strings.NewReader(`{"keys":[]}`)),
		ETag: awssdk.String(`"etag-1"`),
	}, nil)
	client.EXPECT().GetObjectTagging(gomock.Any(), gomock.Any()).Return(&s3.GetObjectTaggingOutput{
		TagSet: []s3types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String(testRotationOwner)}},
	}, nil)

	err := backend.CheckAccess(context.Background(), target)
	if err == nil || !strings.Contains(err.Error(), "missing ownership tag") {
		t.Fatalf("CheckAccess() error = %v, want missing ownership tag", err)
	}
}

func TestS3JWKSBackendPublishUsesETagAndPreservesExactTags(t *testing.T) {
	controller := gomock.NewController(t)
	client := mockaws.NewMockClient(controller)
	backend, target := newTestS3JWKSBackend(t, client)
	tags := []s3RevisionTag{
		{Key: "Name", Value: testRotationOwner},
		{Key: "custom.example/note", Value: "spaces & symbols"},
		{Key: testS3OwnershipTagKey(), Value: ownedCcoctlAWSResourceTagValue},
	}
	revision := mustEncodeS3Revision(t, s3ObjectRevision{ETag: `"etag-1"`, VersionID: "version-1", Tags: tags})
	expectCurrentS3Tags(t, client, tags, "version-1")

	desired := []byte(`{"keys":[{"kid":"new"}]}`)
	client.EXPECT().PutObject(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, input *s3.PutObjectInput, optionFunctions ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
			assertS3ObjectInput(t, input.Bucket, input.Key)
			assertS3WriteRetriesDisabled(t, optionFunctions)
			if got := awssdk.ToString(input.ContentType); got != "application/json" {
				t.Fatalf("PutObject ContentType = %q, want application/json", got)
			}
			if got := awssdk.ToString(input.IfMatch); got != `"etag-1"` {
				t.Fatalf("PutObject IfMatch = %q, want quoted predecessor ETag", got)
			}
			body, err := io.ReadAll(input.Body)
			if err != nil {
				t.Fatalf("read PutObject body: %v", err)
			}
			if string(body) != string(desired) {
				t.Fatalf("PutObject body = %q, want %q", body, desired)
			}
			gotTags, err := url.ParseQuery(awssdk.ToString(input.Tagging))
			if err != nil {
				t.Fatalf("parse PutObject Tagging: %v", err)
			}
			wantTags := url.Values{
				"Name":                  []string{testRotationOwner},
				"custom.example/note":   []string{"spaces & symbols"},
				testS3OwnershipTagKey(): []string{ownedCcoctlAWSResourceTagValue},
			}
			if gotTags.Encode() != wantTags.Encode() {
				t.Fatalf("PutObject tags = %q, want %q", gotTags.Encode(), wantTags.Encode())
			}
			return &s3.PutObjectOutput{}, nil
		},
	)

	outcome, err := backend.PublishIfVersion(context.Background(), target, revision, desired)
	if err != nil {
		t.Fatalf("PublishIfVersion() error = %v", err)
	}
	if outcome != rotation.EffectSubmitted {
		t.Fatalf("PublishIfVersion() outcome = %q, want %q", outcome, rotation.EffectSubmitted)
	}
}

func TestS3JWKSBackendPublishRejectsTagOrVersionDrift(t *testing.T) {
	tests := []struct {
		name           string
		currentVersion string
		currentTags    []s3RevisionTag
		wantError      string
	}{
		{
			name:           "version changed",
			currentVersion: "version-2",
			currentTags:    testS3RevisionTags(),
			wantError:      "version changed",
		},
		{
			name:           "tags changed",
			currentVersion: "version-1",
			currentTags: append(testS3RevisionTags(), s3RevisionTag{
				Key: "new-tag", Value: "new-value",
			}),
			wantError: "tags changed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			client := mockaws.NewMockClient(controller)
			backend, target := newTestS3JWKSBackend(t, client)
			revision := mustEncodeS3Revision(t, s3ObjectRevision{
				ETag: `"etag-1"`, VersionID: "version-1", Tags: testS3RevisionTags(),
			})
			expectCurrentS3Tags(t, client, test.currentTags, test.currentVersion)

			outcome, err := backend.PublishIfVersion(context.Background(), target, revision, []byte(`{"keys":[]}`))
			if outcome != rotation.EffectNotApplied {
				t.Fatalf("PublishIfVersion() outcome = %q, want %q", outcome, rotation.EffectNotApplied)
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("PublishIfVersion() error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestS3JWKSBackendPublishClassifiesAWSOutcomes(t *testing.T) {
	tests := []struct {
		name        string
		putError    error
		wantOutcome rotation.EffectOutcome
	}{
		{
			name: "precondition failed",
			putError: &smithy.GenericAPIError{
				Code: "PreconditionFailed", Message: "stale ETag", Fault: smithy.FaultUnknown,
			},
			wantOutcome: rotation.EffectNotApplied,
		},
		{
			name: "conditional conflict",
			putError: &smithy.GenericAPIError{
				Code: "ConditionalRequestConflict", Message: "conflicting write", Fault: smithy.FaultUnknown,
			},
			wantOutcome: rotation.EffectNotApplied,
		},
		{
			name: "access denied",
			putError: &smithy.GenericAPIError{
				Code: "AccessDenied", Message: "missing permission", Fault: smithy.FaultClient,
			},
			wantOutcome: rotation.EffectNotApplied,
		},
		{
			name: "server outcome unknown",
			putError: &smithy.GenericAPIError{
				Code: "InternalError", Message: "try again", Fault: smithy.FaultServer,
			},
			wantOutcome: rotation.EffectUnknown,
		},
		{
			name:        "transport outcome unknown",
			putError:    errors.New("connection closed"),
			wantOutcome: rotation.EffectUnknown,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller := gomock.NewController(t)
			client := mockaws.NewMockClient(controller)
			backend, target := newTestS3JWKSBackend(t, client)
			tags := testS3RevisionTags()
			revision := mustEncodeS3Revision(t, s3ObjectRevision{
				ETag: `"etag-1"`, VersionID: "version-1", Tags: tags,
			})
			expectCurrentS3Tags(t, client, tags, "version-1")
			client.EXPECT().PutObject(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
				func(_ context.Context, _ *s3.PutObjectInput, optionFunctions ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
					assertS3WriteRetriesDisabled(t, optionFunctions)
					return nil, test.putError
				},
			)

			outcome, err := backend.PublishIfVersion(context.Background(), target, revision, []byte(`{"keys":[]}`))
			if outcome != test.wantOutcome {
				t.Fatalf("PublishIfVersion() outcome = %q, want %q", outcome, test.wantOutcome)
			}
			if err == nil || !strings.Contains(err.Error(), "s3:PutObject") {
				t.Fatalf("PublishIfVersion() error = %v, want actionable permission context", err)
			}
		})
	}
}

func TestS3JWKSBackendPublishRejectsInvalidRevisionWithoutAWSCalls(t *testing.T) {
	controller := gomock.NewController(t)
	client := mockaws.NewMockClient(controller)
	backend, target := newTestS3JWKSBackend(t, client)

	outcome, err := backend.PublishIfVersion(context.Background(), target, "not-a-revision", []byte(`{"keys":[]}`))
	if outcome != rotation.EffectNotApplied {
		t.Fatalf("PublishIfVersion() outcome = %q, want %q", outcome, rotation.EffectNotApplied)
	}
	if err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Fatalf("PublishIfVersion() error = %v, want invalid revision", err)
	}
}

func TestS3JWKSBackendPublishRejectsOversizedObjectWithoutAWSCalls(t *testing.T) {
	controller := gomock.NewController(t)
	client := mockaws.NewMockClient(controller)
	backend, target := newTestS3JWKSBackend(t, client)
	revision := mustEncodeS3Revision(t, s3ObjectRevision{
		ETag: `"etag-1"`, Tags: testS3RevisionTags(),
	})

	outcome, err := backend.PublishIfVersion(context.Background(), target, revision, make([]byte, maxS3JWKSBytes+1))
	if outcome != rotation.EffectNotApplied {
		t.Fatalf("PublishIfVersion() outcome = %q, want %q", outcome, rotation.EffectNotApplied)
	}
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("PublishIfVersion() error = %v, want size-limit error", err)
	}
}

func TestS3RevisionRejectsOversizedOpaqueFields(t *testing.T) {
	tests := []struct {
		name     string
		revision s3ObjectRevision
	}{
		{
			name: "ETag",
			revision: s3ObjectRevision{
				ETag: strings.Repeat("e", maxS3ETagBytes+1), Tags: testS3RevisionTags(),
			},
		},
		{
			name: "version ID",
			revision: s3ObjectRevision{
				ETag: `"etag-1"`, VersionID: strings.Repeat("v", maxS3VersionIDBytes+1), Tags: testS3RevisionTags(),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := encodeS3Revision(test.revision); err == nil {
				t.Fatal("encodeS3Revision() error = nil, want bounded-field error")
			}
		})
	}
}

func newTestS3JWKSBackend(t *testing.T, client *mockaws.MockClient) (*S3JWKSBackend, string) {
	t.Helper()
	backend, err := NewS3JWKSBackend(client, testRotationRegion, testRotationBucket, testRotationOwner)
	if err != nil {
		t.Fatalf("NewS3JWKSBackend() error = %v", err)
	}
	resolver, err := NewS3TargetResolver(testRotationRegion, testRotationBucket)
	if err != nil {
		t.Fatalf("NewS3TargetResolver() error = %v", err)
	}
	target, err := resolver.ResolveTarget(context.Background())
	if err != nil {
		t.Fatalf("ResolveTarget() error = %v", err)
	}
	return backend, target
}

func testS3OwnershipTagKey() string {
	return ccoctlAWSResourceTagKeyPrefix + "/" + testRotationOwner
}

func testS3RevisionTags() []s3RevisionTag {
	return []s3RevisionTag{{Key: testS3OwnershipTagKey(), Value: ownedCcoctlAWSResourceTagValue}}
}

func mustEncodeS3Revision(t *testing.T, revision s3ObjectRevision) string {
	t.Helper()
	encoded, err := encodeS3Revision(revision)
	if err != nil {
		t.Fatalf("encodeS3Revision() error = %v", err)
	}
	return encoded
}

func expectCurrentS3Tags(t *testing.T, client *mockaws.MockClient, tags []s3RevisionTag, versionID string) {
	t.Helper()
	client.EXPECT().GetObjectTagging(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, input *s3.GetObjectTaggingInput, _ ...func(*s3.Options)) (*s3.GetObjectTaggingOutput, error) {
			assertS3ObjectInput(t, input.Bucket, input.Key)
			if input.VersionId != nil {
				t.Fatalf("current GetObjectTagging VersionId = %q, want no explicit version", awssdk.ToString(input.VersionId))
			}
			tagSet := make([]s3types.Tag, 0, len(tags))
			for _, tag := range tags {
				tagSet = append(tagSet, s3types.Tag{Key: awssdk.String(tag.Key), Value: awssdk.String(tag.Value)})
			}
			return &s3.GetObjectTaggingOutput{TagSet: tagSet, VersionId: awssdk.String(versionID)}, nil
		},
	)
}

func assertS3ObjectInput(t *testing.T, bucket, key *string) {
	t.Helper()
	if got := awssdk.ToString(bucket); got != testRotationBucket {
		t.Fatalf("AWS S3 bucket = %q, want %q", got, testRotationBucket)
	}
	if got := awssdk.ToString(key); got != provisioning.KeysURI {
		t.Fatalf("AWS S3 key = %q, want %q", got, provisioning.KeysURI)
	}
}

func assertS3WriteRetriesDisabled(t *testing.T, optionFunctions []func(*s3.Options)) {
	t.Helper()
	if len(optionFunctions) != 1 {
		t.Fatalf("PutObject option functions = %d, want 1", len(optionFunctions))
	}
	options := s3.Options{}
	optionFunctions[0](&options)
	if options.Retryer == nil || options.Retryer.MaxAttempts() != 1 {
		t.Fatalf("PutObject retryer max attempts = %v, want 1", options.Retryer)
	}
}
