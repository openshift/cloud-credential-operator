# Cloud Credential Operator - Testing Guide

> **Generic Testing Practices**: See [Tier 1 Testing Practices](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/testing) for test pyramid philosophy (60/30/10), E2E framework patterns, and mock vs real strategies.

This guide covers **CCO-specific** test suites and testing practices.

## Test Organization

CCO follows the standard testing pyramid:

```text
      E2E Tests (10%, slow, comprehensive)
            ▲
       Integration Tests (30%, medium)
            ▲
        Unit Tests (60%, fast, focused)
```

**Test Scope**:
- **Unit**: Controller logic, cloud actuators (mocked APIs), domain logic
- **Integration**: Kubernetes API integration, controller reconciliation
- **E2E**: Full credential provisioning with real cloud providers

## Unit Tests

### Location

Unit tests live alongside the code they test:
- `pkg/operator/*/` - Controller unit tests
- `pkg/{aws,azure,gcp,...}/` - Cloud actuator unit tests (mocked cloud APIs)
- `pkg/cmd/` - ccoctl command tests

### Running Unit Tests

```bash
# All unit tests
make test

# Specific package
go test -v ./pkg/operator/credentialsrequest/...

# Disable caching
go test -count=1 ./pkg/...

# With coverage
go test -cover ./pkg/...

# Coverage report
go test -coverprofile=coverage.out ./pkg/...
go tool cover -html=coverage.out
```

### Unit Test Patterns

#### Controller Tests

Test controller logic without real Kubernetes API:

```go
func TestCredentialsRequestReconcile(t *testing.T) {
    // Use fake clientset
    fakeClient := fake.NewFakeClient()
    
    // Create test CredentialsRequest
    cr := &v1.CredentialsRequest{
        ObjectMeta: metav1.ObjectMeta{
            Name: "test-cr",
            Namespace: "test-ns",
        },
        Spec: v1.CredentialsRequestSpec{
            SecretRef: corev1.ObjectReference{
                Name: "test-secret",
                Namespace: "test-ns",
            },
        },
    }
    
    // Create reconciler with mocked actuator
    r := &Reconciler{
        Client: fakeClient,
        Actuator: mockActuator,
    }
    
    // Test reconcile logic
    result, err := r.Reconcile(ctx, req)
    require.NoError(t, err)
    assert.False(t, result.Requeue)
}
```

**For generic controller patterns**, see [Tier 1 Controller Runtime](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/operator-patterns/controller-runtime.md)

#### Cloud Actuator Tests (Mocked)

Test cloud provider logic with mocked APIs:

```go
func TestAWSActuatorCreate(t *testing.T) {
    // Mock AWS API client
    mockIAM := &mockAWSClient{
        CreateUserFunc: func(input *iam.CreateUserInput) (*iam.CreateUserOutput, error) {
            return &iam.CreateUserOutput{
                User: &iam.User{UserName: input.UserName},
            }, nil
        },
    }
    
    actuator := &AWSActuator{
        Client: mockIAM,
    }
    
    // Test Create logic
    err := actuator.Create(ctx, cr)
    require.NoError(t, err)
    
    // Verify API calls
    assert.True(t, mockIAM.CreateUserCalled)
}
```

**Why mock cloud APIs in unit tests**:
- Fast execution (no network I/O)
- No cloud account required
- Deterministic (no flakes from cloud API rate limits)
- Test error scenarios (API failures, rate limits)

### Component-Specific Unit Test Patterns

#### Mode Detection Tests

Test automatic mode detection logic:

```go
func TestModeDetection(t *testing.T) {
    tests := []struct {
        name           string
        rootSecret     *corev1.Secret
        cloudAPIWorks  bool
        canMint        bool
        expectedMode   string
    }{
        {
            name: "Mint mode when root can create IAM",
            rootSecret: &corev1.Secret{/* valid creds */},
            cloudAPIWorks: true,
            canMint: true,
            expectedMode: "mint",
        },
        {
            name: "Passthrough when root cannot mint but has perms",
            rootSecret: &corev1.Secret{/* valid creds */},
            cloudAPIWorks: true,
            canMint: false,
            expectedMode: "passthrough",
        },
        {
            name: "Manual when no root secret",
            rootSecret: nil,
            expectedMode: "manual",
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            mode := detectMode(tt.rootSecret, mockCloudClient)
            assert.Equal(t, tt.expectedMode, mode)
        })
    }
}
```

#### Finalizer Tests

Test finalizer cleanup logic:

```go
func TestFinalizerCleanup(t *testing.T) {
    cr := &v1.CredentialsRequest{
        ObjectMeta: metav1.ObjectMeta{
            DeletionTimestamp: &now,
            Finalizers: []string{"cloudcredential.openshift.io/deprovision"},
        },
    }
    
    mockActuator := &mockActuator{
        DeleteFunc: func(ctx context.Context, cr *v1.CredentialsRequest) error {
            return nil // Successful deletion
        },
    }
    
    r := &Reconciler{Actuator: mockActuator}
    _, err := r.Reconcile(ctx, req)
    require.NoError(t, err)
    
    // Verify finalizer removed
    assert.Empty(t, cr.Finalizers)
}
```

## Integration Tests

### Location

`test/integration/` (currently limited; most testing in unit + E2E)

### Running Integration Tests

```bash
# Requires KUBECONFIG set to test cluster
export KUBECONFIG=/path/to/kubeconfig
go test -v ./test/integration/...
```

### Integration Test Patterns

Test with real Kubernetes API (but mocked cloud APIs):

```go
func TestCredentialsRequestIntegration(t *testing.T) {
    client := framework.NewTestClient(t)
    
    // Create CredentialsRequest
    cr := &v1.CredentialsRequest{...}
    err := client.Create(ctx, cr)
    require.NoError(t, err)
    
    // Wait for status update
    err = wait.Poll(1*time.Second, 30*time.Second, func() (bool, error) {
        err := client.Get(ctx, key, cr)
        return err == nil && cr.Status.Provisioned, nil
    })
    require.NoError(t, err)
}
```

### Component-Specific Integration Tests

**CredentialsRequest Controller**:
- Create CR, verify Secret created
- Update CR, verify Secret updated
- Delete CR, verify Secret deleted (if owned)

**Status Controller**:
- Create multiple CRs, verify ClusterOperator status aggregation
- Mark CR failed, verify ClusterOperator Degraded

## E2E Tests

### Location

`test/e2e/` and `cmd/cloud-credential-tests-ext/`

**Two E2E suites**:
1. **In-repo E2E** (`test/e2e/`): Basic scenarios
2. **Extended E2E** (`cloud-credential-tests-ext`): Cloud-specific, long-running

### Running E2E Tests

```bash
# Requires real OpenShift cluster with cloud provider
export KUBECONFIG=/path/to/kubeconfig

# In-repo E2E
go test -v ./test/e2e/ -timeout 30m

# Extended E2E (cloud-specific)
# Build extended test binary
go build -o _output/cloud-credential-tests-ext ./cmd/cloud-credential-tests-ext

# Run against AWS cluster
./_output/cloud-credential-tests-ext --kubeconfig=$KUBECONFIG --cloud=aws

# Run against Azure cluster
./_output/cloud-credential-tests-ext --kubeconfig=$KUBECONFIG --cloud=azure
```

### E2E Test Organization

```text
test/e2e/
├── operator_test.go           # Basic operator E2E tests
└── framework/                 # E2E test utilities

cmd/cloud-credential-tests-ext/
├── main.go                    # Extended test suite entry
├── aws/                       # AWS-specific E2E tests
├── azure/                     # Azure-specific E2E tests
└── gcp/                       # GCP-specific E2E tests
```

### E2E Test Scenarios

#### Mint Mode E2E

```go
func TestMintModeE2E(t *testing.T) {
    client := framework.NewClient(t)
    
    // Create CredentialsRequest
    cr := &v1.CredentialsRequest{
        ObjectMeta: metav1.ObjectMeta{
            Name: "test-mint-cr",
            Namespace: "openshift-cloud-credential-operator",
        },
        Spec: v1.CredentialsRequestSpec{
            SecretRef: corev1.ObjectReference{
                Name: "test-creds",
                Namespace: "default",
            },
            ProviderSpec: &runtime.RawExtension{
                Raw: marshalAWSProviderSpec(t, &v1.AWSProviderSpec{
                    StatementEntries: []v1.StatementEntry{
                        {Effect: "Allow", Action: []string{"s3:ListBucket"}, Resource: "*"},
                    },
                }),
            },
        },
    }
    
    err := client.Create(ctx, cr)
    require.NoError(t, err)
    defer client.Delete(ctx, cr)
    
    // Wait for provisioning
    err = wait.Poll(5*time.Second, 5*time.Minute, func() (bool, error) {
        err := client.Get(ctx, key, cr)
        return err == nil && cr.Status.Provisioned, nil
    })
    require.NoError(t, err)
    
    // Verify Secret created
    secret := &corev1.Secret{}
    err = client.Get(ctx, client.ObjectKey{Name: "test-creds", Namespace: "default"}, secret)
    require.NoError(t, err)
    assert.NotEmpty(t, secret.Data["aws_access_key_id"])
    assert.NotEmpty(t, secret.Data["aws_secret_access_key"])
    
    // Verify cloud IAM user created (AWS API call)
    awsClient := framework.NewAWSClient(t)
    user, err := awsClient.GetUser(&iam.GetUserInput{UserName: aws.String(expectedUserName)})
    require.NoError(t, err)
    assert.NotNil(t, user)
    
    // Cleanup: Delete CR, verify cloud IAM user deleted
    err = client.Delete(ctx, cr)
    require.NoError(t, err)
    
    eventually.Assert(t, func() bool {
        _, err := awsClient.GetUser(&iam.GetUserInput{UserName: aws.String(expectedUserName)})
        return awserr.Code(err) == iam.ErrCodeNoSuchEntityException
    }, 2*time.Minute)
}
```

#### Passthrough Mode E2E

Test that root credential is copied to target secrets when in passthrough mode.

#### Manual + OIDC Mode E2E

1. Run `ccoctl` to create cloud IAM
2. Apply secret manifests
3. Create CredentialsRequest
4. Verify Secret contains cloud config (role ARN, token file path)
5. Deploy test pod, verify it can authenticate to cloud using ServiceAccount token

### Component-Specific E2E Scenarios

**Mode Detection**:
- Install with mint-capable root cred → verify mint mode
- Install with non-mint root cred → verify passthrough mode
- Install without root cred → verify manual mode

**Credential Rotation**:
- Update CredentialsRequest ProviderSpec → verify Secret updated

**Finalizer Cleanup**:
- Delete CredentialsRequest → verify cloud IAM user deleted (mint mode)

**ClusterOperator Status**:
- All CRs provisioned → verify Available=True
- One CR fails → verify Degraded=True

**Multi-Cloud**:
- Run same tests on AWS, Azure, GCP clusters

## Test Coverage

### Current Coverage

```bash
# Generate coverage report
make test
go tool cover -html=coverage.out

# Expected coverage:
# - pkg/operator: 60-70% (controllers)
# - pkg/{aws,azure,gcp}: 50-60% (actuators with mocked APIs)
# - E2E: Critical paths (mint, passthrough, manual modes)
```

### Coverage Gaps

**Known gaps**:
- Limited integration tests (mostly rely on E2E for Kubernetes API testing)
- Not all cloud providers have equal E2E coverage (AWS > Azure > GCP > others)
- Manual + OIDC E2E tests require complex setup (often manual testing)
- Upgrade scenarios (testing mode changes during upgrade)

**Plans**:
- Expand integration tests using envtest
- Improve cloud provider parity in E2E tests
- Automate Manual + OIDC E2E setup

## CI/CD Testing

### PR Testing

CI runs on every PR (Prow):
- **Unit tests** (always): All unit tests with coverage
- **Verify** (always): Code generation, formatting, linting
- **E2E** (always): Basic E2E tests on AWS cluster

See `.ci-operator.yaml` for CI configuration.

### Periodic Testing

Periodic jobs run extended E2E suite:
- **AWS E2E** (daily): Full AWS scenarios (mint, passthrough, STS)
- **Azure E2E** (daily): Full Azure scenarios
- **GCP E2E** (daily): Full GCP scenarios
- **Upgrade E2E** (weekly): Test mode detection during upgrades

## Debugging Failing Tests

### Unit Test Failures

```bash
# Run with verbose output
go test -v ./pkg/operator/credentialsrequest/... -run TestSpecific

# Run with race detector
go test -race ./pkg/...

# Debug specific test
dlv test ./pkg/operator/credentialsrequest -- -test.run TestSpecific
```

### E2E Test Failures

```bash
# Check CCO operator logs
oc logs -n openshift-cloud-credential-operator \
  deployment/cloud-credential-operator

# Check CredentialsRequest status
oc get credentialsrequests -A
oc describe credentialsrequest [name] -n [namespace]

# Check ClusterOperator status
oc get clusteroperator cloud-credential -o yaml

# Check target Secret
oc get secret [name] -n [namespace] -o yaml

# Collect must-gather
oc adm must-gather
```

**Common E2E failures**:
- **Cloud API rate limits**: Retry or use longer timeouts
- **Permissions errors**: Verify root credential has required permissions
- **Finalizer stuck**: Check if cloud resource was deleted externally
- **Secret not created**: Check controller logs for actuator errors

## Component-Specific Test Notes

### Cloud Credentials Required for E2E

**AWS**:
- Root credential with `iam:CreateUser`, `iam:DeleteUser`, `iam:PutUserPolicy`, `iam:CreateAccessKey`
- Or STS-capable environment with OIDC provider

**Azure**:
- Service principal with Application Administrator role
- Or Workload Identity-capable environment

**GCP**:
- Service account with `iam.serviceAccounts.create`, `iam.serviceAccountKeys.create`
- Or Workload Identity-capable environment

### Mock vs Real Cloud APIs

**Unit tests**: Always mock cloud APIs (fast, deterministic)

**E2E tests**: Always use real cloud APIs (verify actual provisioning)

**Integration tests**: Typically mock cloud APIs but use real Kubernetes API

### Known Flaky Tests

**E2E Cloud API Timeouts**:
- Symptom: Timeout waiting for IAM user creation
- Cause: Cloud API slow or rate limited
- Mitigation: Retry or increase timeout

**Finalizer Cleanup Race**:
- Symptom: Finalizer not removed after cloud resource deleted
- Cause: Race between cloud API call and status update
- Mitigation: Add retry logic in test

### Test Environment Requirements

**Unit/Integration**:
- Go 1.23+
- No cluster required (unit tests)
- Test cluster for integration tests (optional)

**E2E**:
- Real OpenShift cluster on cloud provider
- Cloud credentials with IAM permissions
- KUBECONFIG set

## See Also

- [Development Guide](./CCO_DEVELOPMENT.md)
- [Architecture](./architecture/components.md)
- [CredentialsRequest CRD](./domain/credentialsrequest.md)
- [Tier 1 Testing Practices](https://github.com/openshift/enhancements/tree/master/ai-docs/practices/testing)
