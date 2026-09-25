# Test Plan: Simplified ccoctl Upgrade Workflow

**Plan status:** In progress

**Feature:** [OCPSTRAT-3797](https://redhat.atlassian.net/browse/OCPSTRAT-3797)

**Delivery epic:** [CCO-744](https://redhat.atlassian.net/browse/CCO-744)

**Test automation story:** [CCO-765](https://redhat.atlassian.net/browse/CCO-765)

**Target release:** OpenShift 5.1

## 1. Test Plan Identifier

CCO-765 — Simplified upgrade process with automated Secret application and
`upgradeable-to` annotation management.

## 2. References

| Type | Reference |
| --- | --- |
| Feature requirements | [OCPSTRAT-3797](https://redhat.atlassian.net/browse/OCPSTRAT-3797) |
| Component delivery epic | [CCO-744](https://redhat.atlassian.net/browse/CCO-744) |
| Secret application implementation | [cloud-credential-operator#1095](https://github.com/openshift/cloud-credential-operator/pull/1095) |
| Cloud role ordering implementation | [cloud-credential-operator#1104](https://github.com/openshift/cloud-credential-operator/pull/1104) |
| Annotation implementation | [cloud-credential-operator#1105](https://github.com/openshift/cloud-credential-operator/pull/1105) |
| User documentation | [`docs/ccoctl.md`](../ccoctl.md), [`docs/mode-manual-creds.md`](../mode-manual-creds.md) |

## 3. Introduction

Upgrading a cluster that uses CCO manual mode and short-term credentials
previously required administrators to apply generated Secret manifests with a
separate `oc` command and patch the CloudCredential `upgradeable-to` annotation
by hand. The feature adds provider-specific `ccoctl` entry points that perform
those cluster operations directly. It also creates all custom Azure and GCP
roles before identities and role bindings so cloud-side propagation can begin
earlier.

This plan verifies the user-visible command paths for AWS, Azure, and GCP while
retaining focused unit coverage for validation, error handling, and cloud API
ordering.

## 4. Test Items

- `ccoctl aws|azure|gcp apply secrets`
- `ccoctl aws|azure|gcp set-upgradeable-to`
- Azure `create-managed-identities` custom-role preflight
- GCP `create-service-accounts` custom-role preflight
- Generated AWS, Azure, and GCP Secret manifest compatibility
- Existing manual-mode upgrade workflow and documentation

## 5. Features to Be Tested

### Automated component coverage

| ID | Scenario | Layer | Expected result | Status |
| --- | --- | --- | --- | --- |
| U1 | Load single- and multi-document Secret YAML; ignore non-Secrets | Unit | Only valid, namespaced Secrets are selected | Implemented in #1095 |
| U2 | Create a missing Secret and update an existing Secret | Unit | All valid Secrets are attempted and aggregate errors are returned | Implemented in #1095 |
| U3 | Reject malformed manifests, missing names/namespaces, and unexpected arguments | Unit | The command fails before changing the cluster | Implemented in #1095 |
| U4 | Normalize a full release to major.minor and reject malformed, current, or older versions | Unit | Only a future major.minor reaches the patch operation | Implemented in #1105 |
| U5 | Patch only `cloudcredential.openshift.io/upgradeable-to` | Unit | Unrelated metadata and spec fields remain unchanged | Implemented in #1105 |
| U6 | Prepare all Azure custom roles before identity creation or assignment | Unit orchestration | Every role operation precedes identity and binding operations | Partially implemented in #1104; see Risk R2 |
| U7 | Prepare all GCP custom roles before service-account creation or IAM binding | Unit orchestration | Every role operation precedes account and binding operations | Implemented in #1104 |
| U8 | Register `apply secrets` and `set-upgradeable-to` under AWS, Azure, and GCP | Unit command tree | Both commands are discoverable through every supported provider | `pkg/cmd/provisioning/provider_commands_test.go` |

### Live-cluster end-to-end coverage

| ID | Scenario | Environment | Expected result | Automation |
| --- | --- | --- | --- | --- |
| E1 | Run the production `apply secrets` handler with a generated Secret | OpenShift cluster with CCO capability | The Secret is created with the generated data | `test/extend/ccoctl_upgrade.go` |
| E2 | Change the generated data and rerun the production `apply secrets` handler | Same as E1 | The existing Secret is updated | `test/extend/ccoctl_upgrade.go` |
| E3 | Run the production `set-upgradeable-to` handler with the next minor version | Same as E1 | The CloudCredential annotation equals the requested major.minor | `test/extend/ccoctl_upgrade.go` |
| E4 | Restore the pre-test annotation and delete test Secrets | Same as E1 | The cluster returns to its original state | `test/extend/ccoctl_upgrade.go` cleanup |
| E5 | Run provider manual-OIDC installation lanes | AWS, Azure, and GCP manual-OIDC Prow jobs | Existing short-term credential installation remains healthy | Existing Prow lanes |

The E1–E4 test is provider-neutral at the Kubernetes API layer and invokes the
same production handlers used by all three provider trees. U8 separately
verifies provider registration. Together they cover command exposure, flag
handling, kubeconfig resolution, manifest decoding, real API create/update
behavior, version validation, and the annotation patch without requiring
disposable cloud IAM resources.

## 6. Features Not to Be Tested

- Mint and passthrough credential modes; the feature targets manual mode with
  short-term credentials.
- Providers other than AWS, Azure, and GCP.
- Bound service-account signer-key rotation.
- Cloud-provider IAM propagation timing as a performance guarantee. The test
  verifies ordering, not a provider-specific propagation service level.
- A real cluster upgrade across releases. Existing upgrade jobs provide
  regression coverage; this feature changes preparation commands, not CVO's
  upgrade execution.

## 7. Approach

1. Use unit tests for malformed input, partial failures, Kubernetes client
   errors, version edge cases, and cloud-client call ordering.
2. Use the OpenShift test extension for the API-server-backed golden path.
3. Invoke the production shared command constructors instead of duplicating
   their logic in the E2E test, and verify all provider command registrations in
   U8.
4. Use a unique namespace and non-sensitive synthetic Secret data.
5. Calculate the next minor from the cluster under test, then restore the exact
   pre-test annotation value.
6. Run the extension case in `cco/conformance/parallel`, exercised by the
   `e2e-aws-cco-parallel` presubmit. Use the existing Azure and GCP manual-OIDC
   lanes for provider regression signal.

## 8. Pass/Fail Criteria

The feature passes when:

- all component unit tests pass;
- E1–E4 pass against a live OpenShift API server;
- `e2e-aws-cco-parallel`, `e2e-azure-manual-oidc`, and
  `e2e-gcp-manual-oidc` pass on the exact pull request revision;
- the test leaves no namespace, Secret, or annotation changes behind;
- no critical or major unresolved defect remains against the acceptance
  criteria.

Any command error, unexpected Secret data, incorrect annotation, cleanup
failure, or provider regression is a failure.

## 9. Suspension and Resumption Criteria

Suspend feature validation when the cluster API is unavailable, the CCO
capability is absent, a provider CI environment cannot install, or an unrelated
platform incident prevents a representative run. Resume after the environment
is healthy and rerun the affected scenario on the same code revision.

## 10. Test Deliverables

- This Markdown test plan.
- Component unit tests delivered by #1095, #1104, and #1105.
- Live-cluster command-path coverage in `test/extend/ccoctl_upgrade.go`.
- Prow results for the pull request revision.
- Jira links to the plan, automation pull request, and final CI evidence.

## 11. Testing Tasks

| Task | Owner | State |
| --- | --- | --- |
| Review and merge implementation unit coverage | CCO maintainers | Complete |
| Add API-server-backed command-path coverage | CCO QE | In progress |
| Review this plan against OCPSTRAT-3797 acceptance criteria | CCO team | Pending |
| Run feature-specific and provider regression CI | CCO QE / CI | Pending |
| Attach plan and results to OCPSTRAT-3797 and CCO-765 | CCO QE | Pending |

## 12. Environmental Needs

- OpenShift cluster with the CCO capability enabled.
- Cluster-admin kubeconfig for the test extension.
- `cloudcredential.operator.openshift.io/cluster` and
  `clusterversion.config.openshift.io/version` resources.
- AWS cluster for the CCO extension presubmit.
- Azure and GCP manual-OIDC presubmit environments for provider regressions.
- No production credentials or user data are used by E1–E4.

## 13. Responsibilities

- CCO QE owns the plan, E2E automation, execution evidence, and Jira linkage.
- CCO maintainers review command behavior and test implementation.
- CI/platform owners provide healthy disposable test environments.
- Documentation owners validate the user-facing upgrade instructions.

## 14. Staffing and Training Needs

No additional staffing or training is required. Reviewers should understand
CCO manual mode, `ccoctl`, OpenShift test extensions, and provider manual-OIDC
CI lanes.

## 15. Schedule

The plan, automation, and initial presubmit validation are targeted for the
OpenShift 5.1 development window. Provider regression evidence must be captured
before CCO-765 is resolved.

## 16. Risks and Contingencies

| ID | Risk | Mitigation |
| --- | --- | --- |
| R1 | A green provider lane proves only regression health if the new command is not selected | Require E1–E4 and inspect the extension JUnit entry by name |
| R2 | Azure #1104 tests the role-preflight helper but not the full multi-request orchestrator ordering | Add a follow-up orchestrator-level test if review requires stronger cloud-client ordering proof |
| R3 | A failed test could leave the singleton annotation changed | Register cleanup immediately after reading the original value and report cleanup errors |
| R4 | Running the same namespace name concurrently could collide | Generate a random namespace per execution |
| R5 | Provider IAM APIs are eventually consistent | Verify ordering deterministically in unit tests and use existing manual-OIDC lanes for live regression evidence |

## 17. Approvals

Approval is recorded through pull request review and CCO-765/OCPSTRAT-3797
acceptance. No separate sign-off document is required.
