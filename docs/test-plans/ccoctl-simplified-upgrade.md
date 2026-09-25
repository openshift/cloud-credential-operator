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
| Upgrade CI implementation | [openshift/release#85981](https://github.com/openshift/release/pull/85981) |
| Manual credentials upgrade procedure | [Preparing to update a cluster with manually maintained credentials](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/updating_clusters/preparing-to-update-a-cluster#about-manually-maintained-credentials-upgrade_preparing-manual-creds-update) |
| User documentation | [`docs/ccoctl.md`](../ccoctl.md), [`docs/mode-manual-creds.md`](../mode-manual-creds.md) |

## 3. Introduction

Upgrading a cluster that uses CCO manual mode and short-term credentials
previously required administrators to apply generated Secret manifests with a
separate `oc` command and patch the CloudCredential `upgradeable-to` annotation
by hand. The feature adds provider-specific `ccoctl` entry points that perform
those cluster operations directly. It also creates all custom Azure and GCP
roles before identities and role bindings so cloud-side propagation can begin
earlier.

This plan verifies the complete documented upgrade path on AWS, Azure, and GCP:
install a cluster with manually maintained short-term credentials, prepare the
target-release cloud resources, apply the generated Secrets, mark the cluster
upgradeable, and complete a cross-minor OpenShift upgrade. Focused unit coverage
continues to verify validation, error handling, and cloud API ordering.

## 4. Test Items

- `ccoctl aws|azure|gcp apply secrets`
- `ccoctl aws|azure|gcp set-upgradeable-to`
- Azure `create-managed-identities` custom-role preflight
- GCP `create-service-accounts` custom-role preflight
- Generated AWS, Azure, and GCP Secret manifest compatibility
- AWS manual OIDC STS cross-minor upgrade workflow
- Azure and GCP manual OIDC workload identity cross-minor upgrade workflows

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

### Live-cluster end-to-end coverage

| ID | Scenario | Environment | Expected result | Automation |
| --- | --- | --- | --- | --- |
| E1 | Install the initial release with manually maintained OIDC credentials | AWS STS | The cluster installs and operators authenticate with generated short-term credentials | `e2e-aws-manual-oidc-upgrade` |
| E2 | Install the initial release with manually maintained workload identity credentials | Azure | The cluster installs and operators authenticate with generated federated identities | `e2e-azure-manual-oidc-upgrade` |
| E3 | Install the initial release with manually maintained workload identity credentials | GCP | The cluster installs and operators authenticate with generated workload identities | `e2e-gcp-manual-oidc-upgrade` |
| E4 | Extract target-release CredentialsRequests and update provider resources | Each E1–E3 cluster | Target-release identities, roles, policies, and bindings are prepared without replacing required existing resources | Provider-specific upgrade credential step in #85981 |
| E5 | Run `ccoctl <provider> apply secrets` and `set-upgradeable-to` | Each E1–E3 cluster | Generated Secrets are applied and CCO reports `Upgradeable=True` for the target release | Provider-specific upgrade credential step in #85981 |
| E6 | Run the OpenShift upgrade suite from stable 5.0 to 5.1 | Each E1–E3 cluster | The cluster completes the upgrade and standard upgrade assertions pass | Provider-specific workflow in #85981 |

The three workflows invoke the production provider command trees and exercise
real cloud IAM resources, generated Secret manifests, kubeconfig handling,
version normalization, the CloudCredential annotation, and CVO upgrade behavior
as one end-to-end flow.

## 6. Features Not to Be Tested

- Mint and passthrough credential modes; the feature targets manual mode with
  short-term credentials.
- Providers other than AWS, Azure, and GCP.
- Same-minor and z-stream upgrades; the feature gate is exercised through a
  cross-minor stable 5.0 to 5.1 upgrade.
- Bound service-account signer-key rotation.
- Cloud-provider IAM propagation timing as a performance guarantee. The test
  verifies ordering, not a provider-specific propagation service level.

## 7. Approach

1. Use unit tests for malformed input, partial failures, Kubernetes client
   errors, version edge cases, and cloud-client call ordering.
2. Reuse the existing provider manual-OIDC installation and teardown chains.
3. Before the upgrade suite, extract target-release CredentialsRequests, update
   the provider resources with `ccoctl`, apply the generated Secrets, and set
   the target version through `set-upgradeable-to`.
4. Assert that the cloud-credential ClusterOperator reports
   `Upgradeable=True` before invoking the standard OpenShift upgrade test.
5. Execute equivalent workflows for AWS, Azure, and GCP using release registry
   naming conventions and generated Prow configuration.

## 8. Pass/Fail Criteria

The feature passes when:

- all component unit tests pass;
- E1–E6 pass for `e2e-aws-manual-oidc-upgrade`,
  `e2e-azure-manual-oidc-upgrade`, and `e2e-gcp-manual-oidc-upgrade` on the
  exact pull request revision;
- every provider workflow completes its post chain and removes cloud resources;
- no critical or major unresolved defect remains against the acceptance
  criteria.

Any command error, cloud IAM preparation failure, incorrect Secret or
annotation, blocked/failed upgrade, cleanup failure, or provider regression is
a failure.

## 9. Suspension and Resumption Criteria

Suspend feature validation when the cluster API is unavailable, the CCO
capability is absent, a provider CI environment cannot install, or an unrelated
platform incident prevents a representative run. Resume after the environment
is healthy and rerun the affected scenario on the same code revision.

## 10. Test Deliverables

- This Markdown test plan.
- Component unit tests delivered by #1095, #1104, and #1105.
- Three-platform upgrade automation delivered by openshift/release#85981.
- Prow results for the pull request revision.
- Jira links to the plan, automation pull request, and final CI evidence.

## 11. Testing Tasks

| Task | Owner | State |
| --- | --- | --- |
| Review and merge implementation unit coverage | CCO maintainers | Complete |
| Add AWS, Azure, and GCP cross-minor upgrade workflows | CCO QE | In review in openshift/release#85981 |
| Review this plan against OCPSTRAT-3797 acceptance criteria | CCO team | Pending |
| Run feature-specific and provider regression CI | CCO QE / CI | Pending |
| Attach plan and results to OCPSTRAT-3797 and CCO-765 | CCO QE | Pending |

## 12. Environmental Needs

- AWS, Azure, and GCP cluster profiles used by the release CI manual-OIDC lanes.
- Stable 5.0 initial and 5.1 target release payloads.
- Disposable cloud projects/subscriptions/accounts with permissions to create
  and remove the identities, roles, policies, and bindings required by CCO.
- Cluster-admin kubeconfig generated by each installation workflow.
- No production credentials or user data are used.

## 13. Responsibilities

- CCO QE owns the plan, E2E automation, execution evidence, and Jira linkage.
- CCO maintainers review command behavior and test implementation.
- CI/platform owners provide healthy disposable test environments.
- Documentation owners validate the user-facing upgrade instructions.

## 14. Staffing and Training Needs

No additional staffing or training is required. Reviewers should understand
CCO manual mode, `ccoctl`, provider manual-OIDC CI lanes, and OpenShift upgrade
testing.

## 15. Schedule

The plan, automation, and initial presubmit validation are targeted for the
OpenShift 5.1 development window. Provider regression evidence must be captured
before CCO-765 is resolved.

## 16. Risks and Contingencies

| ID | Risk | Mitigation |
| --- | --- | --- |
| R1 | A green provider install lane proves only regression health if the new commands are not selected | Require the provider upgrade credential step before `openshift-e2e-test` in each workflow and inspect its Prow output |
| R2 | Azure #1104 tests the role-preflight helper but not the full multi-request orchestrator ordering | Add a follow-up orchestrator-level test if review requires stronger cloud-client ordering proof |
| R3 | A failed upgrade could leave cloud resources behind | Always run the existing provider post chain as a best-effort post step |
| R4 | Target CredentialsRequests can introduce new provider resources | Extract from the exact target payload and preserve existing Azure roles while reconciling requested resources |
| R5 | Provider IAM APIs are eventually consistent | Verify ordering deterministically in unit tests and exercise the real provider path before the upgrade |

## 17. Approvals

Approval is recorded through pull request review and CCO-765/OCPSTRAT-3797
acceptance. No separate sign-off document is required.
