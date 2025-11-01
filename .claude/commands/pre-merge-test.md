---
description: Trigger CI jobs for pre-merge testing of CCO PRs 
argument-hint: [RELEASE_VERSION] [TEST_TYPE] [PR_URL]
---

## Name
pre-merge-test

## Synopsis
```
/pre-merge-test [RELEASE_VERSION] [TEST_TYPE] [PR_URL]
```

## Description
For each release, CCO includes EPICs, user stories, or OCP bugs such as:
- Kubernetes upgrades (e.g., Upgrade to Kubernetes 1.34)
- Regular Maintenance, https://issues.redhat.com/browse/CCO-718   
- For bug verification, many bugs or CVE bugs require multi-version backports. For these cases, QE typically builds a custom image that includes the PR code change and installs OCP on the relevant cluster types (e.g., AWS STS, GCP OIDC) to verify the fix.  

Each requires regression testing that includes:
- Validating the installation success of different types of OCP clusters
- Reviewing related e2e regression test results for anomalies
- Manually running test cases when required

## Implementation
### Step 1: Extract and Validate Parameters

Extract from user input:
- Release version → `RELEASE_VERSION`
- PR URL (prompt if not provided)
- Test type filter → `TEST_TYPE` (see supported types below, default: all)

Supported TEST_TYPE values:
- Single type: `aws`, `aws-sts-install`, `aws-sts-e2e`, `azure`, `azure-oidc-install`, `azure-oidc-e2e`, `gcp`, `gcp-oidc-install`, `gcp-oidc-e2e`, `vsphere`, `ibmcloud`
- Multiple types: `aws,azure` or `aws-sts-install,azure-oidc-e2e` (comma-separated)
- `all` - All related jobs

**Parse TEST_TYPE and define type descriptions:**
```bash
# Convert TEST_TYPE to array, handling comma-separated values
IFS=',' read -r -a TEST_TYPES <<< "$TEST_TYPE"

# Define type descriptions mapping
declare -A TYPE_DESCRIPTIONS=(
    ["aws"]="AWS mint mode job(s)"
    ["aws-sts-install"]="AWS STS install job(s)"
    ["aws-sts-e2e"]="AWS STS test job(s)"
    ["azure"]="Azure passthrough mode job(s)"
    ["azure-oidc-install"]="Microsoft Entra Workload ID install job(s)"
    ["azure-oidc-e2e"]="Microsoft Entra Workload ID job(s)"
    ["gcp"]="GCP mint mode job(s)"
    ["gcp-oidc-install"]="GCP OIDC install job(s)"
    ["gcp-oidc-e2e"]="GCP OIDC test job(s)"
    ["vsphere"]="vSphere job(s)"
    ["ibmcloud"]="IBM Cloud job(s)"
    ["all"]="All related jobs"
)

# Get description for summary comment using the mapping
TEST_TYPES_DESC=""
for type in "${TEST_TYPES[@]}"; do
    desc="${TYPE_DESCRIPTIONS[$type]}"
    if [[ -n "$TEST_TYPES_DESC" ]]; then
        TEST_TYPES_DESC="$TEST_TYPES_DESC, $desc"
    else
        TEST_TYPES_DESC="$desc"
    fi
done
```

Action: Inform user of extracted parameters:
```
✓ Extracted parameters:
  - Release: {RELEASE_VERSION}
  - Test types: {TEST_TYPES[*]}
  - PR: {PR_URL}
```
### Step 2: Verify PR Status

Command:
```bash
gh pr view <PR_URL> --json state,isDraft
```

Required Result:
- `"state": "OPEN"`
- `"isDraft": false`

On Success: Proceed to Step 3
On Failure: Stop execution and inform user with error details

### Step 3: Query and Filter CI Jobs

**IMPORTANT: Determine which job types to query based on TEST_TYPE:**

- **If TEST_TYPE = "all"**: Query these specific types only: `aws`, `aws-sts-e2e`, `azure`, `azure-oidc-e2e`, `gcp`, `gcp-oidc-e2e`, `vsphere`, `ibmcloud`
  - ⚠️ **Note**: `all` does NOT include `-install` jobs (`aws-sts-install`, `azure-oidc-install`, `gcp-oidc-install`) because the corresponding `-e2e` jobs already provide full install + regression test coverage.

- **If TEST_TYPE is comma-separated** (e.g., "aws,azure" or "aws-sts-install,gcp-oidc-e2e"): Query only the types listed

- **If TEST_TYPE is a single type**: Query only that specific type

**MANDATORY Implementation:**
1. Loop through the TEST_TYPES array from Step 1
2. For each type in the array, execute its corresponding job query command **in parallel**
3. Collect all job results into a single list

**Available job query commands for each type:**

#### AWS Jobs

**aws** - AWS mint mode jobs:
```bash
gh api repos/openshift/release/contents/ci-operator/jobs/openshift/openshift-tests-private/openshift-openshift-tests-private-release-${RELEASE_VERSION}-periodics.yaml --jq '.download_url' | xargs curl -s | grep -E "^  name:.*amd64.*nightly.*aws.*private" | grep -v upgrade | grep -v '\-sts\-' | grep -vE "(rosa|hive|hypershift|longduration|ota|usgov)" | sed 's/^  name: //' | sort
```

**aws-sts-install** - AWS STS install verification jobs (install only):
```bash
# Cloud credential operator jobs
gh api "repos/openshift/release/contents/ci-operator/jobs/openshift/cloud-credential-operator/openshift-cloud-credential-operator-release-${RELEASE_VERSION}-periodics.yaml" --jq '.content' | base64 -d | grep "^  name:.*aws" | sed 's/^  name: //'
```

**aws-sts-e2e** - AWS STS full test jobs (install + e2e regression):
```bash
# AWS USGov STS jobs
gh api repos/openshift/release/contents/ci-operator/jobs/openshift/openshift-tests-private/openshift-openshift-tests-private-release-${RELEASE_VERSION}-periodics.yaml --jq '.download_url' | xargs curl -s | grep -E "^  name:.*nightly.*aws-usgov.*sts" | grep -vE "(upgrade|destructive|hypershift)" | sed 's/^  name: //' | sort
```

#### Azure Jobs

**azure** - Azure passthrough mode jobs:
```bash
gh api repos/openshift/release/contents/ci-operator/jobs/openshift/openshift-tests-private/openshift-openshift-tests-private-release-${RELEASE_VERSION}-periodics.yaml --jq '.download_url' | xargs curl -s | grep -E "^  name:.*amd64.*nightly.*azure.*mag.*fips" | grep -vE "(upgrade|destructive|hypershift)" | sed 's/^  name: //' | sort
```

**azure-oidc-install** - Azure OIDC install verification jobs (install only):
```bash
# Cloud credential operator jobs
gh api "repos/openshift/release/contents/ci-operator/jobs/openshift/cloud-credential-operator/openshift-cloud-credential-operator-release-${RELEASE_VERSION}-periodics.yaml" --jq '.content' | base64 -d | grep "^  name:.*azure" | sed 's/^  name: //'
```

**azure-oidc-e2e** - Azure OIDC full test jobs (install + e2e regression):
```bash
# Private tests
gh api repos/openshift/release/contents/ci-operator/jobs/openshift/openshift-tests-private/openshift-openshift-tests-private-release-${RELEASE_VERSION}-periodics.yaml --jq '.download_url' | xargs curl -s | grep -E "^  name:.*amd.*nightly.*azure.*oidc" | grep -vE "(upgrade|destructive|hypershift)" | sed 's/^  name: //' | sort
```

#### GCP Jobs

**gcp** - GCP mint mode jobs:
```bash
gh api repos/openshift/release/contents/ci-operator/jobs/openshift/openshift-tests-private/openshift-openshift-tests-private-release-${RELEASE_VERSION}-periodics.yaml --jq '.download_url' | xargs curl -s | grep -E "^  name:.*gcp.*filestore" | grep -i fips | sed 's/^  name: //' | sort
```

**gcp-oidc-install** - GCP OIDC install verification jobs (install only):
```bash
gh api "repos/openshift/release/contents/ci-operator/jobs/openshift/cloud-credential-operator/openshift-cloud-credential-operator-release-${RELEASE_VERSION}-periodics.yaml" --jq '.content' | base64 -d | grep "^  name:.*gcp" | sed 's/^  name: //'
```

**gcp-oidc-e2e** - GCP OIDC full test jobs (install + e2e regression):
```bash
gh api repos/openshift/release/contents/ci-operator/jobs/openshift/openshift-tests-private/openshift-openshift-tests-private-release-${RELEASE_VERSION}-periodics.yaml --jq '.download_url' | xargs curl -s | grep -E "^  name:.*amd64.*nightly.*gcp.*oidc" | grep -vE "(upgrade|destructive)" | sed 's/^  name: //' | sort
```

#### vSphere Jobs

**vsphere** - vSphere jobs:
```bash
gh api repos/openshift/release/contents/ci-operator/jobs/openshift/openshift-tests-private/openshift-openshift-tests-private-release-${RELEASE_VERSION}-periodics.yaml --jq '.download_url' | xargs curl -s | grep -E "^  name:.*amd64.*nightly.*vsphere-ipi.*sanity" | sed 's/^  name: //' | sort
```

#### IBM Cloud Jobs

**ibmcloud** - IBM Cloud jobs:
```bash
gh api repos/openshift/release/contents/ci-operator/jobs/openshift/openshift-tests-private/openshift-openshift-tests-private-release-${RELEASE_VERSION}-periodics.yaml --jq '.download_url' | xargs curl -s | grep -E "^  name:.*amd64.*nightly.*ibmcloud.*mini-perm" | grep -v upgrade | sed 's/^  name: //' | sort
```


### Step 4: Display Jobs and Request User Confirmation

⚠️ **MANDATORY STEP - DO NOT SKIP**

First, display all filtered jobs to the user:
```
Found X job(s) to trigger:
1. periodic-ci-openshift-cloud-credential-operator-release-{VERSION}-xxx-*
2. periodic-ci-openshift-cloud-credential-operator-release-{VERSION}-xxx-*
3. periodic-ci-openshift-cloud-credential-operator-release-{VERSION}-xxx-*
...
```

Then, ask user for confirmation with these options:
1. **Yes** - Trigger all listed jobs
2. **No** - Cancel the workflow

(Users can also provide custom input to modify the job list)

**Requirements:**
1. Display ALL filtered job names to user before asking for confirmation
2. Use AskUserQuestion tool for confirmation (not text-based yes/no)
3. **STOP and WAIT** for user response from the tool
4. Handle user responses:
   - **"Yes"**: Proceed to Step 5 and trigger all jobs
   - **"No"**: Cancel workflow and inform user that no jobs will be triggered
   - **Custom text input**: Parse user input to handle custom requests such as:
     - Select specific jobs by indices (e.g., "1,3,5" or "only 1 and 3")
     - Exclude specific jobs (e.g., "skip job 2" or "exclude azure")
     - Other modifications to the job list
     - After updating the list, display the modified jobs and ask for confirmation again
     - If unclear, ask for clarification

### Step 5: Trigger CI Jobs

After receiving "yes" confirmation, trigger each job with a **separate comment**.

**Command Pattern:**
```bash
gh pr comment <PR_URL> --body "/payload-job <job-name>"
```

**Example:**
```bash
# Comment 1
gh pr comment <PR_URL> --body "/payload-job periodic-ci-openshift-cloud-credential-operator-release-4.21-periodics-aws-pod-identity-webhook-*"

# Comment 2
gh pr comment <PR_URL> --body "/payload-job periodic-ci-openshift-cloud-credential-operator-release-4.21-periodics-azure-pod-identity-webhook-*"

# Comment 3
gh pr comment <PR_URL> --body "/payload-job periodic-ci-openshift-cloud-credential-operator-release-4.21-periodics-gcp-pod-identity-webhook-*"
```

⚠️ **MANDATORY:** Each `/payload-job` command MUST be in its own separate comment, not multiple commands in one comment.

**On Success:** Proceed to Step 6
**On Failure:** Report error and stop

### Step 6: Post Summary Comment to PR

After all individual `/payload-job` commands have been posted, add a **single summary comment** to the PR listing all triggered jobs.

**Command Pattern:**
```bash
# Use TEST_TYPES_DESC from Step 1 (already defined with proper descriptions)
gh pr comment <PR_URL> --body "$(cat <<EOF
Pre-merge CI tests triggered for release ${RELEASE_VERSION} (test types: ${TEST_TYPES_DESC})

Triggered jobs:
1. <job-name-1>
2. <job-name-2>
3. <job-name-3>
...

Monitor the comments above for job execution status.
EOF
)"
```

**Examples:**

**For specific test types:**
```bash
# TEST_TYPE = "aws,azure" -> TEST_TYPES_DESC = "AWS mint mode job(s), Azure passthrough mode jobs"
gh pr comment <PR_URL> --body "$(cat <<EOF
Pre-merge CI tests triggered for release 4.21 (test types: ${TEST_TYPES_DESC})

Triggered jobs:
1. periodic-ci-openshift-openshift-tests-private-release-4.21-amd64-nightly-aws-ipi-private-fips-f28
2. periodic-ci-openshift-openshift-tests-private-release-4.21-amd64-nightly-azure-ipi-mag-fips-f28

Monitor the comments above for job execution status.
EOF
)"
```

**For all test types:**
```bash
# TEST_TYPE = "all" -> TEST_TYPES_DESC = "All related jobs"
gh pr comment <PR_URL> --body "$(cat <<EOF
Pre-merge CI tests triggered for release 4.21 (test types: ${TEST_TYPES_DESC})

Triggered jobs:
1. periodic-ci-openshift-openshift-tests-private-release-4.21-amd64-nightly-aws-ipi-private-fips-f28
2. periodic-ci-openshift-openshift-tests-private-release-4.21-amd64-nightly-aws-sts-e2e-f28
3. periodic-ci-openshift-openshift-tests-private-release-4.21-amd64-nightly-azure-ipi-mag-fips-f28
...

Monitor the comments above for job execution status.
EOF
)"
```

### Step 7: Workflow Completion

After posting the summary comment:
1. Display confirmation message to user with triggered job summary
2. Inform user to monitor PR comments for job execution status
3. End workflow

**Example user confirmation message:**
```
✅ Workflow completed for PR <PR_URL>
✅ Triggered CI jobs for ${TEST_TYPE} testing on release ${RELEASE_VERSION}

Monitor the PR comments for job execution results and status updates.
```

## Examples

1. **Test all regression jobs**:
   ```bash
   /pre-merge-test 4.21 all https://github.com/openshift/cloud-credential-operator/pull/123
   ```

2. **Test single type - AWS mint mode jobs**:
   ```bash
   /pre-merge-test 4.21 aws https://github.com/openshift/cloud-credential-operator/pull/123
   ```

3. **Test multiple types - AWS and Azure**:
   ```bash
   /pre-merge-test 4.21 aws,azure https://github.com/openshift/cloud-credential-operator/pull/123
   ```

4. **Test multiple types - AWS, GCP, and vSphere**:
   ```bash
   /pre-merge-test 4.21 aws,gcp,vsphere https://github.com/openshift/cloud-credential-operator/pull/123
   ```

5. **Test AWS STS install and Azure OIDC e2e jobs**:
   ```bash
   /pre-merge-test 4.21 aws-sts-install,azure-oidc-e2e https://github.com/openshift/cloud-credential-operator/pull/123
   ```

## Arguments
- **$1** (required): Release version (e.g., "4.21", "4.20")
- **$2** (optional): Test type filter - single type or comma-separated multiple types like `aws,azure` or `aws-sts-install,azure-oidc-e2e`. Supported types: `aws`, `aws-sts-install`, `aws-sts-e2e`, `azure`, `azure-oidc-install`, `azure-oidc-e2e`, `gcp`, `gcp-oidc-install`, `gcp-oidc-e2e`, `vsphere`, `ibmcloud`, or `all` (default: `all`)
- **$3** (required): PR URL
