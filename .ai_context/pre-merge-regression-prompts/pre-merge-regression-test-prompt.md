---
agent: pre-merge-regression-test
version: 1.0
purpose: Execute pre-merge OCP installation CI testing workflow
invoked-by: /verify-ocp-install command
---

# Pre-Merge Regression Testing for CCO

## Overview

This agent executes the complete workflow for triggering OpenShift Container Platform (OCP) installation CI jobs for Cloud Credential Operator PRs before merging.

**Workflow Duration:** ~5-10 minutes (excluding actual CI job execution)

## Input Requirements

The agent expects user input in the following formats:
- `trigger 4.21 azure CI for <PR_URL>`
- `trigger 4.21 CI for <PR_URL>`
- `/verify-ocp-install 4.21 azure <PR_URL>`

**Required Parameters:**
- Release version (e.g., "4.21", "4.20")
- PR URL
- Platform: aws/azure/gcp/all (default: all)

## Execution Workflow

Execute the following steps sequentially. Do not skip any step.

### Step 1: Extract and Validate Parameters

Extract from user input:
- Release version → `RELEASE_VERSION`
- PR URL (prompt if not provided)
- Platform filter → `PLATFORM` (aws/azure/gcp/all, default: all)

**Action:** Inform user of extracted parameters:
```
✓ Extracted parameters:
  - Release: {RELEASE_VERSION}
  - Platform: {PLATFORM}
  - PR: {PR_URL}
```

### Step 2: Verify PR Status

**Command:**
```bash
gh pr view <PR_URL> --json state,isDraft
```

**Required Result:**
- `"state": "OPEN"`
- `"isDraft": false`

**On Success:** Proceed to Step 3
**On Failure:** Stop execution and inform user with error details

### Step 3: Query and Filter CI Jobs

**Command to get all jobs:**
```bash
gh api "repos/openshift/release/contents/ci-operator/jobs/openshift/cloud-credential-operator/openshift-cloud-credential-operator-release-${RELEASE_VERSION}-periodics.yaml" \
  --jq '.content' | base64 -d | grep "^  name:" | awk '{print $2}'
```

**Filter by platform:**
- **AWS**: `... | grep "aws"`
- **Azure**: `... | grep "azure"`
- **GCP**: `... | grep "gcp"`
- **All**: Use all job names (no filtering)

**Expected Job Types:**
- `e2e-{platform}-manual-oidc` - Manual mode with OIDC/workload identity
- `e2e-{platform}-upgrade` - Upgrade testing
- `e2e-{platform}-*` - Other platform-specific tests

### Step 4: Display Jobs and Request User Confirmation

⚠️ **MANDATORY STEP - DO NOT SKIP**

**Display Format:**
```
Found X job(s) to trigger:
1. periodic-ci-openshift-cloud-credential-operator-release-{VERSION}-periodics-e2e-{platform}-manual-oidc
2. periodic-ci-openshift-cloud-credential-operator-release-{VERSION}-periodics-e2e-{platform}-upgrade
...

Proceed to trigger these jobs? (yes/no)
```

**Requirements:**
1. Display ALL filtered job names to user
2. Ask explicit confirmation: "Proceed to trigger these jobs? (yes/no)"
3. **STOP and WAIT** for user response
4. Only proceed to Step 5 if user responds with "yes"
5. If user responds "no", abort workflow

### Step 5: Trigger CI Jobs

After receiving "yes" confirmation, trigger each job with a **separate comment**.

**Command Pattern:**
```bash
gh pr comment <PR_URL> --body "/payload-job <job-name>"
```

**Example:**
```bash
# Comment 1
gh pr comment <PR_URL> --body "/payload-job periodic-ci-openshift-cloud-credential-operator-release-4.21-periodics-e2e-aws-manual-oidc"

# Comment 2
gh pr comment <PR_URL> --body "/payload-job periodic-ci-openshift-cloud-credential-operator-release-4.21-periodics-e2e-azure-manual-oidc"
```

⚠️ **Critical:** Each `/payload-job` command MUST be in its own separate comment, not multiple commands in one comment.

**On Success:** Proceed to Step 6
**On Failure:** Report error and stop

### Step 6: Monitor Bot Response

After triggering all jobs, the OpenShift CI bot will automatically reply with:
- Confirmation message listing triggered job names
- Link to payload test details page

**Action:** Inform user:
```
✓ All jobs triggered successfully.

The OpenShift CI bot will reply with:
- Confirmation of triggered jobs
- Link to monitor job status

Please check the bot's reply and follow the provided link to track job progress.
```

## Tools Available

You have access to GitHub CLI (`gh`) which is already authenticated.

**Common Commands:**

```bash
# Query available jobs
gh api "repos/openshift/release/contents/ci-operator/jobs/openshift/cloud-credential-operator/openshift-cloud-credential-operator-release-${RELEASE_VERSION}-periodics.yaml" \
  --jq '.content' | base64 -d | grep "^  name:" | awk '{print $2}'

# Check PR status
gh pr view <PR_URL> --json state,isDraft

# Trigger job (one per comment)
gh pr comment <PR_URL> --body "/payload-job <job-name>"

# Abort all jobs (emergency)
gh pr comment <PR_URL> --body "/payload-abort"
```

## Error Handling

**If PR validation fails:**
- Inform user PR must be open and not in draft state
- Provide link to PR for review

**If job query fails:**
- Verify release version is correct
- Check if periodics file exists for that version
- Suggest checking OpenShift release repository

**If job trigger fails:**
- Verify `gh` authentication: `gh auth status`
- Check PR permissions
- Ensure PR is from openshift/cloud-credential-operator (not a fork)

## References

- [OpenShift CI /payload-job Documentation](https://docs.ci.openshift.org/docs/release-oversight/pull-request-testing/#payload-job)
- [OpenShift Release CI Configuration](https://github.com/openshift/release)

## Notes

- Jobs run in OpenShift CI infrastructure
- Typical job duration: 2-3 hours per job
- Jobs run in parallel once triggered
- Monitor job status via link provided by CI bot
- Jobs can be aborted with `/payload-abort` if needed
