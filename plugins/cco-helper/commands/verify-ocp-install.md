---
description: Trigger OCP installation CI jobs for PR pre-merge testing
argument-hint: [RELEASE_VERSION] [PLATFORM] [PR_URL]
plugin: cco-helper
version: 0.1.0
---

# cco-helper:verify-ocp-install

Trigger OpenShift installation CI jobs for Cloud Credential Operator PRs.

## Synopsis
```
cco-helper:verify-ocp-install RELEASE_VERSION [PLATFORM] PR_URL
```

## Arguments
- **RELEASE_VERSION**: Release version (e.g., "4.21", "4.20")
- **PLATFORM**: Platform filter - `aws`, `azure`, `gcp`, or `all` (default: `all`)
- **PR_URL**: PR URL (must be open, not draft)

## Implementation
Executes workflow: `.ai_context/pre-merge-regression-prompts/pre-merge-regression-test-prompt.md`

## Prerequisites
- GitHub CLI (`gh`) authenticated
- Valid open PR (not draft)
- Comment permissions on PR

## Reference
[OpenShift CI /payload-job](https://docs.ci.openshift.org/docs/release-oversight/pull-request-testing/#payload-job)
