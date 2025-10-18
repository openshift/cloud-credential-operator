---
description: Trigger OCP installation CI jobs for PR pre-merge testing
argument-hint: [RELEASE_VERSION] [PLATFORM] [PR_URL]
---

## Name
verify-ocp-install

## Synopsis
```
/verify-ocp-install RELEASE_VERSION [PLATFORM] PR_URL
```

## Description
Trigger OpenShift Container Platform (OCP) installation CI jobs for pre-merge testing of Cloud Credential Operator PRs.

## Implementation
Delegates to plugin command: `cco-helper:verify-ocp-install`

## Examples

1. **Test all platforms**:
   ```
   /verify-ocp-install 4.21 all https://github.com/openshift/cloud-credential-operator/pull/123
   ```

2. **Test specific platform**:
   ```
   /verify-ocp-install 4.21 azure https://github.com/openshift/cloud-credential-operator/pull/123
   ```

## Arguments
- **$1** (required): Release version (e.g., "4.21", "4.20")
- **$2** (optional): Platform - `aws`, `azure`, `gcp`, or `all` (default: `all`)
- **$3** (required): PR URL

## See Also
- Plugin: `cco-helper:verify-ocp-install`
- `/trigger-qe-regression-ci`

---

Execute: `cco-helper:verify-ocp-install {args}`
