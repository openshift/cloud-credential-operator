---
description: Trigger QE regression CI jobs to identify potential issues
argument-hint: None
plugin: cco-helper
version: 0.1.0
---

# cco-helper:trigger-qe-regression-ci

Trigger QE regression CI jobs for Cloud Credential Operator testing.

## Synopsis
```
cco-helper:trigger-qe-regression-ci
```

## Arguments
None - operates on current branch/PR context

## Implementation
Triggers regression test suite covering:
- Cloud providers: AWS, Azure, GCP
- Auth modes: Manual, Mint, Passthrough, OIDC/Workload Identity
- Scenarios: Installation, upgrades, credential rotation, error handling

Typical duration: 30-60 minutes

## Prerequisites
- GitHub CLI (`gh`) authenticated
- Valid CI/CD configuration
- Trigger permissions
