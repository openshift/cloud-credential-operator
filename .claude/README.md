# CCO Slash Commands

This directory contains slash commands for the Cloud Credential Operator (CCO) repository.

## Features
- Pre-merge regression testing for EPICs, user stories, or bugs

## Prerequisites
- Claude Code installed
- `gh` installed

## Available Commands

### `/pre-merge-test`
Triggers ad-hoc Prow jobs using `/payload-job` commands to run CI regression tests on PR branches.

#### What This Does

Automates pre-merge regression testing for CCO releases including Kubernetes upgrades, regular maintenance EPICs, and bug fixes. Triggers comprehensive CI jobs across multiple cloud platforms to validate installation success and test for anomalies.

#### When to Use
Use this command for:
- **Kubernetes upgrade EPICs** (e.g., K8s 1.34, 1.35)
- **Regular maintenance EPICs** for each release
- **Bug fixes and CVE patches** requiring multi-platform validation
- **Any PR** needing pre-merge installation regression testing across cloud platforms

#### Usage
```bash
/pre-merge-test RELEASE_VERSION [TEST_TYPE] PR_URL
```

See [pre-merge-test.md](commands/pre-merge-test.md) for detailed implementation steps and command reference.
