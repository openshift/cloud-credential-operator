# AI Context for Cloud Credential Operator (CCO)

This directory contains AI-assisted prompts for CCO.

## Directory Structure

### `pre-merge-regression-prompts/`

**File Structure:**
```
pre-merge-regression-prompts/
├── CLAUDE.md                              # Claude AI entry point
├── GEMINI.md                              # Gemini AI entry point  
├── CLINE.md                               # Cline AI entry point
├── .cursorrules                           # Cursor IDE
└── pre-merge-regression-test-prompt.md    # Complete workflow prompt
```

#### What This Does
CCO releases include EPICs such as:
- Kubernetes version upgrades (e.g., Upgrade to Kubernetes 1.34)
- Regular Maintenance for each release

Each EPIC requires regression testing that includes:
- Checking CI e2e test results
- Manually run some cases if required
- Testing new features if required
- Validating across multiple platforms

Provides a workflow to trigger CI regression testing for pre-merge validation.

Core function:
- Triggers ad-hoc Prow jobs using `/payload-job` commands to run CI regression tests on PR branches

#### When to Use
Use this prompt for:
- Kubernetes upgrade EPICs (e.g., K8s 1.34, 1.35)
- Regular maintenance for each release
- Platform-specific changes requiring regression validation
- Any PR needing pre-merge regression testing

#### Usage

Each AI-specific file references the main workflow in `pre-merge-regression-test-prompt.md`.

**Example usage:**
```
User: "trigger 4.21 azure CI for https://github.com/openshift/cloud-credential-operator/pull/123"
AI: [Follows the 6-step workflow from pre-merge-regression-test-prompt.md]
```