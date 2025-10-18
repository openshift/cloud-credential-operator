---
description: Trigger QE regression CI jobs to identify potential issues
argument-hint: None
---

## Name
trigger-qe-regression-ci

## Synopsis
```
/trigger-qe-regression-ci
```

## Description
Trigger QE (Quality Engineering) regression CI jobs to identify potential issues and assess whether related changes might impact other components.

## Implementation
Delegates to plugin command: `cco-helper:trigger-qe-regression-ci`

## Examples

1. **Basic usage**:
   ```
   /trigger-qe-regression-ci
   ```

## Arguments
None - operates on current branch/PR context

## See Also
- Plugin: `cco-helper:trigger-qe-regression-ci`
- `/verify-ocp-install`

---

Execute: `cco-helper:trigger-qe-regression-ci`
