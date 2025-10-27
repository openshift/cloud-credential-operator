# Code Review Automation

Perform a comprehensive code review of the current changes in this repository. Follow these steps:

1. **Analyze Changes**: Run `git diff` and `git status` to understand what has been modified
2. **Review Scope**: Determine which components are affected (operator, ccoctl, cloud providers, controllers, etc.)
3. **Code Quality Checks**:
   - Go best practices and idiomatic patterns
   - Error handling completeness
   - Nil pointer checks
   - Resource cleanup (defer statements, context cancellation)
   - Concurrent access safety (mutex usage, race conditions)
   - Memory leaks (unclosed resources, goroutine leaks)

4. **Project-Specific Requirements**:
   - Controller patterns: proper Reconcile() return values, requeue logic, condition updates
   - Cloud provider implementations: actuator interface compliance
   - API changes: ensure CRD generation is needed (`make update-codegen`)
   - Bindata updates: check if manifest changes require `make update-bindata`
   - Vendor updates: verify `go.mod` and `vendor/` are in sync
   - Testing: ensure unit tests cover new code paths

5. **Security & Credentials**:
   - Proper credential handling (no hardcoded secrets, secure storage)
   - RBAC compliance for Kubernetes operations
   - Cloud provider permissions (least privilege)
   - Sensitive data not logged

6. **Documentation & Comments**:
   - Public functions/types have godoc comments
   - Complex logic is explained
   - TODO/FIXME comments are justified
   - CLAUDE.md updates if workflow changes

7. **Testing Requirements**:
   - Unit tests for new functions
   - Mock implementations for cloud provider testing
   - E2E test considerations for cloud-specific changes
   - Build tag usage (`e2e` for e2e tests)

8. **Common Pitfalls**:
   - Missing `-mod=vendor` in test commands
   - Unhandled errors in reconciliation loops
   - Missing status condition updates
   - Event emission for important state changes
   - Missing file path references (file:line format)

Provide actionable feedback with specific file:line references for each issue found. Categorize findings as:
- **Critical**: Must fix (bugs, security issues, breaking changes)
- **Important**: Should fix (code quality, best practices)
- **Suggestions**: Consider (optimizations, alternative approaches)

After the review, suggest which tests should be run:
- `make test` for unit tests
- `make verify` for verification checks
- `make test-e2e-sts` or `make test-e2e-azident` for cloud-specific changes
