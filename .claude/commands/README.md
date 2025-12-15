# OTE Migration Slash Command

This directory contains a Claude Code slash command to help automate OpenShift Tests Extension (OTE) migration for component repositories.

## Available Command

### `/migrate-ote`

**Purpose**: Perform the complete OTE migration from start to finish in a single, guided workflow.

**Usage**:
```
/migrate-ote
```

**What it does**:

The command walks you through a comprehensive migration process with 8 phases:

**Phase 1: Cleanup**
- Prepares for migration (no files to delete in current version)

**Phase 2: User Input Collection** (9 inputs with validation)
1. Extension name
2. Working directory (create/use existing)
3. Git status validation (if existing directory)
4. Source repository URL
5. Target repository URL
6. Source test file path (default: `test/extended/`)
7. Source testdata path (default: `test/extended/testdata/`)
8. **⭐ Destination test path** (default: `test/e2e/`) - CUSTOMIZABLE
9. **⭐ Destination testdata path** (default: `test/testdata/`) - CUSTOMIZABLE

**Phase 3: Repository Setup**
- Clones or updates source repository
- Clones or updates target repository

**Phase 4: Structure Creation**
- Creates `tests-extension/` directory
- Creates `cmd/` and user-specified test directories
- Copies test files to custom destination
- Copies testdata to custom destination

**Phase 5: Code Generation**
- Generates `go.mod`
- Generates `cmd/<extension-name>/main.go` with custom import paths
- Creates `bindata.mk` with custom testdata path
- Creates `Makefile` with custom testdata path
- Creates `fixtures.go` in custom testdata path

**Phase 6: Bingo Setup**
- Sets up `.bingo/` directory for go-bindata
- Creates go-bindata version pinning files
- Configures Makefile integration (no need to install bingo!)

**Phase 7: Test Migration**
- Adds testdata import to test files
- Replaces `compat_otp.FixturePath()` calls with `testdata.FixturePath()`
- Updates imports to use custom paths

**Phase 8: Documentation**
- Generates comprehensive migration summary
- Provides next steps and validation guide
- Lists all created files and configuration

**When to use**:
- When ready to migrate a component repository to OTE
- To create a new tests-extension from scratch
- To set up OTE integration with customizable paths

**Output**:
- Complete `tests-extension/` directory structure
- Generated code files (main.go, go.mod, Makefile, fixtures.go)
- Cloned repositories in `repos/` directory
- Bingo configuration for reproducible builds
- Comprehensive migration summary with next steps

---

## Key Features

### ⭐ Customizable Destination Paths

The migration supports fully customizable destination paths:

**Test files destination:**
- Default: `test/e2e/`
- Can be customized to any relative path (e.g., `pkg/tests/`, `test/integration/`)

**Testdata destination:**
- Default: `test/testdata/`
- Can be customized to any relative path (e.g., `pkg/testdata/`, `test/fixtures/`)

All generated code (main.go, Makefile, bindata.mk) will use your custom paths.

### 🔄 Repository Management

The command automatically handles repository cloning and updating:

**First run:**
- Clones source and target repositories from provided URLs

**Subsequent runs:**
- Detects existing clones
- Updates them with `git fetch && git pull`

This allows you to re-run migrations with updated source code.

### ✅ Git Status Validation

If using an existing working directory:
- Checks if it's a git repository
- Validates that the status is clean
- Asks to commit or stash changes if needed

### 📦 Bingo Integration

Sets up `.bingo/` directory with:
- Pinned go-bindata version
- Makefile integration
- **No need to install bingo globally** - Makefile handles everything!

---

## Typical Workflow

### Complete Migration Example

```bash
# Navigate to your workspace
cd ~/workspace

# Run the migration command
/migrate-ote
```

**You'll be prompted for:**
1. Extension name: `sdn`
2. Working directory: `/home/user/workspace/sdn-migration`
3. Source repo URL: `https://github.com/openshift/origin.git`
4. Target repo URL: `https://github.com/openshift/sdn.git`
5. Source test path: `test/extended/networking/`
6. Source testdata path: `test/extended/testdata/`
7. **Dest test path:** `test/e2e/` ⭐
8. **Dest testdata path:** `test/testdata/` ⭐

**After migration completes:**

```bash
cd sdn-migration/tests-extension

# Generate bindata
make bindata

# Update dependencies
go get github.com/openshift-eng/openshift-tests-extension@latest
go mod tidy

# Build
make build

# Validate
./sdn list
./sdn run --platform=aws --dry-run
```

---

## What Gets Generated

### Directory Structure

```
<working-dir>/
├── tests-extension/
│   ├── .bingo/                        # go-bindata tool management
│   │   ├── go-bindata.mod
│   │   ├── Variables.mk
│   │   ├── .gitignore
│   │   └── README.md
│   ├── cmd/
│   │   └── <extension-name>/
│   │       └── main.go               # OTE entry point
│   ├── <dest-test-path>/             # Test files (CUSTOMIZABLE)
│   │   └── *_test.go
│   ├── <dest-testdata-path>/         # Testdata (CUSTOMIZABLE)
│   │   ├── bindata.go                # Generated
│   │   └── fixtures.go               # Wrapper functions
│   ├── go.mod
│   ├── Makefile
│   ├── bindata.mk
│   └── .gitignore
└── repos/
    ├── source/                       # Cloned source repo
    └── target/                       # Cloned target repo
```

### Generated Code

#### 1. `cmd/<extension-name>/main.go`

Complete OTE entry point including:
- Extension and suite registration
- Ginkgo test spec building
- Platform filters (from labels and `[platform:xxx]` in test names)
- Testdata validation and cleanup hooks
- Test package imports (using custom paths)

#### 2. `<dest-testdata-path>/fixtures.go`

Comprehensive testdata wrapper with:
- `FixturePath()` - Main replacement for `compat_otp.FixturePath()`
- `CleanupFixtures()` - Cleanup extracted fixtures
- `GetFixtureData()` - Direct access to embedded data
- `FixtureExists()` - Check if fixture exists
- `ListFixtures()` - List all available fixtures
- `ListFixturesInDir()` - List fixtures in directory
- `GetManifest()`, `GetConfig()` - Convenience functions
- `ValidateFixtures()` - Validate required fixtures exist

#### 3. `Makefile` and `bindata.mk`

Build system with:
- Custom testdata path: `DEST_TESTDATA_PATH := <dest-testdata-path>`
- Bindata generation target
- Build, test, list, clean targets
- Automatic go-bindata building from `.bingo/`

#### 4. `.bingo/` Directory

Tool version management:
- `go-bindata.mod` - Pinned go-bindata version
- `Variables.mk` - Makefile integration with `$(GO_BINDATA)` variable
- `.gitignore` - Committed to git
- `README.md` - Documentation

---

## Supported Patterns

The command automatically detects and handles:

### Platform Patterns
- `[platform:aws]` in test names → `et.PlatformEquals("aws")`
- `Platform:gcp` labels → `et.PlatformEquals("gcp")`

### Environment Patterns
- `[sig-network]` → Suite organization
- `[Conformance]` → Conformance suite membership
- `SLOW` label → Slow test suite

### Lifecycle Patterns
- `Lifecycle:Blocking` (default)
- `Lifecycle:Informing`

---

## Customization After Migration

### Add More Environment Filters

Edit `cmd/<extension-name>/main.go`:

```go
// Network filter
specs.Walk(func(spec *et.ExtensionTestSpec) {
    if strings.Contains(spec.Name, "[network:ovn]") {
        spec.Include(et.NetworkEquals("ovn"))
    }
})

// Topology filter
specs.Walk(func(spec *et.ExtensionTestSpec) {
    re := regexp.MustCompile(`\[topology:(ha|single)\]`)
    if match := re.FindStringSubmatch(spec.Name); match != nil {
        spec.Include(et.TopologyEquals(match[1]))
    }
})
```

### Add Custom Test Suites

```go
// Slow tests suite
ext.AddSuite(e.Suite{
    Name: "openshift/<extension>/slow",
    Qualifiers: []string{
        `labels.exists(l, l=="SLOW")`,
    },
})

// Conformance tests suite
ext.AddSuite(e.Suite{
    Name: "openshift/<extension>/conformance",
    Qualifiers: []string{
        `labels.exists(l, l=="Conformance")`,
    },
})
```

### Add More Hooks

```go
// Before each test
specs.AddBeforeEach(func() {
    // Setup for each test
})

// After each test
specs.AddAfterEach(func(res *et.ExtensionTestResult) {
    if res.Result == et.ResultFailed {
        // Collect diagnostics on failure
    }
})
```

---

## Troubleshooting

### Command not showing up
- Ensure `.claude/commands/` exists in your directory
- Restart Claude Code
- Verify `migrate-ote.md` is present and readable

### Repository cloning fails
- Check URL is correct and accessible
- Verify git authentication (SSH keys or credentials)
- Ensure git is installed: `git --version`

### Tests not discovered
- Check test files are in `<dest-test-path>/`
- Verify test package import in `main.go`
- Ensure tests aren't vendored
- Run `go mod tidy`

### Bindata generation fails
- Ensure testdata directory exists and has files
- Check `.bingo/Variables.mk` is present
- Try running `make bindata` manually
- Verify go-bindata builds: `cd .bingo && go build -modfile=go-bindata.mod`

### Platform filters not working
- Check pattern matches test naming (case-sensitive)
- Verify label format: `Platform:aws` (capital P)
- Test with dry-run: `./<extension> run --platform=aws --dry-run`

### Build errors
- Run `go mod tidy`
- Check all imports are correct
- Verify custom paths are valid Go package paths
- Ensure test packages are imported in `main.go`

---

## Advanced Usage Examples

### Custom Paths Example

Use `pkg/` directory instead of `test/`:

**When prompted:**
- Destination test path: `pkg/e2e/tests/`
- Destination testdata path: `pkg/e2e/testdata/`

**Generated imports:**
```go
import (
    "github.com/<org>/<ext>-tests-extension/pkg/e2e/testdata"
    _ "github.com/<org>/<ext>-tests-extension/pkg/e2e/tests"
)
```

### Multiple Extensions

Run multiple migrations in the same workspace:

```bash
# First migration
/migrate-ote
# Extension: sdn
# Working dir: /workspace/sdn-migration

# Second migration
/migrate-ote
# Extension: router
# Working dir: /workspace/router-migration
```

Each gets isolated `tests-extension/` and `repos/` directories.

### Re-running with Updates

If source repository has new tests:

```bash
# Re-run the migration
/migrate-ote
# Use same configuration

# The tool will:
# - Update existing repository clones
# - Copy new test files
# - Regenerate code if needed
```

---

## Additional Resources

- [OTE Framework Documentation](https://github.com/openshift/enhancements/pull/1676)
- [OTE Framework Repository](https://github.com/openshift-eng/openshift-tests-extension)
- [Example Integration](https://github.com/openshift-eng/openshift-tests-extension/blob/main/cmd/example-tests/main.go)
- [Environment Selectors](https://github.com/openshift-eng/openshift-tests-extension/blob/main/pkg/extension/extensiontests/environment.go)

---

## Contributing

To improve this migration command:

1. Edit `migrate-ote.md` in this directory
2. Test with real repositories
3. Submit improvements

---

## What Changed in v2.0

### Removed Commands
- ❌ `/analyze-for-ote` - Functionality integrated into `/migrate-ote`

### New Features
- ✅ **Single unified command** - Complete migration in one workflow
- ✅ **Customizable paths** - Test and testdata destinations are configurable
- ✅ **Repository management** - Automatic cloning and updating
- ✅ **Working directory support** - Create new or use existing directories
- ✅ **Git validation** - Checks git status for existing directories
- ✅ **Enhanced summary** - Comprehensive migration report

### Migration from v1.0

**Old workflow (2 commands):**
```bash
/analyze-for-ote      # Setup infrastructure
make bindata          # Manual step
go get ...            # Manual step
# Uncomment imports   # Manual step
/migrate-ote          # Complete migration
```

**New workflow (1 command):**
```bash
/migrate-ote          # Everything!
# Manual steps clearly listed in migration summary:
# - make bindata
# - go get ...
# - make build
```
