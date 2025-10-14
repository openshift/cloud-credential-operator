# CCO Helper Plugin

AI-assisted helper for OpenShift Cloud Credential Operator development and testing.

## Description

The CCO Helper plugin provides automated workflows for:
- Pre-merge OCP installation testing
- QE regression CI triggering

## Commands

### `cco-helper:verify-ocp-install`

Trigger OCP installation CI jobs for PR pre-merge testing.

```bash
cco-helper:verify-ocp-install 4.21 azure <PR_URL>
```

**Arguments:**
- `RELEASE_VERSION`: OpenShift release (e.g., "4.21")
- `PLATFORM`: `aws`, `azure`, `gcp`, or `all`
- `PR_URL`: Pull request URL

### `cco-helper:trigger-qe-regression-ci`

Trigger comprehensive regression test suite.

```bash
cco-helper:trigger-qe-regression-ci
```

**Arguments:** None (operates on current context)

## Installation

### Option 1: Install from GitHub

#### Step 1: Add the Marketplace

```bash
/plugin marketplace add openshift/cloud-credential-operator
```

This adds the OpenShift Cloud Credential Operator repository as a plugin marketplace.

#### Step 2: Install the Plugin

```bash
/plugin install cco-helper
```

Or browse and install from the plugin menu:
```bash
/plugin
```

Then select `cco-helper` from the list.

#### Step 3: Verify Installation

```bash
/plugin 
```

You should see `cco-helper` in the installed plugins.
```

## Prerequisites

- **GitHub CLI** (`gh`) installed and authenticated
- **Git** configured
- Access to OpenShift Cloud Credential Operator repository
- Appropriate CI/CD permissions

## Quick Start

Once installed, use the plugin commands:

1. **Using plugin commands directly:**
   ```bash
   cco-helper:verify-ocp-install 4.21 azure https://github.com/openshift/cloud-credential-operator/pull/123
   cco-helper:trigger-qe-regression-ci
   ```

2. **Using slash commands (if configured):**
   ```bash
   /verify-ocp-install 4.21 all https://github.com/openshift/cloud-credential-operator/pull/123
   /trigger-qe-regression-ci
   ```

### Plugin Management

- **Browse plugins:** `/plugin`
- **List installed:** `/plugin list`
- **Get plugin info:** `/plugin info cco-helper`
- **Update plugin:** `/plugin update cco-helper`
- **Uninstall plugin:** `/plugin uninstall cco-helper`

## Configuration

No additional configuration required. The plugin uses:
- GitHub CLI authentication (`gh auth status`)
- Current git repository context
- OpenShift release repository (public)

## Supported Platforms

- ✅ AWS (IAM roles, STS, OIDC)
- ✅ Azure (Managed Identity, Workload Identity)
- ✅ GCP (Workload Identity, Service Accounts)

## Troubleshooting

### Authentication Issues
```bash
gh auth status
gh auth login
```

### PR Validation Fails
- Ensure PR is open (not draft)
- Verify you have comment permissions
- Check PR is from correct repository

## Contributing

This plugin is part of the OpenShift Cloud Credential Operator project.

**To contribute:**
1. Fork the repository
2. Create a feature branch
3. Make changes to `plugins/cco-helper/`
4. Test with your changes
5. Submit a pull request


## License

Apache License 2.0 - See [LICENSE](../../LICENSE)

## Support

- **Issues**: [GitHub Issues](https://github.com/openshift/cloud-credential-operator/issues)
- **Discussions**: OpenShift community channels
- **Documentation**: [CCO Docs](https://github.com/openshift/cloud-credential-operator/tree/master/docs)

## Maintainers

- OpenShift Cloud Credential Operator Team
