Metrics
=======

cloud-credential-operator (CCO) exposes metrics for integration with Prometheus. Metrics are not persistent. Restarting CCO will reset metrics.

The metrics are exposed via HTTP on port 2112 at `/metrics` (eg. http://localhost:2112/metrics).

The metrics names have a `cco` prefix.

### Server

These metrics describe the status of CCO. 

All these metrics are prefixed with `cco_`

| Name                            | Description                                        | Type      |
|---------------------------------|----------------------------------------------------|-----------|
| credentials_requests            | Count of credentials requests                      | Gauge     |
| controller_reconcile_seconds    | Controller execution time in reconcile loop.       | Histogram |
| credentials_requests_conditions | Credentials requests with active conditions.       | Gauge     |

`credentials_requests` counts the total number of CredentialRequest objects and labels them by their cloud/infrastructure.

`controller_reconcile_seconds` measures each controller's (ie secretannotator, credentialsrequests, configmap, etc) execution time through it's respective reconcile loop.

`credentials_requests_conditions` reports the number of CredentialsRequests with active conditions in their status (ie. Ignored, ProvisionFailed, MissingTargetNamespace, etc).
