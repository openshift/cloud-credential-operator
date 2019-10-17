Metrics
=======

cloud-credential-operator (CCO) exposes metrics for integration with Prometheus. Metrics are not persistent. Restarting CCO will reset metrics.

The metrics are exposed via HTTP on port 2112 at `/metrics` (eg. http://localhost:2112/metrics).

The metrics names have a `cco` prefix.

### Server

These metrics describe the status of CCO. 

| Name                            | Description                                        | Type      |
|---------------------------------|----------------------------------------------------|-----------|
| cco_credentials_requests            | Counts the total number of CredentialRequest objects and labels them by their cloud/infrastructure.                 | Gauge     |
| cco_controller_reconcile_seconds    | Measures each controller's (ie secretannotator, credentialsrequests, configmap, etc) execution time through it's respective reconcile loop.       | Histogram |
| cco_credentials_requests_conditions | Reports the number of CredentialsRequests with active conditions in their status (ie. Ignored, ProvisionFailed, MissingTargetNamespace, etc).       | Gauge     |
