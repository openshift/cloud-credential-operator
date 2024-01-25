Metrics
=======

cloud-credential-operator (CCO) exposes metrics for integration with Prometheus. Metrics are not persistent. Restarting CCO will reset metrics.

The metrics are exposed via HTTP on port 2112 at `/metrics` (eg. http://localhost:2112/metrics).

The metrics names have a `cco` prefix.

### Descriptions

These metrics describe the status of CCO. 

| Name                                | Description                                                                                                                                    | Type      |
|-------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------|-----------|
| cco_credentials_mode                | Track current mode the cloud-credentials-operator is functioning under.                                                                        | Gauge     |
| cco_credentials_requests            | Counts the total number of CredentialRequest objects and labels them by their cloud/infrastructure.                                            | Gauge     |
| cco_controller_reconcile_seconds    | Measures each controller's (i.e. secretannotator, credentialsrequests, configmap, etc) execution time through it's respective reconcile loop.  | Histogram |
| cco_credentials_requests_conditions | Reports the number of CredentialsRequests with active conditions in their status (i.e. Ignored, ProvisionFailed, MissingTargetNamespace, etc). | Gauge     |

### Extra metrics
There are also per-controller metrics that are produced for free with the kubernetes scaffolding, e.g. controller-runtime. Some examples of these kinds of metrics:

```  
# HELP workqueue_queue_duration_seconds How long in seconds an item stays in workqueue before being requested
# TYPE workqueue_queue_duration_seconds histogram                                                                                                 
workqueue_queue_duration_seconds_bucket{name="credentialsrequest_controller",le="1e-08"} 0
workqueue_queue_duration_seconds_bucket{name="credentialsrequest_controller",le="1e-07"} 0
workqueue_queue_duration_seconds_bucket{name="credentialsrequest_controller",le="1e-06"} 0
workqueue_queue_duration_seconds_bucket{name="credentialsrequest_controller",le="9.999999999999999e-06"} 0
workqueue_queue_duration_seconds_bucket{name="credentialsrequest_controller",le="9.999999999999999e-05"} 0
workqueue_queue_duration_seconds_bucket{name="credentialsrequest_controller",le="0.001"} 0
workqueue_queue_duration_seconds_bucket{name="credentialsrequest_controller",le="0.01"} 0
workqueue_queue_duration_seconds_bucket{name="credentialsrequest_controller",le="0.1"} 0
workqueue_queue_duration_seconds_bucket{name="credentialsrequest_controller",le="1"} 46
workqueue_queue_duration_seconds_bucket{name="credentialsrequest_controller",le="10"} 46
workqueue_queue_duration_seconds_bucket{name="credentialsrequest_controller",le="+Inf"} 46
workqueue_queue_duration_seconds_sum{name="credentialsrequest_controller"} 26.782756081000002
workqueue_queue_duration_seconds_count{name="credentialsrequest_controller"} 46
...
```

```
# HELP workqueue_retries_total Total number of retries handled by workqueue
# TYPE workqueue_retries_total counter
workqueue_retries_total{name="cleanup"} 0
workqueue_retries_total{name="credentialsrequest_controller"} 7
workqueue_retries_total{name="credreq_labeller"} 0
workqueue_retries_total{name="loglevel"} 0
workqueue_retries_total{name="pod-identity"} 0
workqueue_retries_total{name="secretannotator"} 0
workqueue_retries_total{name="status"} 34
```

```
# HELP workqueue_unfinished_work_seconds How many seconds of work has been done that is in progress and hasn't been observed by work_duration. Large values indicate stuck threads. One can deduce the number of stuck threads by observing the rate at which this increases.
# TYPE workqueue_unfinished_work_seconds gauge
workqueue_unfinished_work_seconds{name="cleanup"} 0
workqueue_unfinished_work_seconds{name="credentialsrequest_controller"} 0
workqueue_unfinished_work_seconds{name="credreq_labeller"} 0
workqueue_unfinished_work_seconds{name="loglevel"} 0
workqueue_unfinished_work_seconds{name="pod-identity"} 0
workqueue_unfinished_work_seconds{name="secretannotator"} 0
workqueue_unfinished_work_seconds{name="status"} 0
```
