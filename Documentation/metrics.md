Metrics
=======

cloud-credential-operator (CCO) exposes metrics for integration with Prometheus. Metrics are not persistent. Restarting CCO will reset metrics.

The metrics are exposed via HTTP on port 2112 at `/metrics` (eg. http://localhost:2112/metrics).

The metrics names have a `cco` prefix.

### Descriptions

These metrics describe the status of CCO. 

| Name                            | Description                                        | Type      |
|---------------------------------|----------------------------------------------------|-----------|
| cco_credentials_requests            | Counts the total number of CredentialRequest objects and labels them by their cloud/infrastructure.                 | Gauge     |
| cco_controller_reconcile_seconds    | Measures each controller's (ie secretannotator, credentialsrequests, configmap, etc) execution time through it's respective reconcile loop.       | Histogram |
| cco_credentials_requests_conditions | Reports the number of CredentialsRequests with active conditions in their status (ie. Ignored, ProvisionFailed, MissingTargetNamespace, etc).       | Gauge     |

### Extra metrics
There are also per-controller metrics that are produced for free with the kubernetes scaffolding. Some examples of these kinds of metrics:

```
# HELP credentialsrequest_controller_queue_latency How long an item stays in workqueuecredentialsrequest_controller before being requested.                      
# TYPE credentialsrequest_controller_queue_latency summary                                                                                                       
credentialsrequest_controller_queue_latency{name="credentialsrequest_controller",quantile="0.5"} NaN                                                             
credentialsrequest_controller_queue_latency{name="credentialsrequest_controller",quantile="0.9"} NaN                                                             
credentialsrequest_controller_queue_latency{name="credentialsrequest_controller",quantile="0.99"} NaN                                                            
credentialsrequest_controller_queue_latency_sum{name="credentialsrequest_controller"} 0                                                                          
credentialsrequest_controller_queue_latency_count{name="credentialsrequest_controller"} 0  
```

```
# HELP workqueue_retries_total Total number of retries handled by workqueue
# TYPE workqueue_retries_total counter
workqueue_retries_total{name="credentialsrequest_controller"} 0
workqueue_retries_total{name="secretannotator"} 0
```

```
# HELP secretannotator_unfinished_work_seconds How many seconds of work secretannotator has done that is in progress and hasn't been observed by work_duration. L
arge values indicate stuck threads. One can deduce the number of stuck threads by observing the rate at which this increases.
# TYPE secretannotator_unfinished_work_seconds gauge
secretannotator_unfinished_work_seconds 0
```
