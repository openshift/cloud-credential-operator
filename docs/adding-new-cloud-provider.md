# How to add a new Cloud Provider

## Add provider specific code to the cloud credentials operator 
The Cloud Credentials Operator has three modes

- *Manual* is a recommended mode. In this mode a user performs tasks related to cloud credentials using tools external to the cluster. 
- *Mint* mode. In this mode the admin credential is stored in the kube-system namespace and those admin credentials are used to create fine-grained users/permission for in-cluster components.
- *Passthrough* mode. In this mode a single credential having all the required permissions for all the in-cluster components is stored in the kube-system namespace and passed along as-is to other in-cluster components. This credential does not have sufficient permissions to mint additional users/credentials.

The current guidance is for a new provider to initially support at least the *Manual* mode. The other two modes are optional. The other two modes are optional. Learn more about CCO modes [here](../README.md#modes-of-operation). 

For adding a new provider we need new code at the following places

1) Create a ProviderSpec API that holds the specifications for the credentials request. Refer aws implementation [here](../pkg/apis/cloudcredential/v1/types_aws.go). Also, register the ProviderSpec API in [register.go](../pkg/apis/cloudcredential/v1/register.go).

Follow the next steps only if you are planning to support *Mint* and *Passthrough* mode.  

2) Create a ProviderStatus API that holds the status of the credentials request. Refer aws implementation [here](../pkg/apis/cloudcredential/v1/types_aws.go). Also, register the ProviderStatus API in [register.go](../pkg/apis/cloudcredential/v1/register.go).
3) Implement [this](../pkg/operator/credentialsrequest/actuator/actuator.go) actuator interface. Here you add code to create/update/manage credentials on the cloud. Refer aws implementation [here](../pkg/aws/actuator/actuator.go).
4) Add the new actuator to the [controller.go](../pkg/operator/controller.go)
5) Add the new platform in `crInfraMatches` function in [credentrialsrequest_controller.go](../pkg/operator/credentialsrequest/credentialsrequest_controller.go) so that it identified as a valid platform by the controller.
6) If mint mode is supported, add the code for [secretannotator_controller.go](../pkg/operator/secretannotator/secretannotator_controller.go) to annotate the cloud credential secret to indicate the credential's capabilities. Refer aws implementation [here](../pkg/operator/secretannotator/aws/reconciler.go).
7) Make the required changes in [metrics.go](../pkg/operator/metrics/metrics.go) to report appropriate metrics. 

Finally, update the support matrix in [README.md](../README.md) to specify which modes/versions are supported.

## Add provider specific code to the ccoctl tool

The ccoctl tool helps you set up credentials infrastructure outside the cluster. You need to implement following commands (or something similar) for the ccoctl

1) (For platforms that support using the cluster's internal identity provider) A command to set up identity provider that authenticates OpenShift in-cluster components based on a token   

```bash  
ccoctl <cloud-provider> create-identity-provider --name=<name>
```

2) A command that can take a list of CredentialsRequest objects to create users/roles, along with permissions, which OpenShift components can assume to send cloud API requests 

```bash
ccoctl <cloud-provider> create-roles --name=<name> --credentials-requests-dir=<path-to-directory-with-list-of-credentials-requests>
```

3) A command to delete credentials infrastructure in the cloud 

```bash
ccoctl <cloud-provider> delete --name=<name>
```

Please refer to aws implementation [here](./ccoctl.md) to get more insights into this tooling.
