# Azure Mint Mode removal

## Summary

Azure is [removing support](https://techcommunity.microsoft.com/t5/azure-active-directory-identity/update-your-applications-to-use-microsoft-authentication-library/ba-p/1257363) for the Azure Active Directory Graph API that is used to create App Registrations, Service Principals, role assignments, and credentials for supporting Mint mode in Azure. CCO will pivot existing clusters to switch away from Mint mode to Passthrough mode.

## New installations

For new cluster installations, Passthrough and Manual modes will be the only supported modes of operation.

## Upgrades

For a cluster previously installed/running in Mint mode, CCO will update existing Secrets containing the credentials of previously minted App Registrations/Service Principals with the contents of the Secret kube-system/azure-credentials (normally containing the credentials used during installation). It is required that the permissions associated with the credentials in this Secret be sufficient to be used by all in-cluster components needing to interact with Azure APIs.

CCO will also try to clean up previously minted App Registrations/Service Principals while the Azure AD Graph API is still functional. If the cluster is upgraded to a version of OpenShift that no longer supports Mint mode after the Azure AD Graph API is sunset, CCO will set a condition (type "OrphanedCloudResource" with a message like "unable to clean up App Registration / Service Principal: APP-REGISTRATION-NAME-HERE") on the associated CredentialsRequest and will not treat the error as fatal. Cleanup after the Azure AD Graph API is sunset will require manual intervention using the Azure CLI tool or the Azure web console to remove the App Registrations/Service Principals that were unable to be cleaned up. Note that even after cleaning up the resource(s) manually, the condition will persist as CCO would no longer be able to verify that the cleanup has been performed.

Example of finding and removing an orphaned App Registration:
```bash
$ az ad app list --filter "displayname eq 'APP-REGISTRATION-NAME-HERE'" --query '[].objectId'                                                         
[                                
  "038c2538-7c40-49f5-abe5-f59c59c29244"                                        
]  
$ az ad app delete --id 038c2538-7c40-49f5-abe5-f59c59c29244
```

## Future

Rather than re-implement support for Mint mode using the new [Microsoft Graph API](https://docs.microsoft.com/en-us/graph/sdks/create-requests?tabs=Go), the intention is to support Azure federated OpenID identities along with pod/workload identity as the preferred in-cluster credentials/authentication mode if/when Azure releases support for this feature.
