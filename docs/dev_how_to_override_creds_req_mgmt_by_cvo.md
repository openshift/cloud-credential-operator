### Override the CVO stomping your CredentialsRequest changes temporarily

If you are making changes to the CredentialsRequest, you may need to prevent the CVO from changing it right back:

oc patch clusterversion version --type=merge -p "$(cat hack/cco-override.json)"

check with:

oc get clusterversion version -o jsonpath='{.spec.overrides}'

then this will stay as you set it:

oc replace -f bindata/bootstrap/cloudcredential_v1_credentialsrequest_crd.yaml

---

### If you need to permanently change the CredentialsRequest

Ultimately you will need to affect a change to the release image for the CredentialsRequest CRD:

we need to change this:
0000_50_cloud-credential-operator_00-crd.yaml

retrieved from here:
oc adm release extract --to manifests quay.io/openshift-release-dev/ocp-release:4.14.0-ec.0-x86_64

An old commit message has some clues about which files here are being watched for inclusion in the release image:

https://github.com/openshift/cloud-credential-operator/commit/8dfd9c04027a4de097ce0f88b06613bc6d43465c

Removing unneeded bits and paraphrasing:

migrate the CRDs

Process used was to first generate v1 CRD into a temporary location:
`_output/tools/bin/controller-gen paths=./pkg/apis/...  crd:crdVersions=v1 output:crd:artifacts:config=tmpcrds`

Next copy the CRD to manifests/00-crd.yaml, and compare for any unexpected changes.

Add back the `include.release.openshift.io` annotations.

Finally, copy that CRD to
`bindata/boostrap/cloudcredential_v1_credentialsrequest_crd.yaml`.

`make update` will now take any new API changes and update the generated
CRDs appropriately (keeping the v1 CRD).