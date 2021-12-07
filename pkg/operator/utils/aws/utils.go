package aws

import (
	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/aws/aws-sdk-go/service/iam"

	configv1 "github.com/openshift/api/config/v1"

	ccaws "github.com/openshift/cloud-credential-operator/pkg/aws"
	"github.com/openshift/cloud-credential-operator/pkg/operator/utils"
)

// ClientBuilder handles creating an AWS client using the details found in the cluster's
// Infrastructure object.
func ClientBuilder(accessKeyID, secretAccessKey []byte, c client.Client) (ccaws.Client, error) {
	infra, err := utils.GetInfrastructure(c)
	if err != nil {
		return nil, err
	}

	params := setupClientParams(infra)

	return ccaws.NewClient(accessKeyID, secretAccessKey, params)
}

func setupClientParams(infra *configv1.Infrastructure) *ccaws.ClientParams {
	region := ""
	endpoint := ""
	if infra.Status.PlatformStatus != nil && infra.Status.PlatformStatus.AWS != nil {
		// If PlatformStatus isn't nil and has AWS status, then we can at least assume Region is provided
		region = infra.Status.PlatformStatus.AWS.Region

		endpoint = getIAMEndpoint(infra)
	}

	params := &ccaws.ClientParams{
		InfraName: infra.Status.InfrastructureName,
		Region:    region,
		Endpoint:  endpoint,
	}

	return params
}

// LoadInfrastructureRegion loads the AWS region the cluster is installed to.
func LoadInfrastructureRegion(c client.Client, logger log.FieldLogger) (string, error) {
	infra, err := utils.GetInfrastructure(c)
	if err != nil {
		logger.WithError(err).Error("error loading Infrastructure region")
		return "", err
	}
	if infra.Status.PlatformStatus == nil {
		// Older clusters may have an Infrastructure object without the PlatformStatus fields.
		// Send back an empty region and the AWS client will use default settings.
		// The permissions simulation will also simply not fill out the region for simulations.
		return "", nil
	}
	return infra.Status.PlatformStatus.AWS.Region, nil
}

func getIAMEndpoint(infra *configv1.Infrastructure) string {
	for _, ep := range infra.Status.PlatformStatus.AWS.ServiceEndpoints {
		if ep.Name == iam.ServiceName {
			return ep.URL
		}
	}
	return ""
}
