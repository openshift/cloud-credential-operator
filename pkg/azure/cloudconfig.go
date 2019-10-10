package azure

// https://github.com/kubernetes/kubernetes/blob/v1.16.0/staging/src/k8s.io/legacy-cloud-providers/azure/azure.go#L90
type cloudconfig struct {
	// The name of the resource group that the Vnet is deployed in
	VnetResourceGroup string `json:"vnetResourceGroup,omitempty" yaml:"vnetResourceGroup,omitempty"`
}
