package azure

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseAzureResourceID(t *testing.T) {
	testCases := []struct {
		id                 string
		expectedResourceID *resourceID
		expectError        string
	}{
		{
			// Missing "resourceGroups".
			"/subscriptions/00000000-0000-0000-0000-000000000000//myResourceGroup/",
			nil,
			"Key/Value cannot be empty strings. Key: '', Value: 'myResourceGroup'",
		},
		{
			// Empty resource group ID.
			"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups//",
			nil,
			"Key/Value cannot be empty strings. Key: 'resourceGroups', Value: ''",
		},
		{
			"random",
			nil,
			"cannot parse Azure ID: parse random: invalid URI for request",
		},
		{
			"/subscriptions/6d74bdd2-9f84-11e5-9bd9-7831c1c4c038",
			nil,
			"no resource group name found in: \"subscriptions/6d74bdd2-9f84-11e5-9bd9-7831c1c4c038\"",
		},
		{
			"subscriptions/6d74bdd2-9f84-11e5-9bd9-7831c1c4c038",
			nil,
			"cannot parse Azure ID: parse subscriptions/6d74bdd2-9f84-11e5-9bd9-7831c1c4c038: invalid URI for request",
		},
		{
			"/subscriptions/6d74bdd2-9f84-11e5-9bd9-7831c1c4c038/resourceGroups/testGroup1",
			&resourceID{
				SubscriptionID: "6d74bdd2-9f84-11e5-9bd9-7831c1c4c038",
				ResourceGroup:  "testGroup1",
				Provider:       "",
				Path:           map[string]string{},
			},
			"",
		},
		{
			"/subscriptions/6d74bdd2-9f84-11e5-9bd9-7831c1c4c038/resourceGroups/testGroup1/providers/Microsoft.Network",
			&resourceID{
				SubscriptionID: "6d74bdd2-9f84-11e5-9bd9-7831c1c4c038",
				ResourceGroup:  "testGroup1",
				Provider:       "Microsoft.Network",
				Path:           map[string]string{},
			},
			"",
		},
		{
			// Missing leading /
			"subscriptions/6d74bdd2-9f84-11e5-9bd9-7831c1c4c038/resourceGroups/testGroup1/providers/Microsoft.Network/virtualNetworks/virtualNetwork1/",
			nil,
			"cannot parse Azure ID: parse subscriptions/6d74bdd2-9f84-11e5-9bd9-7831c1c4c038/resourceGroups/testGroup1/providers/Microsoft.Network/virtualNetworks/virtualNetwork1/",
		},
		{
			"/subscriptions/6d74bdd2-9f84-11e5-9bd9-7831c1c4c038/resourceGroups/testGroup1/providers/Microsoft.Network/virtualNetworks/virtualNetwork1",
			&resourceID{
				SubscriptionID: "6d74bdd2-9f84-11e5-9bd9-7831c1c4c038",
				ResourceGroup:  "testGroup1",
				Provider:       "Microsoft.Network",
				Path: map[string]string{
					"virtualNetworks": "virtualNetwork1",
				},
			},
			"",
		},
		{
			"/subscriptions/6d74bdd2-9f84-11e5-9bd9-7831c1c4c038/resourceGroups/testGroup1/providers/Microsoft.Network/virtualNetworks/virtualNetwork1?api-version=2006-01-02-preview",
			&resourceID{
				SubscriptionID: "6d74bdd2-9f84-11e5-9bd9-7831c1c4c038",
				ResourceGroup:  "testGroup1",
				Provider:       "Microsoft.Network",
				Path: map[string]string{
					"virtualNetworks": "virtualNetwork1",
				},
			},
			"",
		},
		{
			"/subscriptions/6d74bdd2-9f84-11e5-9bd9-7831c1c4c038/resourceGroups/testGroup1/providers/Microsoft.Network/virtualNetworks/virtualNetwork1/subnets/publicInstances1?api-version=2006-01-02-preview",
			&resourceID{
				SubscriptionID: "6d74bdd2-9f84-11e5-9bd9-7831c1c4c038",
				ResourceGroup:  "testGroup1",
				Provider:       "Microsoft.Network",
				Path: map[string]string{
					"virtualNetworks": "virtualNetwork1",
					"subnets":         "publicInstances1",
				},
			},
			"",
		},
		{
			"/subscriptions/34ca515c-4629-458e-bf7c-738d77e0d0ea/resourcegroups/acceptanceTestResourceGroup1/providers/Microsoft.Cdn/profiles/acceptanceTestCdnProfile1",
			&resourceID{
				SubscriptionID: "34ca515c-4629-458e-bf7c-738d77e0d0ea",
				ResourceGroup:  "acceptanceTestResourceGroup1",
				Provider:       "Microsoft.Cdn",
				Path: map[string]string{
					"profiles": "acceptanceTestCdnProfile1",
				},
			},
			"",
		},
		{
			"/subscriptions/34ca515c-4629-458e-bf7c-738d77e0d0ea/resourceGroups/testGroup1/providers/Microsoft.ServiceBus/namespaces/testNamespace1/topics/testTopic1/subscriptions/testSubscription1",
			&resourceID{
				SubscriptionID: "34ca515c-4629-458e-bf7c-738d77e0d0ea",
				ResourceGroup:  "testGroup1",
				Provider:       "Microsoft.ServiceBus",
				Path: map[string]string{
					"namespaces":    "testNamespace1",
					"topics":        "testTopic1",
					"subscriptions": "testSubscription1",
				},
			},
			"",
		},
		{
			"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/example-resources/providers/Microsoft.ApiManagement/service/service1/subscriptions/22222222-2222-2222-2222-222222222222",
			&resourceID{
				SubscriptionID: "11111111-1111-1111-1111-111111111111",
				ResourceGroup:  "example-resources",
				Provider:       "Microsoft.ApiManagement",
				Path: map[string]string{
					"service":       "service1",
					"subscriptions": "22222222-2222-2222-2222-222222222222",
				},
			},
			"",
		},
	}

	for _, test := range testCases {
		t.Run("", func(t *testing.T) {
			parsed, err := parseAzureResourceID(test.id)
			if test.expectError == "" {
				assert.NoError(t, err)
			} else {
				assert.Errorf(t, err, test.expectError)
			}
			assert.Equal(t, test.expectedResourceID, parsed)
		})
	}
}
