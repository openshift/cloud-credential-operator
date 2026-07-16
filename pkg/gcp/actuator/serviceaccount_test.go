package actuator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServiceAccountEmail(t *testing.T) {
	tests := []struct {
		name        string
		svcAcctID   string
		projectName string
		expected    string
	}{
		{
			name:        "standard project",
			svcAcctID:   "my-service-account",
			projectName: "my-project",
			expected:    "my-service-account@my-project.iam.gserviceaccount.com",
		},
		{
			name:        "domain-scoped project",
			svcAcctID:   "my-service-account",
			projectName: "eu0:my-project",
			expected:    "my-service-account@my-project.eu0.iam.gserviceaccount.com",
		},
		{
			name:        "domain-scoped project with different domain",
			svcAcctID:   "openshift-ingress",
			projectName: "berlin0:openshift-prod",
			expected:    "openshift-ingress@openshift-prod.berlin0.iam.gserviceaccount.com",
		},
		{
			name:        "project name with no colon",
			svcAcctID:   "test-sa",
			projectName: "simple-project-123",
			expected:    "test-sa@simple-project-123.iam.gserviceaccount.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := serviceAccountEmail(tc.svcAcctID, tc.projectName)
			assert.Equal(t, tc.expected, got)
		})
	}
}
