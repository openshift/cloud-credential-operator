/*
Copyright 2021 The OpenShift Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package openstack

import (
	"regexp"
	"testing"
)

func TestOpenStackActuatorFixInvalidCACertFile(t *testing.T) {
	const noCACert = `
clouds:
  openstack:
    auth:
      auth_url: http://1.2.3.4:5000
      password: password
      project_domain_name: Default
      project_name: openshift
      user_domain_name: Default
      username: openshift
    identity_api_version: "3"
    region_name: regionOne
    verify: true
`

	const incorrectCACert = `
clouds:
  openstack:
    auth:
      auth_url: http://1.2.3.4:5000
      password: password
      project_domain_name: Default
      project_name: openshift
      user_domain_name: Default
      username: openshift
    cacert: /incorrect/path/to/ca-bundle.pem
    identity_api_version: "3"
    region_name: regionOne
    verify: true
`

	const correctCACert = `
clouds:
  openstack:
    auth:
      auth_url: http://1.2.3.4:5000
      password: password
      project_domain_name: Default
      project_name: openshift
      user_domain_name: Default
      username: openshift
    cacert: /etc/kubernetes/static-pod-resources/configmaps/cloud-config/ca-bundle.pem
    identity_api_version: "3"
    region_name: regionOne
    verify: true
`

	tests := []struct {
		name    string
		arg     string
		want    string
		wantErr bool
	}{
		{"noCACert", noCACert, "", false},
		{"incorrectCACert", incorrectCACert, "cacert: " + caCertFile, false},
		{"correctCACert", incorrectCACert, "cacert: " + caCertFile, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &OpenStackActuator{}
			got := a.fixInvalidCACertFile(tt.arg)
			caCertFile := regexp.MustCompile(`cacert: .*`).FindString(got)
			if caCertFile != tt.want {
				t.Errorf("OpenStackActuator.fixInvalidCACertFile() = %v, want %v", got, tt.want)
			}
		})
	}
}
