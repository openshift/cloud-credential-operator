/*
Copyright 2019 The OpenShift Authors.

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

package ovirt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var ca_bundle = `
-----BEGIN CERTIFICATE-----
MIIEDjCCAvagAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwYDELMAkGA1UEBhMCVVMxIDAeBgNVBAoM
F2xhYi5lbmcudGx2Mi5yZWRoYXQuY29tMS8wLQYDVQQDDCZ2bS0xMC01MS5sYWIuZW5nLnRsdjIu
cmVkaGF0LmNvbS45OTM3ODAeFw0yMDAyMTAxMjEyNDdaFw0zMDAyMDgxMjEyNDdaMGAxCzAJBgNV
BAYTAlVTMSAwHgYDVQQKDBdsYWIuZW5nLnRsdjIucmVkaGF0LmNvbTEvMC0GA1UEAwwmdm0tMTAt
NTEubGFiLmVuZy50bHYyLnJlZGhhdC5jb20uOTkzNzgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDDMZydFaXS1KznEAN3R5d0IBOt+dy8HcmcMEDnZru+BqiJL0cghTFe/HaF7fR7WQjD
Q5mVeSWshcYSd5bnSkjnzoZ+DYQfkRhqsgS/cl705AwJje1scRasYUFsXNgKIGMtY0UswsLoNqhb
q5rm4LFpckXDENJhVxYfqVyplodBgAWBNJ7G/f23IRrPNZm7cUmQ6u2LQrWxrjvx0hLeGzWJ+nBs
laGwjt/zeCHlRZW45rH0pTwK/tbMb4bN+eFyBdC/4EwTOQsPxE92SmbEDLh/Dbu5sy8KELMXsFoP
h2HLjCR/5KNXLdZzQY1/2nT6lqV4teqUyR7FtFWuCDtMQLQ5AgMBAAGjgdEwgc4wHQYDVR0OBBYE
FKmz7ldOrYBfDlDvR8FdZDlZfX9xMIGLBgNVHSMEgYMwgYCAFKmz7ldOrYBfDlDvR8FdZDlZfX9x
oWSkYjBgMQswCQYDVQQGEwJVUzEgMB4GA1UECgwXbGFiLmVuZy50bHYyLnJlZGhhdC5jb20xLzAt
BgNVBAMMJnZtLTEwLTUxLmxhYi5lbmcudGx2Mi5yZWRoYXQuY29tLjk5Mzc4ggIQADAPBgNVHRMB
Af8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAJytEfblSIyZ7fu81
ozFyynTHHJSck5vP8baAY+/uujMYEDmm5vFuwCTvoZAp3eXK5ixVyLF50Rb48BOJUlRRAojko7T1
Zln4BhQULgGNzDUAtUwiM7l1mCs3b0rlXII5br90Mic6NXXZcTtly8EKBhCkub47170oFl6MviKv
U5wUTtoeWHgaH1d4Hx9WIO4QQuHzQuQT2Kh4GjC2rckBOs/kS4THZfW4730ReH5OlTOjll8QrTmN
jEh90ELGUGECJ1MrEI1F6bjowsceq0vMU0Rhup9QXbiAyUZ/wVPVjIBCGZEcPFPCIsT2C1lWgA2q
clEaxBP6e5HHDuA3rv7kCw==
-----END CERTIFICATE-----
`

func TestConvertRootCredentials(t *testing.T) {
	tests := []struct {
		givenSecret    corev1.Secret
		expectedCreds  OvirtCreds
		expectedToFail bool
	}{
		{
			givenSecret: corev1.Secret{
				TypeMeta:   v1.TypeMeta{},
				ObjectMeta: v1.ObjectMeta{},
				Data: map[string][]byte{
					"ovirt_url":       []byte("https://enginefqdn/ovirt-engine/api"),
					"ovirt_username":  []byte("admin@internal"),
					"ovirt_password":  []byte("secret"),
					"ovirt_cafile":    []byte("/etc/pki/ovirt-engine/ca.pem"),
					"ovirt_ca_bundle": []byte(ca_bundle),
					"ovirt_insecure":  []byte("true"),
				},
				StringData: nil,
				Type:       "Opaque",
			},
			expectedCreds: OvirtCreds{
				URL:      "https://enginefqdn/ovirt-engine/api",
				Username: "admin@internal",
				Passord:  "secret",
				CAFile:   "/etc/pki/ovirt-engine/ca.pem",
				CABundle: ca_bundle,
				Insecure: true,
			},
			expectedToFail: false,
		},
		{
			givenSecret: corev1.Secret{
				TypeMeta:   v1.TypeMeta{},
				ObjectMeta: v1.ObjectMeta{},
				Data:       nil,
				StringData: nil,
				Type:       "",
			},
			expectedCreds: OvirtCreds{
				URL:      "",
				Username: "",
				Passord:  "",
				CAFile:   "",
				Insecure: false,
			},
			expectedToFail: true,
		},
	}

	for _, v := range tests {
		ovirtCreds, err := secretToCreds(&v.givenSecret)
		if v.expectedToFail {
			assert.Error(t, err, "expected failure")
		} else {
			assert.NoError(t, err)
			assert.Equal(t, v.expectedCreds, ovirtCreds)
		}
	}
}
