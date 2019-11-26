package assets

import (
	"fmt"
	"strings"
)

var _config_crds_cloudcredential_v1_credentialsrequest_yaml = []byte(`apiVersion: apiextensions.k8s.io/v1beta1
kind: CustomResourceDefinition
metadata:
  creationTimestamp: null
  labels:
    controller-tools.k8s.io: "1.0"
  name: credentialsrequests.cloudcredential.openshift.io
spec:
  group: cloudcredential.openshift.io
  names:
    kind: CredentialsRequest
    plural: credentialsrequests
  scope: Namespaced
  subresources:
    status: {}
  validation:
    openAPIV3Schema:
      properties:
        apiVersion:
          description: 'APIVersion defines the versioned schema of this representation
            of an object. Servers should convert recognized schemas to the latest
            internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#resources'
          type: string
        kind:
          description: 'Kind is a string value representing the REST resource this
            object represents. Servers may infer this from the endpoint the client
            submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds'
          type: string
        metadata:
          type: object
        spec:
          properties:
            providerSpec:
              description: ProviderSpec contains the cloud provider specific credentials
                specification.
              type: object
            secretRef:
              description: SecretRef points to the secret where the credentials should
                be stored once generated.
              type: object
          required:
          - secretRef
          type: object
        status:
          properties:
            conditions:
              description: Conditions includes detailed status for the CredentialsRequest
              items:
                properties:
                  lastProbeTime:
                    description: LastProbeTime is the last time we probed the condition
                    format: date-time
                    type: string
                  lastTransitionTime:
                    description: LastTransitionTime is the last time the condition
                      transitioned from one status to another.
                    format: date-time
                    type: string
                  message:
                    description: Message is a human-readable message indicating details
                      about the last transition
                    type: string
                  reason:
                    description: Reason is a unique, one-word, CamelCase reason for
                      the condition's last transition
                    type: string
                  status:
                    description: Status is the status of the condition
                    type: string
                  type:
                    description: Type is the specific type of the condition
                    type: string
                required:
                - type
                - status
                type: object
              type: array
            lastSyncGeneration:
              description: LastSyncGeneration is the generation of the credentials
                request resource that was last synced. Used to determine if the object
                has changed and requires a sync.
              format: int64
              type: integer
            lastSyncTimestamp:
              description: LastSyncTimestamp is the time that the credentials were
                last synced.
              format: date-time
              type: string
            providerStatus:
              description: ProviderStatus contains cloud provider specific status.
              type: object
            provisioned:
              description: Provisioned is true once the credentials have been initially
                provisioned.
              type: boolean
          required:
          - provisioned
          - lastSyncGeneration
          type: object
      required:
      - spec
  version: v1
status:
  acceptedNames:
    kind: ""
    plural: ""
  conditions: []
  storedVersions: []
`)

func config_crds_cloudcredential_v1_credentialsrequest_yaml() ([]byte, error) {
	return _config_crds_cloudcredential_v1_credentialsrequest_yaml, nil
}

var _config_manager_deployment_yaml = []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: cloud-credential-operator
  namespace: openshift-cloud-credential-operator
  labels:
    control-plane: controller-manager
    controller-tools.k8s.io: "1.0"
  annotations:
    config.openshift.io/inject-proxy: "manager"
spec:
  selector:
    matchLabels:
      control-plane: controller-manager
      controller-tools.k8s.io: "1.0"
  replicas: 1
  revisionHistoryLimit: 4
  template:
    metadata:
      labels:
        app: cloud-credential-operator
        control-plane: controller-manager
        controller-tools.k8s.io: "1.0"
    spec:
      priorityClassName: system-cluster-critical
      nodeSelector:
        node-role.kubernetes.io/master: ""
      tolerations:
      - key: "node-role.kubernetes.io/master"
        operator: "Exists"
        effect: "NoSchedule"
      - key: "node.kubernetes.io/unreachable"
        operator: "Exists"
        effect: "NoExecute"
        tolerationSeconds: 120
      - key: "node.kubernetes.io/not-ready"
        operator: "Exists"
        effect: "NoExecute"
        tolerationSeconds: 120
      containers:
      - env:
        - name: RELEASE_VERSION
          value: "0.0.1-snapshot"
        image: quay.io/openshift/origin-cloud-credential-operator:latest
        imagePullPolicy: IfNotPresent
        name: manager
        resources:
          requests:
            cpu: 10m
            memory: 150Mi
        ports:
        - containerPort: 9876
          name: webhook-server
          protocol: TCP
        command: ["/bin/bash", "-ec"]
        args:
        - |
          if [ -s /var/run/configmaps/trusted-ca-bundle/tls-ca-bundle.pem ]; then
              echo "Copying system trust bundle"
              cp -f /var/run/configmaps/trusted-ca-bundle/tls-ca-bundle.pem /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
          fi
          exec /root/manager --log-level=debug
        terminationMessagePolicy: FallbackToLogsOnError
        volumeMounts:
        - name: cco-trusted-ca
          mountPath: /var/run/configmaps/trusted-ca-bundle
      terminationGracePeriodSeconds: 10
      volumes:
      - name: cco-trusted-ca
        configMap:
          optional: true
          name: cco-trusted-ca
          items:
          - key: ca-bundle.crt
            path: tls-ca-bundle.pem
---
apiVersion: v1
kind: ConfigMap
metadata:
  labels:
    # This label ensures that the OpenShift Certificate Authority bundle
    # is added to the ConfigMap.
    config.openshift.io/inject-trusted-cabundle: "true"
  name: cco-trusted-ca
  namespace: openshift-cloud-credential-operator
`)

func config_manager_deployment_yaml() ([]byte, error) {
	return _config_manager_deployment_yaml, nil
}

var _config_manager_metrics_service_yaml = []byte(`apiVersion: v1
kind: Service
metadata:
  name: cco-metrics
  namespace: openshift-cloud-credential-operator
spec:
  ports:
  - name: cco-metrics
    port: 2112
    protocol: TCP
    targetPort: 2112
  selector:
    app: cloud-credential-operator
  sessionAffinity: None
  type: ClusterIP
`)

func config_manager_metrics_service_yaml() ([]byte, error) {
	return _config_manager_metrics_service_yaml, nil
}

var _config_manager_namespace_yaml = []byte(`apiVersion: v1
kind: Namespace
metadata:
  annotations:
    openshift.io/node-selector: ""
  labels:
    controller-tools.k8s.io: "1.0"
    openshift.io/run-level: "1"
    openshift.io/cluster-monitoring: "true"
  name: openshift-cloud-credential-operator
`)

func config_manager_namespace_yaml() ([]byte, error) {
	return _config_manager_namespace_yaml, nil
}

var _config_manager_prometheusrule_yaml = []byte(`apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: cloud-credential-operator-alerts
  namespace: openshift-cloud-credential-operator
spec:
  groups:
  - name: CloudCredentialOperator
    rules:
    - alert: CCOTargetNamespaceMissing
      expr: cco_credentials_requests_conditions{condition="MissingTargetNamespace"} > 0
      for: 5m
      labels:
        severity: warning
      annotations:
        message: CredentialsRequest(s) pointing to non-existant namespace
    - alert: CCOProvisioningFailed
      expr: cco_credentials_requests_conditions{condition="CredentialsProvisionFailure"} > 0
      for: 5m
      labels:
        severity: warning
      annotations:
        message: CredentialsRequest(s) unable to be fulfilled
    - alert: CCODeprovisioningFailed
      expr: cco_credentials_requests_conditions{condition="CredentialsDeprovisionFailure"} > 0
      for: 5m
      labels:
        severity: warning
      annotations:
        message: CredentialsRequest(s) unable to be cleaned up
    - alert: CCOInsufficientCloudCreds
      expr: cco_credentials_requests_conditions{condition="InsufficientCloudCreds"} > 0
      for: 5m
      labels:
        severity: warning
      annotations:
        message: Cluster's cloud credentials insufficient for minting or passthrough
    - alert: CCOperatorDown
      expr: absent(up{job="cco-metrics"} == 1)
      for: 5m
      labels:
        severity: critical
      annotations:
        message: cloud-credential-operator pod not running
`)

func config_manager_prometheusrule_yaml() ([]byte, error) {
	return _config_manager_prometheusrule_yaml, nil
}

var _config_manager_service_yaml = []byte(`apiVersion: v1
kind: Service
metadata:
  name: controller-manager-service
  namespace: openshift-cloud-credential-operator
  labels:
    control-plane: controller-manager
    controller-tools.k8s.io: "1.0"
spec:
  selector:
    control-plane: controller-manager
    controller-tools.k8s.io: "1.0"
  ports:
  - port: 443
`)

func config_manager_service_yaml() ([]byte, error) {
	return _config_manager_service_yaml, nil
}

var _config_manager_servicemonitor_yaml = []byte(`apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: cloud-credential-operator
  namespace: openshift-cloud-credential-operator
spec:
  endpoints:
  - bearerTokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token
    interval: 30s
    port: cco-metrics
    scheme: http
    tlsConfig:
      caFile: /etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt
      serverName: cco.openshift-cloud-credential-operator.svc
  namespaceSelector:
    matchNames:
    - openshift-cloud-credential-operator
  selector: {}
`)

func config_manager_servicemonitor_yaml() ([]byte, error) {
	return _config_manager_servicemonitor_yaml, nil
}

var _config_rbac_cloud_credential_operator_role_yaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  creationTimestamp: null
  name: cloud-credential-operator-role
rules:
- apiGroups:
  - cloudcredential.openshift.io
  resources:
  - credentialsrequests
  - credentialsrequests/status
  - credentialsrequests/finalizers
  verbs:
  - get
  - list
  - watch
  - create
  - update
  - patch
  - delete
- apiGroups:
  - ""
  resources:
  - secrets
  - configmaps
  - events
  verbs:
  - get
  - list
  - watch
  - create
  - update
  - patch
  - delete
- apiGroups:
  - ""
  resources:
  - namespaces
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - config.openshift.io
  resources:
  - clusterversions
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - config.openshift.io
  resources:
  - infrastructures
  - dnses
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - config.openshift.io
  resources:
  - clusteroperators
  - clusteroperators/status
  verbs:
  - create
  - get
  - update
  - list
  - watch
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - get
  - list
  - watch
  - update
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - get
  - list
  - watch
  - update
`)

func config_rbac_cloud_credential_operator_role_yaml() ([]byte, error) {
	return _config_rbac_cloud_credential_operator_role_yaml, nil
}

var _config_rbac_cloud_credential_operator_role_binding_yaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  creationTimestamp: null
  name: cloud-credential-operator-rolebinding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cloud-credential-operator-role
subjects:
- kind: ServiceAccount
  name: default
  namespace: system
`)

func config_rbac_cloud_credential_operator_role_binding_yaml() ([]byte, error) {
	return _config_rbac_cloud_credential_operator_role_binding_yaml, nil
}

var _config_rbac_prometheus_role_yaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: prometheus-k8s
  namespace: openshift-cloud-credential-operator
  annotations:
    exclude.release.openshift.io/internal-openshift-hosted: "true"
rules:
- apiGroups:
  - ""
  resources:
  - services
  - endpoints
  - pods
  verbs:
  - get
  - list
  - watch
`)

func config_rbac_prometheus_role_yaml() ([]byte, error) {
	return _config_rbac_prometheus_role_yaml, nil
}

var _config_rbac_prometheus_role_binding_yaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: prometheus-k8s
  namespace: openshift-cloud-credential-operator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: prometheus-k8s
subjects:
- kind: ServiceAccount
  name: prometheus-k8s
  namespace: openshift-monitoring
`)

func config_rbac_prometheus_role_binding_yaml() ([]byte, error) {
	return _config_rbac_prometheus_role_binding_yaml, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		return f()
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() ([]byte, error){
	"config/crds/cloudcredential_v1_credentialsrequest.yaml":  config_crds_cloudcredential_v1_credentialsrequest_yaml,
	"config/manager/deployment.yaml":                          config_manager_deployment_yaml,
	"config/manager/metrics-service.yaml":                     config_manager_metrics_service_yaml,
	"config/manager/namespace.yaml":                           config_manager_namespace_yaml,
	"config/manager/prometheusrule.yaml":                      config_manager_prometheusrule_yaml,
	"config/manager/service.yaml":                             config_manager_service_yaml,
	"config/manager/servicemonitor.yaml":                      config_manager_servicemonitor_yaml,
	"config/rbac/cloud-credential-operator_role.yaml":         config_rbac_cloud_credential_operator_role_yaml,
	"config/rbac/cloud-credential-operator_role_binding.yaml": config_rbac_cloud_credential_operator_role_binding_yaml,
	"config/rbac/prometheus_role.yaml":                        config_rbac_prometheus_role_yaml,
	"config/rbac/prometheus_role_binding.yaml":                config_rbac_prometheus_role_binding_yaml,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for name := range node.Children {
		rv = append(rv, name)
	}
	return rv, nil
}

type _bintree_t struct {
	Func     func() ([]byte, error)
	Children map[string]*_bintree_t
}

var _bintree = &_bintree_t{nil, map[string]*_bintree_t{
	"config": {nil, map[string]*_bintree_t{
		"crds": {nil, map[string]*_bintree_t{
			"cloudcredential_v1_credentialsrequest.yaml": {config_crds_cloudcredential_v1_credentialsrequest_yaml, map[string]*_bintree_t{}},
		}},
		"manager": {nil, map[string]*_bintree_t{
			"deployment.yaml":      {config_manager_deployment_yaml, map[string]*_bintree_t{}},
			"metrics-service.yaml": {config_manager_metrics_service_yaml, map[string]*_bintree_t{}},
			"namespace.yaml":       {config_manager_namespace_yaml, map[string]*_bintree_t{}},
			"prometheusrule.yaml":  {config_manager_prometheusrule_yaml, map[string]*_bintree_t{}},
			"service.yaml":         {config_manager_service_yaml, map[string]*_bintree_t{}},
			"servicemonitor.yaml":  {config_manager_servicemonitor_yaml, map[string]*_bintree_t{}},
		}},
		"rbac": {nil, map[string]*_bintree_t{
			"cloud-credential-operator_role.yaml":         {config_rbac_cloud_credential_operator_role_yaml, map[string]*_bintree_t{}},
			"cloud-credential-operator_role_binding.yaml": {config_rbac_cloud_credential_operator_role_binding_yaml, map[string]*_bintree_t{}},
			"prometheus_role.yaml":                        {config_rbac_prometheus_role_yaml, map[string]*_bintree_t{}},
			"prometheus_role_binding.yaml":                {config_rbac_prometheus_role_binding_yaml, map[string]*_bintree_t{}},
		}},
	}},
}}
