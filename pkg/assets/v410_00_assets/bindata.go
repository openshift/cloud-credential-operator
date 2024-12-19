// Code generated for package v410_00_assets by go-bindata DO NOT EDIT. (@generated)
// sources:
// bindata/v4.1.0/aws-pod-identity-webhook/deployment.yaml
// bindata/v4.1.0/aws-pod-identity-webhook/mutatingwebhook.yaml
// bindata/v4.1.0/azure-pod-identity-webhook/deployment.yaml
// bindata/v4.1.0/azure-pod-identity-webhook/mutatingwebhook.yaml
// bindata/v4.1.0/common/clusterrole.yaml
// bindata/v4.1.0/common/clusterrolebinding.yaml
// bindata/v4.1.0/common/poddisruptionbudget.yaml
// bindata/v4.1.0/common/role.yaml
// bindata/v4.1.0/common/rolebinding.yaml
// bindata/v4.1.0/common/sa.yaml
// bindata/v4.1.0/common/svc.yaml
package v410_00_assets

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

// Name return file name
func (fi bindataFileInfo) Name() string {
	return fi.name
}

// Size return file size
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}

// Mode return file mode
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}

// Mode return file modify time
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}

// IsDir return file whether a directory
func (fi bindataFileInfo) IsDir() bool {
	return fi.mode&os.ModeDir != 0
}

// Sys return file is sys mode
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _v410AwsPodIdentityWebhookDeploymentYaml = []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: pod-identity-webhook
  namespace: openshift-cloud-credential-operator
spec:
  replicas: 2
  selector:
    matchLabels:
      app: pod-identity-webhook
  template:
    metadata:
      annotations:
        target.workload.openshift.io/management: '{"effect": "PreferredDuringScheduling"}'
      labels:
        app: pod-identity-webhook
    spec:
      containers:
      - name: pod-identity-webhook
        image: ${IMAGE}
        imagePullPolicy: IfNotPresent
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: [ "ALL" ]
        command:
        - /usr/bin/aws-pod-identity-webhook
        - --aws-default-region=us-east-1
        - --in-cluster=false
        - --tls-cert=/var/run/app/certs/tls.crt
        - --tls-key=/var/run/app/certs/tls.key
        - --namespace=openshift-cloud-credential-operator
        - --port=9443
        - --service-name=pod-identity-webhook
        - --annotation-prefix=eks.amazonaws.com # TODO: use openshift.io based prefix
        - --token-audience=sts.amazonaws.com
        - --logtostderr
        resources:
          requests:
            cpu: 10m
            memory: 10Mi
        volumeMounts:
        - name: webhook-certs
          mountPath: /var/run/app/certs
          readOnly: false
      nodeSelector:
        node-role.kubernetes.io/master: ""
      priorityClassName: system-cluster-critical
      serviceAccountName: pod-identity-webhook
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      tolerations:
      - effect: NoSchedule
        key: node-role.kubernetes.io/master
        operator: Exists
      - effect: NoExecute
        key: node.kubernetes.io/unreachable
        operator: Exists
        tolerationSeconds: 120
      - effect: NoExecute
        key: node.kubernetes.io/not-ready
        operator: Exists
        tolerationSeconds: 120
      volumes:
      - name: webhook-certs
        secret:
          secretName: pod-identity-webhook
`)

func v410AwsPodIdentityWebhookDeploymentYamlBytes() ([]byte, error) {
	return _v410AwsPodIdentityWebhookDeploymentYaml, nil
}

func v410AwsPodIdentityWebhookDeploymentYaml() (*asset, error) {
	bytes, err := v410AwsPodIdentityWebhookDeploymentYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.1.0/aws-pod-identity-webhook/deployment.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v410AwsPodIdentityWebhookMutatingwebhookYaml = []byte(`apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: pod-identity-webhook
  annotations:
    service.beta.openshift.io/inject-cabundle: "true"
webhooks:
  - name: pod-identity-webhook.aws.mutate.io
    admissionReviewVersions:
      - v1beta1
    failurePolicy: Ignore
    sideEffects: None
    clientConfig:
      service:
        name: pod-identity-webhook
        namespace: openshift-cloud-credential-operator
        path: "/mutate"
    namespaceSelector:
      matchExpressions:
        - key: openshift.io/run-level
          operator: NotIn
          values:
            - "0"
    rules:
      - operations: [ "CREATE" ]
        apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
`)

func v410AwsPodIdentityWebhookMutatingwebhookYamlBytes() ([]byte, error) {
	return _v410AwsPodIdentityWebhookMutatingwebhookYaml, nil
}

func v410AwsPodIdentityWebhookMutatingwebhookYaml() (*asset, error) {
	bytes, err := v410AwsPodIdentityWebhookMutatingwebhookYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.1.0/aws-pod-identity-webhook/mutatingwebhook.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v410AzurePodIdentityWebhookDeploymentYaml = []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    azure-workload-identity.io/system: "true"
  name: pod-identity-webhook
  namespace: openshift-cloud-credential-operator
spec:
  replicas: 2
  selector:
    matchLabels:
      app: pod-identity-webhook
  template:
    metadata:
      annotations:
        target.workload.openshift.io/management: '{"effect": "PreferredDuringScheduling"}'
      labels:
        app: pod-identity-webhook
    spec:
      containers:
        - args:
            - --log-level=info
            - --disable-cert-rotation=true
          command:
            - /usr/bin/azure-workload-identity-webhook
          env:
            - name: AZURE_TENANT_ID
              valueFrom:
                secretKeyRef:
                  name: azure-credentials
                  key: azure_tenant_id
            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  apiVersion: v1
                  fieldPath: metadata.namespace
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          livenessProbe:
            failureThreshold: 6
            httpGet:
              path: /healthz
              port: healthz
            initialDelaySeconds: 15
            periodSeconds: 20
          name: pod-identity-webhook
          resources:
            requests:
              cpu: 10m
              memory: 10Mi
          ports:
            - containerPort: 6443
              name: webhook-server
              protocol: TCP
            - containerPort: 8095
              name: metrics
              protocol: TCP
            - containerPort: 9440
              name: healthz
              protocol: TCP
          readinessProbe:
            httpGet:
              path: /readyz
              port: healthz
            initialDelaySeconds: 5
            periodSeconds: 5
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: [ "ALL" ]
          volumeMounts:
            - mountPath: /certs
              name: webhook-certs
              readOnly: true
      nodeSelector:
        node-role.kubernetes.io/master: ""
      tolerations:
        - effect: NoSchedule
          key: node-role.kubernetes.io/master
          operator: Exists
        - effect: NoExecute
          key: node.kubernetes.io/unreachable
          operator: Exists
          tolerationSeconds: 120
        - effect: NoExecute
          key: node.kubernetes.io/not-ready
          operator: Exists
          tolerationSeconds: 120
      priorityClassName: system-cluster-critical
      serviceAccountName: pod-identity-webhook
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      volumes:
        - name: webhook-certs
          secret:
            secretName: pod-identity-webhook
`)

func v410AzurePodIdentityWebhookDeploymentYamlBytes() ([]byte, error) {
	return _v410AzurePodIdentityWebhookDeploymentYaml, nil
}

func v410AzurePodIdentityWebhookDeploymentYaml() (*asset, error) {
	bytes, err := v410AzurePodIdentityWebhookDeploymentYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.1.0/azure-pod-identity-webhook/deployment.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v410AzurePodIdentityWebhookMutatingwebhookYaml = []byte(`apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: pod-identity-webhook
  annotations:
    service.beta.openshift.io/inject-cabundle: "true"
webhooks:
  - admissionReviewVersions:
      - v1
      - v1beta1
    clientConfig:
      service:
        name: pod-identity-webhook
        namespace: openshift-cloud-credential-operator
        path: /mutate-v1-pod
    failurePolicy: Fail
    matchPolicy: Equivalent
    name: pod-identity-webhook.azure.mutate.io
    objectSelector:
      matchLabels:
        azure.workload.identity/use: "true"
    reinvocationPolicy: IfNeeded
    rules:
      - apiGroups:
          - ""
        apiVersions:
          - v1
        operations:
          - CREATE
        resources:
          - pods
    sideEffects: None
`)

func v410AzurePodIdentityWebhookMutatingwebhookYamlBytes() ([]byte, error) {
	return _v410AzurePodIdentityWebhookMutatingwebhookYaml, nil
}

func v410AzurePodIdentityWebhookMutatingwebhookYaml() (*asset, error) {
	bytes, err := v410AzurePodIdentityWebhookMutatingwebhookYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.1.0/azure-pod-identity-webhook/mutatingwebhook.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v410CommonClusterroleYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-identity-webhook
rules:
- apiGroups:
  - ""
  resources:
  - serviceaccounts
  verbs:
  - get
  - watch
  - list
`)

func v410CommonClusterroleYamlBytes() ([]byte, error) {
	return _v410CommonClusterroleYaml, nil
}

func v410CommonClusterroleYaml() (*asset, error) {
	bytes, err := v410CommonClusterroleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.1.0/common/clusterrole.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v410CommonClusterrolebindingYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: pod-identity-webhook
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: pod-identity-webhook
subjects:
- kind: ServiceAccount
  name: pod-identity-webhook
  namespace: openshift-cloud-credential-operator
`)

func v410CommonClusterrolebindingYamlBytes() ([]byte, error) {
	return _v410CommonClusterrolebindingYaml, nil
}

func v410CommonClusterrolebindingYaml() (*asset, error) {
	bytes, err := v410CommonClusterrolebindingYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.1.0/common/clusterrolebinding.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v410CommonPoddisruptionbudgetYaml = []byte(`apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: pod-identity-webhook
  namespace: openshift-cloud-credential-operator
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: pod-identity-webhook
`)

func v410CommonPoddisruptionbudgetYamlBytes() ([]byte, error) {
	return _v410CommonPoddisruptionbudgetYaml, nil
}

func v410CommonPoddisruptionbudgetYaml() (*asset, error) {
	bytes, err := v410CommonPoddisruptionbudgetYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.1.0/common/poddisruptionbudget.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v410CommonRoleYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-identity-webhook
  namespace: openshift-cloud-credential-operator
rules:
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - create
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - get
  - update
  - patch
  resourceNames:
  - "pod-identity-webhook"
`)

func v410CommonRoleYamlBytes() ([]byte, error) {
	return _v410CommonRoleYaml, nil
}

func v410CommonRoleYaml() (*asset, error) {
	bytes, err := v410CommonRoleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.1.0/common/role.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v410CommonRolebindingYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pod-identity-webhook
  namespace: openshift-cloud-credential-operator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-identity-webhook
subjects:
- kind: ServiceAccount
  name: pod-identity-webhook
  namespace: openshift-cloud-credential-operator
`)

func v410CommonRolebindingYamlBytes() ([]byte, error) {
	return _v410CommonRolebindingYaml, nil
}

func v410CommonRolebindingYaml() (*asset, error) {
	bytes, err := v410CommonRolebindingYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.1.0/common/rolebinding.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v410CommonSaYaml = []byte(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: pod-identity-webhook
  namespace: openshift-cloud-credential-operator
`)

func v410CommonSaYamlBytes() ([]byte, error) {
	return _v410CommonSaYaml, nil
}

func v410CommonSaYaml() (*asset, error) {
	bytes, err := v410CommonSaYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.1.0/common/sa.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v410CommonSvcYaml = []byte(`apiVersion: v1
kind: Service
metadata:
  name: pod-identity-webhook
  namespace: openshift-cloud-credential-operator
  annotations:
    prometheus.io/port: "443"
    prometheus.io/scheme: "https"
    prometheus.io/scrape: "true"
    service.beta.openshift.io/serving-cert-secret-name: pod-identity-webhook
spec:
  ports:
  - port: 443
    targetPort: 9443
  selector:
    app: pod-identity-webhook
`)

func v410CommonSvcYamlBytes() ([]byte, error) {
	return _v410CommonSvcYaml, nil
}

func v410CommonSvcYaml() (*asset, error) {
	bytes, err := v410CommonSvcYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.1.0/common/svc.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
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
var _bindata = map[string]func() (*asset, error){
	"v4.1.0/aws-pod-identity-webhook/deployment.yaml":        v410AwsPodIdentityWebhookDeploymentYaml,
	"v4.1.0/aws-pod-identity-webhook/mutatingwebhook.yaml":   v410AwsPodIdentityWebhookMutatingwebhookYaml,
	"v4.1.0/azure-pod-identity-webhook/deployment.yaml":      v410AzurePodIdentityWebhookDeploymentYaml,
	"v4.1.0/azure-pod-identity-webhook/mutatingwebhook.yaml": v410AzurePodIdentityWebhookMutatingwebhookYaml,
	"v4.1.0/common/clusterrole.yaml":                         v410CommonClusterroleYaml,
	"v4.1.0/common/clusterrolebinding.yaml":                  v410CommonClusterrolebindingYaml,
	"v4.1.0/common/poddisruptionbudget.yaml":                 v410CommonPoddisruptionbudgetYaml,
	"v4.1.0/common/role.yaml":                                v410CommonRoleYaml,
	"v4.1.0/common/rolebinding.yaml":                         v410CommonRolebindingYaml,
	"v4.1.0/common/sa.yaml":                                  v410CommonSaYaml,
	"v4.1.0/common/svc.yaml":                                 v410CommonSvcYaml,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//
//	data/
//	  foo.txt
//	  img/
//	    a.png
//	    b.png
//
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
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"v4.1.0": {nil, map[string]*bintree{
		"aws-pod-identity-webhook": {nil, map[string]*bintree{
			"deployment.yaml":      {v410AwsPodIdentityWebhookDeploymentYaml, map[string]*bintree{}},
			"mutatingwebhook.yaml": {v410AwsPodIdentityWebhookMutatingwebhookYaml, map[string]*bintree{}},
		}},
		"azure-pod-identity-webhook": {nil, map[string]*bintree{
			"deployment.yaml":      {v410AzurePodIdentityWebhookDeploymentYaml, map[string]*bintree{}},
			"mutatingwebhook.yaml": {v410AzurePodIdentityWebhookMutatingwebhookYaml, map[string]*bintree{}},
		}},
		"common": {nil, map[string]*bintree{
			"clusterrole.yaml":         {v410CommonClusterroleYaml, map[string]*bintree{}},
			"clusterrolebinding.yaml":  {v410CommonClusterrolebindingYaml, map[string]*bintree{}},
			"poddisruptionbudget.yaml": {v410CommonPoddisruptionbudgetYaml, map[string]*bintree{}},
			"role.yaml":                {v410CommonRoleYaml, map[string]*bintree{}},
			"rolebinding.yaml":         {v410CommonRolebindingYaml, map[string]*bintree{}},
			"sa.yaml":                  {v410CommonSaYaml, map[string]*bintree{}},
			"svc.yaml":                 {v410CommonSvcYaml, map[string]*bintree{}},
		}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
