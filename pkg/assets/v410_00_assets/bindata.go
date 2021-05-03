// Code generated for package v410_00_assets by go-bindata DO NOT EDIT. (@generated)
// sources:
// bindata/v4.1.0/aws-pod-identity-webhook/clusterrole.yaml
// bindata/v4.1.0/aws-pod-identity-webhook/clusterrolebinding.yaml
// bindata/v4.1.0/aws-pod-identity-webhook/deployment.yaml
// bindata/v4.1.0/aws-pod-identity-webhook/mutatingwebhook.yaml
// bindata/v4.1.0/aws-pod-identity-webhook/role.yaml
// bindata/v4.1.0/aws-pod-identity-webhook/rolebinding.yaml
// bindata/v4.1.0/aws-pod-identity-webhook/sa.yaml
// bindata/v4.1.0/aws-pod-identity-webhook/svc.yaml
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

var _v410AwsPodIdentityWebhookClusterroleYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
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

func v410AwsPodIdentityWebhookClusterroleYamlBytes() ([]byte, error) {
	return _v410AwsPodIdentityWebhookClusterroleYaml, nil
}

func v410AwsPodIdentityWebhookClusterroleYaml() (*asset, error) {
	bytes, err := v410AwsPodIdentityWebhookClusterroleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.1.0/aws-pod-identity-webhook/clusterrole.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v410AwsPodIdentityWebhookClusterrolebindingYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
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

func v410AwsPodIdentityWebhookClusterrolebindingYamlBytes() ([]byte, error) {
	return _v410AwsPodIdentityWebhookClusterrolebindingYaml, nil
}

func v410AwsPodIdentityWebhookClusterrolebindingYaml() (*asset, error) {
	bytes, err := v410AwsPodIdentityWebhookClusterrolebindingYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.1.0/aws-pod-identity-webhook/clusterrolebinding.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v410AwsPodIdentityWebhookDeploymentYaml = []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: pod-identity-webhook
  namespace: openshift-cloud-credential-operator
spec:
  replicas: 1
  selector:
    matchLabels:
      app: pod-identity-webhook
  template:
    metadata:
      labels:
        app: pod-identity-webhook
    spec:
      containers:
      - name: pod-identity-webhook
        image: ${IMAGE}
        imagePullPolicy: IfNotPresent
        command:
        - /usr/bin/aws-pod-identity-webhook
        - --in-cluster
        - --namespace=openshift-cloud-credential-operator
        - --port=6443
        - --service-name=pod-identity-webhook
        - --tls-secret=pod-identity-webhook
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
        emptyDir: {}
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

var _v410AwsPodIdentityWebhookMutatingwebhookYaml = []byte(`apiVersion: admissionregistration.k8s.io/v1beta1
kind: MutatingWebhookConfiguration
metadata:
  name: pod-identity-webhook
  annotations:
    service.beta.openshift.io/inject-cabundle: "true"
webhooks:
- name: pod-identity-webhook.amazonaws.com
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

var _v410AwsPodIdentityWebhookRoleYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
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

func v410AwsPodIdentityWebhookRoleYamlBytes() ([]byte, error) {
	return _v410AwsPodIdentityWebhookRoleYaml, nil
}

func v410AwsPodIdentityWebhookRoleYaml() (*asset, error) {
	bytes, err := v410AwsPodIdentityWebhookRoleYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.1.0/aws-pod-identity-webhook/role.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v410AwsPodIdentityWebhookRolebindingYaml = []byte(`apiVersion: rbac.authorization.k8s.io/v1
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

func v410AwsPodIdentityWebhookRolebindingYamlBytes() ([]byte, error) {
	return _v410AwsPodIdentityWebhookRolebindingYaml, nil
}

func v410AwsPodIdentityWebhookRolebindingYaml() (*asset, error) {
	bytes, err := v410AwsPodIdentityWebhookRolebindingYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.1.0/aws-pod-identity-webhook/rolebinding.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v410AwsPodIdentityWebhookSaYaml = []byte(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: pod-identity-webhook
  namespace: openshift-cloud-credential-operator
`)

func v410AwsPodIdentityWebhookSaYamlBytes() ([]byte, error) {
	return _v410AwsPodIdentityWebhookSaYaml, nil
}

func v410AwsPodIdentityWebhookSaYaml() (*asset, error) {
	bytes, err := v410AwsPodIdentityWebhookSaYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.1.0/aws-pod-identity-webhook/sa.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _v410AwsPodIdentityWebhookSvcYaml = []byte(`apiVersion: v1
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
    targetPort: 6443
  selector:
    app: pod-identity-webhook
`)

func v410AwsPodIdentityWebhookSvcYamlBytes() ([]byte, error) {
	return _v410AwsPodIdentityWebhookSvcYaml, nil
}

func v410AwsPodIdentityWebhookSvcYaml() (*asset, error) {
	bytes, err := v410AwsPodIdentityWebhookSvcYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "v4.1.0/aws-pod-identity-webhook/svc.yaml", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
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
	"v4.1.0/aws-pod-identity-webhook/clusterrole.yaml":        v410AwsPodIdentityWebhookClusterroleYaml,
	"v4.1.0/aws-pod-identity-webhook/clusterrolebinding.yaml": v410AwsPodIdentityWebhookClusterrolebindingYaml,
	"v4.1.0/aws-pod-identity-webhook/deployment.yaml":         v410AwsPodIdentityWebhookDeploymentYaml,
	"v4.1.0/aws-pod-identity-webhook/mutatingwebhook.yaml":    v410AwsPodIdentityWebhookMutatingwebhookYaml,
	"v4.1.0/aws-pod-identity-webhook/role.yaml":               v410AwsPodIdentityWebhookRoleYaml,
	"v4.1.0/aws-pod-identity-webhook/rolebinding.yaml":        v410AwsPodIdentityWebhookRolebindingYaml,
	"v4.1.0/aws-pod-identity-webhook/sa.yaml":                 v410AwsPodIdentityWebhookSaYaml,
	"v4.1.0/aws-pod-identity-webhook/svc.yaml":                v410AwsPodIdentityWebhookSvcYaml,
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
			"clusterrole.yaml":        {v410AwsPodIdentityWebhookClusterroleYaml, map[string]*bintree{}},
			"clusterrolebinding.yaml": {v410AwsPodIdentityWebhookClusterrolebindingYaml, map[string]*bintree{}},
			"deployment.yaml":         {v410AwsPodIdentityWebhookDeploymentYaml, map[string]*bintree{}},
			"mutatingwebhook.yaml":    {v410AwsPodIdentityWebhookMutatingwebhookYaml, map[string]*bintree{}},
			"role.yaml":               {v410AwsPodIdentityWebhookRoleYaml, map[string]*bintree{}},
			"rolebinding.yaml":        {v410AwsPodIdentityWebhookRolebindingYaml, map[string]*bintree{}},
			"sa.yaml":                 {v410AwsPodIdentityWebhookSaYaml, map[string]*bintree{}},
			"svc.yaml":                {v410AwsPodIdentityWebhookSvcYaml, map[string]*bintree{}},
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
