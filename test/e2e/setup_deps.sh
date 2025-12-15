#!/bin/bash
set -e

cd /home/minl/cloud-credential-operator/test/e2e

OTP_PATH="/home/minl/openshift-tests-private"
ORIGIN_VERSION="v1.5.0-alpha.3.0.20251203005656-6264449a6c8b"

echo "Step 2: Add required dependencies..."
echo "Using openshift/origin version: $ORIGIN_VERSION (from openshift-tests-private)"

# Add dependencies with retry logic for network issues
echo "Adding openshift-tests-extension dependency..."
go get github.com/openshift-eng/openshift-tests-extension@latest || {
    echo "⚠️  Warning: Failed to download openshift-tests-extension, retrying..."
    sleep 2
    go get github.com/openshift-eng/openshift-tests-extension@latest || echo "❌ Failed after retry"
}

echo "Adding openshift/origin dependency..."
go get "github.com/openshift/origin@$ORIGIN_VERSION" || {
    echo "⚠️  Warning: Failed to download openshift/origin, retrying..."
    sleep 2
    go get "github.com/openshift/origin@$ORIGIN_VERSION" || echo "❌ Failed after retry"
}

echo "Adding Ginkgo and Gomega dependencies..."
go get github.com/onsi/ginkgo/v2@latest || {
    echo "⚠️  Warning: Failed to download ginkgo, retrying..."
    sleep 2
    go get github.com/onsi/ginkgo/v2@latest || echo "❌ Failed after retry"
}

go get github.com/onsi/gomega@latest || {
    echo "⚠️  Warning: Failed to download gomega, retrying..."
    sleep 2
    go get github.com/onsi/gomega@latest || echo "❌ Failed after retry"
}

echo "Step 3: Add k8s.io replace directives..."
# Get k8s.io version from openshift-tests-private
K8S_VERSION=$(grep "k8s.io/api " "$OTP_PATH/go.mod" | head -1 | awk '{print $2}')
echo "Using k8s.io version: $K8S_VERSION (from openshift-tests-private)"

# Extract OpenShift Kubernetes fork version
K8S_FORK=$(grep "k8s.io/kubernetes =>" "$OTP_PATH/go.mod" | awk '{print $4, $5}')
echo "Using OpenShift Kubernetes fork: $K8S_FORK"

cat >> go.mod <<'EOF'

replace (
	k8s.io/api => k8s.io/api v0.34.1
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.34.1
	k8s.io/apimachinery => k8s.io/apimachinery v0.34.1
	k8s.io/apiserver => k8s.io/apiserver v0.34.1
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.34.1
	k8s.io/client-go => k8s.io/client-go v0.34.1
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.34.1
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.34.1
	k8s.io/code-generator => k8s.io/code-generator v0.34.1
	k8s.io/component-base => k8s.io/component-base v0.34.1
	k8s.io/component-helpers => k8s.io/component-helpers v0.34.1
	k8s.io/controller-manager => k8s.io/controller-manager v0.34.1
	k8s.io/cri-api => k8s.io/cri-api v0.34.1
	k8s.io/cri-client => k8s.io/cri-client v0.34.1
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.34.1
	k8s.io/dynamic-resource-allocation => k8s.io/dynamic-resource-allocation v0.34.1
	k8s.io/kms => k8s.io/kms v0.34.1
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.34.1
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.34.1
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.34.1
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.34.1
	k8s.io/kubectl => k8s.io/kubectl v0.34.1
	k8s.io/kubelet => k8s.io/kubelet v0.34.1
	k8s.io/kubernetes => github.com/openshift/kubernetes v1.34.1-openshift-4.19.0-alpha.0.0.20251202204720-2a9bb134efec
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.34.1
	k8s.io/metrics => k8s.io/metrics v0.34.1
	k8s.io/mount-utils => k8s.io/mount-utils v0.34.1
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.34.1
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.34.1
	k8s.io/sample-cli-plugin => k8s.io/sample-cli-plugin v0.34.1
	k8s.io/sample-controller => k8s.io/sample-controller v0.34.1
)
EOF

echo "Step 4: Resolve all dependencies..."
go mod tidy || {
    echo "⚠️  Warning: go mod tidy failed, retrying..."
    sleep 2
    go mod tidy || echo "❌ go mod tidy failed after retry"
}

# Check for invalid local replace directives
if grep -q "replace.*github.com/openshift/origin.*=>.*/" go.mod; then
    echo "WARNING: Removing invalid local replace directive for github.com/openshift/origin"
    sed -i '/replace.*github.com\/openshift\/origin.*=>.*\//d' go.mod
    go mod tidy
fi

echo "Step 4.5: Download all dependencies..."
go mod download || {
    echo "⚠️  Warning: go mod download failed, retrying..."
    sleep 2
    go mod download || echo "❌ Dependency download failed after retry"
}

echo "Step 5: Verify go.mod and go.sum are created..."
if [ -f "go.mod" ] && [ -f "go.sum" ]; then
    echo "✅ go.mod and go.sum created successfully"
    echo "Module: $(grep '^module' go.mod)"
    echo "Dependencies: $(grep -c '^require' go.mod) direct dependencies"

    # Count k8s.io replace directives
    K8S_REPLACES=$(grep -c '^\sk8s.io.*=>' go.mod || echo 0)
    echo "K8s replace directives: $K8S_REPLACES"

    # Verify critical replace directive exists
    if grep -q "k8s.io/kubernetes =>" go.mod; then
        echo "✅ OpenShift Kubernetes fork replace directive added"
    else
        echo "⚠️  Warning: k8s.io/kubernetes replace directive not found"
    fi
else
    echo "❌ Error: go.mod or go.sum not created properly"
    exit 1
fi

echo "✅ Test module setup complete!"
