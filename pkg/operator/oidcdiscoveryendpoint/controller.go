package oidcdiscoveryendpoint

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	jose "gopkg.in/square/go-jose.v2"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/service/s3"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configset "github.com/openshift/client-go/config/clientset/versioned"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cloud-credential-operator/pkg/operator/constants"
	"github.com/openshift/cloud-credential-operator/pkg/operator/platform"
	awsannotator "github.com/openshift/cloud-credential-operator/pkg/operator/secretannotator/aws"
	"github.com/openshift/cloud-credential-operator/pkg/operator/status"
	awsutils "github.com/openshift/cloud-credential-operator/pkg/operator/utils/aws"
)

const (
	controllerName                = "oidcdiscoveryendpoint"
	deploymentName                = "cloud-credential-operator"
	operatorNamespace             = "openshift-cloud-credential-operator"
	tokenSignerConfigMapName      = "bound-sa-token-signing-certs"
	tokenSignerConfigMapNamespace = "openshift-kube-apiserver"
	credentialsSecretNamespace    = "openshift-cloud-credential-operator"
	credentialsSecretName         = "cloud-credential-operator-s3-creds"
	discoveryURI                  = ".well-known/openid-configuration"
	keysURI                       = "keys.json"
	reasonAuthReconcileFailed     = "AuthReconcileFailed"
	reasonS3ReconcileFailed       = "S3ReconcileFailed"
	discoveryTemplate             = `{
	"issuer": "%s",
	"jwks_uri": "%s/%s",
	"authorization_endpoint": "urn:kubernetes:programmatic_authorization",
	"response_types_supported": [
		"id_token"
	],
	"subject_types_supported": [
		"public"
	],
	"id_token_signing_alg_values_supported": [
		"RS256"
	],
	"claims_supported": [
		"sub",
		"iss"
	]
}`
)

type oidcDiscoveryEndpointController struct {
	reconciler *s3EndpointReconciler
	cache      cache.Cache
	logger     log.FieldLogger
}

func (c *oidcDiscoveryEndpointController) Start(stopCh <-chan struct{}) error {
	go c.cache.Start(stopCh)
	<-stopCh
	return nil
}

func Add(mgr manager.Manager, kubeconfig string) error {
	infraStatus, err := platform.GetInfraStatusUsingKubeconfig(mgr, kubeconfig)
	if err != nil {
		return err
	}
	platformType := platform.GetType(infraStatus)
	if platformType != configv1.AWSPlatformType {
		return nil
	}

	log.Info("setting up AWS OIDC Discovery Endpoint Controller")

	config := mgr.GetConfig()
	kubeclientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	configclientset, err := configset.NewForConfig(config)
	if err != nil {
		return err
	}

	controllerRef := &corev1.ObjectReference{
		Kind:      "deployment",
		Namespace: operatorNamespace,
		Name:      deploymentName,
	}
	eventRecorder := events.NewKubeRecorder(kubeclientset.CoreV1().Events(operatorNamespace), deploymentName, controllerRef)
	logger := log.WithFields(log.Fields{"controller": controllerName})

	if infraStatus.PlatformStatus == nil || infraStatus.PlatformStatus.AWS == nil {
		return fmt.Errorf("Infrastructure platform status is not set")
	}

	r := &s3EndpointReconciler{
		controllerRuntimeClient: mgr.GetClient(),
		kubeclientset:           kubeclientset,
		configclientset:         configclientset,
		logger:                  logger,
		eventRecorder:           eventRecorder,
		infrastructureName:      infraStatus.InfrastructureName,
		region:                  infraStatus.PlatformStatus.AWS.Region,
		degraded:                configv1.ClusterOperatorStatusCondition{Status: configv1.ConditionFalse},
	}

	c, err := controller.New(controllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	p := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			return isServiceAccountTokenSigner(e.MetaNew)
		},
		CreateFunc: func(e event.CreateEvent) bool {
			return isServiceAccountTokenSigner(e.Meta)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			// Deleting the token signer configmap shouldn't be done.
			// Be safe and don't react.  When the openshift-kube-apiserver-operator
			// recreates it, we'll catch it.
			return false
		},
	}

	// Create a namespace local cache separate from the Manager cache
	// A namespace scoped cache can still handle cluster scoped resources
	cache, err := cache.New(config, cache.Options{Namespace: tokenSignerConfigMapNamespace})
	if err != nil {
		return err
	}

	informer, err := cache.GetInformer(context.TODO(), &corev1.ConfigMap{})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Informer{Informer: informer}, &handler.EnqueueRequestForObject{}, p)
	if err != nil {
		return err
	}

	status.AddHandler(controllerName, r)
	mgr.Add(&oidcDiscoveryEndpointController{reconciler: r, cache: cache, logger: logger})

	return nil
}

func isServiceAccountTokenSigner(meta metav1.Object) bool {
	// all managed resources are named pod-identity-webhook
	if meta.GetName() == tokenSignerConfigMapName {
		return true
	}
	return false
}

type s3EndpointReconciler struct {
	controllerRuntimeClient client.Client
	kubeclientset           *kubernetes.Clientset
	configclientset         *configset.Clientset
	logger                  log.FieldLogger
	eventRecorder           events.Recorder
	infrastructureName      string
	region                  string
	degraded                configv1.ClusterOperatorStatusCondition
}

var _ reconcile.Reconciler = &s3EndpointReconciler{}

func (r *s3EndpointReconciler) Reconcile(request reconcile.Request) (returnResult reconcile.Result, returnErr error) {
	r.logger.Info("reconciling AWS S3 OIDC discovery endpoint")

	// SyncStatus only if our degraded condition changed
	defer func(initialDegradedCondition configv1.ClusterOperatorStatusCondition) {
		if !status.ConditionEqual(initialDegradedCondition, r.degraded) {
			// There are situations that cause this controller to go degraded that the status controller
			// cannot watch for. So just update the config CR (which the status controller does watch)
			// to trigger a status recalculation.
			if err := r.updateConfigCRTimestamp(); err != nil {
				r.logger.WithError(err).Error("failed to updated config CR to trigger status calculation")
				// make sure we force a re-reconcile if we were unable to calculate status by preserving
				// the previous degraded condition, and returning an error
				r.degraded = initialDegradedCondition
				if returnErr == nil {
					returnErr = err
				}
			}
		}
	}(r.degraded)

	isUnmanaged, err := r.reconcileServiceAccountIssuer()
	if err != nil {
		r.logger.WithError(err).Error("failed reconciling cluster Authentication CR")
		r.degraded = configv1.ClusterOperatorStatusCondition{
			Status:  configv1.ConditionTrue,
			Reason:  reasonAuthReconcileFailed,
			Message: fmt.Sprintf("%s controller: failed reconciling cluster Authentication CR: %v", controllerName, err),
		}
		return reconcile.Result{Requeue: true}, err
	}
	if isUnmanaged {
		return reconcile.Result{}, nil
	}

	err = r.reconcileS3Resources()
	if err != nil {
		r.logger.WithError(err).Error("failed reconciling S3 resources")
		r.degraded = configv1.ClusterOperatorStatusCondition{
			Status:  configv1.ConditionTrue,
			Reason:  reasonS3ReconcileFailed,
			Message: fmt.Sprintf("%s controller: failed reconciling S3 resources: %v", controllerName, err),
		}
		return reconcile.Result{Requeue: true}, err
	}

	r.degraded = configv1.ClusterOperatorStatusCondition{
		Status: configv1.ConditionFalse,
	}

	return reconcile.Result{}, nil
}

// reconcileServiceAccountIssuer sets the ServiceAccountIssuer in the cluster Authentication
// config if it is not set already.  Returned boolean indicates whether or not the rest of
// the reconciliation should be skipped in the event the cluster is configured with a different
// OIDC endpoint.
func (r *s3EndpointReconciler) reconcileServiceAccountIssuer() (bool, error) {
	r.logger.Debugf("reconciling cluster Authentication ServiceAccountIssuer")

	auth, err := r.configclientset.ConfigV1().Authentications().Get(context.TODO(), "cluster", metav1.GetOptions{})
	if err != nil {
		return false, err
	}

	serviceAccountIssuer := r.getIssuerURL()
	if auth.Spec.ServiceAccountIssuer != "" {
		r.logger.Debug("Authentication ServiceAccountIssuer already specified")
		if auth.Spec.ServiceAccountIssuer != serviceAccountIssuer {
			r.logger.Info("Authentication ServiceAccountIssuer is not set to the s3 bucket location, skipping OIDC reconciliation")
			return true, nil
		}
		return false, nil
	}

	newAuth := auth.DeepCopy()
	newAuth.Spec.ServiceAccountIssuer = serviceAccountIssuer
	_, err = r.configclientset.ConfigV1().Authentications().Update(context.TODO(), newAuth, metav1.UpdateOptions{})

	return false, err
}

func (r *s3EndpointReconciler) getIssuerURL() string {
	if r.region == "" {
		return fmt.Sprintf("https://%s.s3.amazonaws.com", r.getBucketName())
	}
	endpoint, err := endpoints.DefaultResolver().EndpointFor(endpoints.S3ServiceID, r.region)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("https://%s.%s", r.getBucketName(), strings.TrimPrefix(endpoint.URL, "https://"))
}

func (r *s3EndpointReconciler) getBucketName() string {
	return fmt.Sprintf("%s-oidc", r.infrastructureName)
}

func (r *s3EndpointReconciler) reconcileS3Resources() error {
	r.logger.Debugf("reconciling S3 resources")

	// Get the root secret and create an AWS client
	secret, err := r.kubeclientset.CoreV1().Secrets(credentialsSecretNamespace).Get(context.TODO(), credentialsSecretName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	accessKey, ok := secret.Data[awsannotator.AwsAccessKeyName]
	if !ok {
		return fmt.Errorf("couldn't fetch key containing %s from cloud cred secret", awsannotator.AwsAccessKeyName)
	}

	secretKey, ok := secret.Data[awsannotator.AwsSecretAccessKeyName]
	if !ok {
		return fmt.Errorf("couldn't fetch key containing %s from cloud cred secret", awsannotator.AwsSecretAccessKeyName)
	}

	awsClient, err := awsutils.ClientBuilder(accessKey, secretKey, r.controllerRuntimeClient)
	if err != nil {
		return fmt.Errorf("error creating aws client: %v", err)
	}

	// Ensure bucket exists
	bucketName := r.getBucketName()
	_, err = awsClient.CreateBucket(&s3.CreateBucketInput{
		Bucket: awssdk.String(bucketName),
	})
	if err != nil {
		var aerr awserr.Error
		if errors.As(err, &aerr) {
			switch aerr.Code() {
			case s3.ErrCodeBucketAlreadyExists:
				r.logger.WithField("bucket", bucketName).WithError(aerr).Error("bucket already exists but it not owned by us")
				return aerr
			case s3.ErrCodeBucketAlreadyOwnedByYou:
				r.logger.WithField("bucket", bucketName).Debug("bucket already exists and is owned by us")
			default:
				r.logger.WithField("bucket", bucketName).WithError(aerr).Error("CreateBucket failed")
				return fmt.Errorf("CreateBucket failed with %s", aerr.Code())
			}
		} else {
			return err
		}
	} else {
		r.logger.WithField("bucket", bucketName).Info("bucket created")
	}

	// Tag bucket for deprovisioning
	_, err = awsClient.PutBucketTagging(&s3.PutBucketTaggingInput{
		Bucket: awssdk.String(bucketName),
		Tagging: &s3.Tagging{
			TagSet: []*s3.Tag{{
				Key:   awssdk.String("kubernetes.io/cluster/" + r.infrastructureName),
				Value: awssdk.String("owned"),
			}},
		},
	})
	if err != nil {
		var aerr awserr.Error
		if errors.As(err, &aerr) {
			r.logger.WithField("bucket", bucketName).WithError(aerr).Error("PutBucketTagging failed")
			return fmt.Errorf("PutBucketTagging failed with %s", aerr.Code())
		}
		return err
	}
	r.logger.WithField("bucket", bucketName).Debug("bucket tagged")

	// Render and create the OIDC discovery JSON s3 object in the well-known location
	issuerURL := r.getIssuerURL()
	discoveryJSON := fmt.Sprintf(discoveryTemplate, issuerURL, issuerURL, keysURI)
	_, err = awsClient.PutObject(&s3.PutObjectInput{
		ACL:    awssdk.String("public-read"),
		Body:   awssdk.ReadSeekCloser(strings.NewReader(discoveryJSON)),
		Bucket: awssdk.String(bucketName),
		Key:    awssdk.String(discoveryURI),
	})
	if err != nil {
		var aerr awserr.Error
		if errors.As(err, &aerr) {
			r.logger.WithField("bucket", bucketName).WithError(aerr).Error("discovery document PutObject failed")
			return fmt.Errorf("discovery document PutObject failed with %s", aerr.Code())
		}
		return err
	}
	r.logger.WithField("bucket", bucketName).Debug("discovery document updated")

	// Extract the token signer and create keys JSON s3 object for jwks_uri
	tokenSignerConfigMap, err := r.kubeclientset.CoreV1().ConfigMaps(tokenSignerConfigMapNamespace).Get(context.TODO(), tokenSignerConfigMapName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	pemKeys := [][]byte{}
	for _, pemKey := range tokenSignerConfigMap.Data {
		pemKeys = append(pemKeys, []byte(pemKey))
	}
	if len(pemKeys) < 1 {
		return fmt.Errorf("no signing keys found in config map %s/%s", tokenSignerConfigMapNamespace, tokenSignerConfigMapName)
	}

	keysJSON, err := encodeKeys(pemKeys)
	if err != nil {
		return err
	}

	_, err = awsClient.PutObject(&s3.PutObjectInput{
		ACL:    awssdk.String("public-read"),
		Body:   awssdk.ReadSeekCloser(bytes.NewReader(keysJSON)),
		Bucket: awssdk.String(bucketName),
		Key:    awssdk.String(keysURI),
	})
	if err != nil {
		var aerr awserr.Error
		if errors.As(err, &aerr) {
			r.logger.WithField("bucket", bucketName).WithError(aerr).Error("keys document PutObject failed")
			return fmt.Errorf("keys document PutObject failed with %s", aerr.Code())
		}
		return err
	}
	r.logger.WithField("bucket", bucketName).Debug("keys document updated")

	return nil
}

// Below this line based on https://github.com/openshift/aws-pod-identity-webhook/blob/master/hack/self-hosted/main.go

// copied from kubernetes/kubernetes#78502
func keyIDFromPublicKey(publicKey interface{}) (string, error) {
	publicKeyDERBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to serialize public key to DER format: %v", err)
	}

	hasher := crypto.SHA256.New()
	hasher.Write(publicKeyDERBytes)
	publicKeyDERHash := hasher.Sum(nil)

	keyID := base64.RawURLEncoding.EncodeToString(publicKeyDERHash)

	return keyID, nil
}

type keyResponse struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

func encodeKeys(pemKeys [][]byte) ([]byte, error) {
	var keys []jose.JSONWebKey
	var response []byte
	for _, key := range pemKeys {
		block, _ := pem.Decode(key)
		if block == nil {
			return response, errors.New("error decoding PEM key")
		}

		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return response, err
		}

		var alg jose.SignatureAlgorithm
		switch pubKey.(type) {
		case *rsa.PublicKey:
			alg = jose.RS256
		default:
			return response, fmt.Errorf("invalid public key type %T, must be *rsa.PrivateKey", pubKey)
		}

		kid, err := keyIDFromPublicKey(pubKey)
		if err != nil {
			return response, err
		}

		keys = append(keys, jose.JSONWebKey{
			Key:       pubKey,
			KeyID:     kid,
			Algorithm: string(alg),
			Use:       "sig",
		})
	}

	keyResponse := keyResponse{Keys: keys}
	return json.MarshalIndent(keyResponse, "", "    ")
}

var _ status.Handler = &s3EndpointReconciler{}

func (r *s3EndpointReconciler) GetConditions(logger log.FieldLogger) ([]configv1.ClusterOperatorStatusCondition, error) {
	var conditions []configv1.ClusterOperatorStatusCondition
	if r.degraded.Status == configv1.ConditionTrue {
		conditions = append(conditions, r.degraded)
	}
	return conditions, nil
}

func (r *s3EndpointReconciler) GetRelatedObjects(logger log.FieldLogger) ([]configv1.ObjectReference, error) {
	return []configv1.ObjectReference{}, nil
}

func (r *s3EndpointReconciler) Name() string {
	return controllerName
}

// updateConfigCRTimestamp will annotate the CCO config CR with the current timestamp to trigger a status calculation
func (r *s3EndpointReconciler) updateConfigCRTimestamp() error {
	operatorConfig := &operatorv1.CloudCredential{}
	if err := r.controllerRuntimeClient.Get(context.TODO(),
		types.NamespacedName{Name: constants.CloudCredOperatorConfig},
		operatorConfig); err != nil {
		return err
	}

	// Hack: the operator config does not allow the managementState to be an empty string
	// yet the operator config stored in etcd can in fact have no data for the managementState.
	if operatorConfig.Spec.ManagementState == "" {
		operatorConfig.Spec.ManagementState = operatorv1.Managed
	}

	if operatorConfig.Annotations == nil {
		operatorConfig.Annotations = map[string]string{}
	}
	operatorConfig.Annotations[constants.CloudCredOperatorConfigTimestampAnnotation] = time.Now().Format(time.StampMilli)

	return r.controllerRuntimeClient.Update(context.TODO(), operatorConfig)
}
