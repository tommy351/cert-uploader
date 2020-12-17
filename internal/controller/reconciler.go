package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tommy351/cert-uploader/pkg/apis/certuploader/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-uploader.dev,resources=certificateuploads,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-uploader.dev,resources=certificateuploads/status,verbs=get;update;patch

const CloudFlareEndpoint = "https://api.cloudflare.com/client/v4"

type CloudFlareCustomCertificateRequest struct {
	Certificate  string `json:"certificate"`
	PrivateKey   string `json:"private_key"`
	BundleMethod string `json:"bundle_method,omitempty"`
	Type         string `json:"type,omitempty"`
}

type CloudFlareCustomCertificateResponse struct {
	Success bool                              `json:"success"`
	Errors  []CloudFlareResponseError         `json:"errors"`
	Result  CloudFlareCustomCertificateResult `json:"result"`
}

type CloudFlareResponseError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type CloudFlareCustomCertificateResult struct {
	ID           string    `json:"id"`
	Hosts        []string  `json:"hosts"`
	Issuer       string    `json:"issuer"`
	Signature    string    `json:"signature"`
	Status       string    `json:"status"`
	BundleMethod string    `json:"bundle_method"`
	ZoneID       string    `json:"zone_id"`
	UploadedOn   time.Time `json:"uploaded_on"`
	ModifiedOn   time.Time `json:"modified_on"`
	ExpiresOn    time.Time `json:"expires_on"`
	Priority     int       `json:"priority"`
}

var ErrInvalidSecretType = errors.New("secret type must be kubernetes.io/tls")

type Reconciler struct {
	Client client.Client
}

func (r *Reconciler) SetupWithManager(mgr manager.Manager) error {
	return builder.
		ControllerManagedBy(mgr).
		For(&v1alpha1.CertificateUpload{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}

func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	cu := new(v1alpha1.CertificateUpload)

	if err := r.Client.Get(ctx, req.NamespacedName, cu); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	cert := new(corev1.Secret)

	if err := r.Client.Get(ctx, types.NamespacedName{
		Namespace: cu.Namespace,
		Name:      cu.Spec.CertificateName,
	}, cert); err != nil {
		return reconcile.Result{}, err
	}

	if cert.Type != corev1.SecretTypeTLS {
		return reconcile.Result{}, ErrInvalidSecretType
	}

	if cu.Spec.CloudFlare != nil {
		return r.uploadToCloudFlare(ctx, cu, cert)
	}

	return reconcile.Result{}, nil
}

func (r *Reconciler) uploadToCloudFlare(ctx context.Context, cu *v1alpha1.CertificateUpload, cert *corev1.Secret) (reconcile.Result, error) {
	logger := log.FromContext(ctx)

	if cu.Status.CertificateResourceVersion == cert.ResourceVersion {
		logger.V(1).Info("Skip because the resource version is not changed")

		return reconcile.Result{}, nil
	}

	apiTokenRef := cu.Spec.CloudFlare.APITokenSecretRef
	apiToken := new(corev1.Secret)

	if err := r.Client.Get(ctx, types.NamespacedName{
		Namespace: cu.Namespace,
		Name:      apiTokenRef.Name,
	}, apiToken); err != nil {
		return reconcile.Result{}, err
	}

	var req *http.Request

	if cu.Status.CloudFlare != nil {
		var buf bytes.Buffer
		err := json.NewEncoder(&buf).Encode(CloudFlareCustomCertificateRequest{
			Certificate:  string(cert.Data[corev1.TLSCertKey]),
			PrivateKey:   string(cert.Data[corev1.TLSPrivateKeyKey]),
			BundleMethod: cu.Spec.CloudFlare.BundleMethod,
			Type:         cu.Spec.CloudFlare.Type,
		})
		if err != nil {
			return reconcile.Result{}, err
		}

		req, err = http.NewRequest(http.MethodPatch, fmt.Sprintf("%s/zones/%s/custom_certificates/%s", CloudFlareEndpoint, cu.Spec.CloudFlare.ZoneID, cu.Status.CloudFlare.CertificateID), &buf)
		if err != nil {
			return reconcile.Result{}, err
		}
	} else {
		var buf bytes.Buffer
		err := json.NewEncoder(&buf).Encode(CloudFlareCustomCertificateRequest{
			Certificate:  string(cert.Data[corev1.TLSCertKey]),
			PrivateKey:   string(cert.Data[corev1.TLSPrivateKeyKey]),
			BundleMethod: cu.Spec.CloudFlare.BundleMethod,
		})
		if err != nil {
			return reconcile.Result{}, err
		}

		req, err = http.NewRequest(http.MethodPost, fmt.Sprintf("%s/zones/%s/custom_certificates", CloudFlareEndpoint, cu.Spec.CloudFlare.ZoneID), &buf)
		if err != nil {
			return reconcile.Result{}, err
		}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Email", cu.Spec.CloudFlare.Email)
	req.Header.Set("X-Auth-Key", string(apiToken.Data[apiTokenRef.Key]))

	logger.V(1).Info("About to send request to CloudFlare", "requestMethod", req.Method, "requestUrl", req.URL)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return reconcile.Result{}, err
	}

	defer res.Body.Close()

	var body CloudFlareCustomCertificateResponse

	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return reconcile.Result{}, err
	}

	logger.V(1).Info("Request sent to CloudFlare", "responseBody", body, "responseStatus", res.StatusCode)

	if len(body.Errors) > 0 {
		return reconcile.Result{}, fmt.Errorf("response error: %+v", body.Errors)
	}

	cu.Status.CertificateResourceVersion = cert.ResourceVersion
	cu.Status.UploadTime = timePtr(metav1.NewTime(body.Result.UploadedOn))
	cu.Status.UpdateTime = timePtr(metav1.NewTime(body.Result.ModifiedOn))
	cu.Status.ExpireTime = timePtr(metav1.NewTime(body.Result.ExpiresOn))
	cu.Status.CloudFlare = &v1alpha1.CloudFlareUploadStatus{
		CertificateID: body.Result.ID,
	}

	if err := r.Client.Status().Update(ctx, cu); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func timePtr(t metav1.Time) *metav1.Time {
	return &t
}
