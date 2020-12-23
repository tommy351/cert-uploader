package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/tommy351/cert-uploader/pkg/apis/certuploader/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const cloudflareEndpoint = "https://api.cloudflare.com/client/v4"

type cloudflareCustomCertificateRequest struct {
	Certificate  string `json:"certificate"`
	PrivateKey   string `json:"private_key"`
	BundleMethod string `json:"bundle_method,omitempty"`
	Type         string `json:"type,omitempty"`
}

type cloudflareCustomCertificateResponse struct {
	Success bool                              `json:"success"`
	Errors  []cloudFlareResponseError         `json:"errors"`
	Result  cloudFlareCustomCertificateResult `json:"result"`
}

type cloudFlareResponseError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cloudFlareCustomCertificateResult struct {
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

func (r *CertificateUploadReconciler) uploadToCloudflare(ctx context.Context, cu *v1alpha1.CertificateUpload, cert *corev1.Secret) (reconcile.Result, error) {
	logger := log.FromContext(ctx)

	if cu.Status.SecretResourceVersion == cert.ResourceVersion {
		logger.V(1).Info("Skip because the resource version is not changed")
		r.EventRecorder.Eventf(cu, corev1.EventTypeNormal, ReasonCertUnchanged, `Skip because secret "%s/%s" not changed`, cert.Namespace, cert.Name)

		return reconcile.Result{}, nil
	}

	apiTokenRef := cu.Spec.Cloudflare.APITokenSecretRef
	apiToken := new(corev1.Secret)
	apiTokenKey := types.NamespacedName{
		Namespace: cu.Namespace,
		Name:      apiTokenRef.Name,
	}

	if err := r.Client.Get(ctx, apiTokenKey, apiToken); err != nil {
		if errors.IsNotFound(err) {
			logger.Error(err, "API token secret does not exist", "apiTokenRef", apiTokenRef)
			r.EventRecorder.Eventf(cu, corev1.EventTypeWarning, ReasonAPITokenNotFound, "Secret %q does not exist", apiTokenKey)

			return reconcile.Result{}, nil
		}

		r.EventRecorder.Eventf(cu, corev1.EventTypeWarning, ReasonFailed, "Failed to get API token: %v", err)

		return reconcile.Result{}, fmt.Errorf("failed to get API token: %w", err)
	}

	var (
		req *http.Request
		buf bytes.Buffer
		err error
	)

	reqBody := cloudflareCustomCertificateRequest{
		Certificate:  string(cert.Data[corev1.TLSCertKey]),
		PrivateKey:   string(cert.Data[corev1.TLSPrivateKeyKey]),
		BundleMethod: cu.Spec.Cloudflare.BundleMethod,
		Type:         cu.Spec.Cloudflare.Type,
	}

	if cu.Status.Cloudflare != nil {
		req, err = http.NewRequest(
			http.MethodPatch,
			fmt.Sprintf("%s/zones/%s/custom_certificates/%s", cloudflareEndpoint, cu.Spec.Cloudflare.ZoneID, cu.Status.Cloudflare.CertificateID),
			&buf,
		)
	} else {
		reqBody.Type = ""
		req, err = http.NewRequest(
			http.MethodPost,
			fmt.Sprintf("%s/zones/%s/custom_certificates", cloudflareEndpoint, cu.Spec.Cloudflare.ZoneID),
			&buf,
		)
	}

	logger = logger.WithValues(
		"requestMethod", req.Method,
		"requestUrl", req.URL,
	)

	if err := json.NewEncoder(&buf).Encode(&reqBody); err != nil {
		logger.Error(err, "Failed to encode JSON")
		r.EventRecorder.Eventf(cu, corev1.EventTypeWarning, ReasonFailed, "Failed to encode JSON: %v", err)

		return reconcile.Result{}, nil
	}

	if err != nil {
		r.EventRecorder.Eventf(cu, corev1.EventTypeWarning, ReasonFailed, "Failed to create HTTP request: %v", err)

		return reconcile.Result{}, fmt.Errorf("failed to create http request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Auth-Email", cu.Spec.Cloudflare.Email)
	req.Header.Set("X-Auth-Key", string(apiToken.Data[apiTokenRef.Key]))

	logger.V(1).Info("Sending request to Cloudflare")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		r.EventRecorder.Eventf(cu, corev1.EventTypeWarning, ReasonFailed, "HTTP request failed: %v", err)

		return reconcile.Result{}, fmt.Errorf("request failed: %w", err)
	}

	defer res.Body.Close()

	var body cloudflareCustomCertificateResponse

	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		r.EventRecorder.Eventf(cu, corev1.EventTypeWarning, ReasonFailed, "Failed to decode HTTP response: %v", err)

		return reconcile.Result{}, fmt.Errorf("decode failed: %w", err)
	}

	logger.V(1).Info("Request sent to Cloudflare", "responseBody", body, "responseStatus", res.StatusCode)

	if len(body.Errors) > 0 {
		logger.Info("Cloudflare response errors", "responseErrors", body.Errors)
		r.EventRecorder.Eventf(cu, corev1.EventTypeWarning, ReasonFailed, "Cloudflare response errors: %v", body.Errors)

		return reconcile.Result{}, nil
	}

	cu.Status.SecretResourceVersion = cert.ResourceVersion
	cu.Status.UploadTime = timePtr(metav1.NewTime(body.Result.UploadedOn))
	cu.Status.UpdateTime = timePtr(metav1.NewTime(body.Result.ModifiedOn))
	cu.Status.ExpireTime = timePtr(metav1.NewTime(body.Result.ExpiresOn))
	cu.Status.Cloudflare = &v1alpha1.CloudflareUploadStatus{
		CertificateID: body.Result.ID,
	}

	if err := r.Client.Status().Update(ctx, cu); err != nil {
		r.EventRecorder.Eventf(cu, corev1.EventTypeWarning, ReasonFailed, "Failed to update status: %v", err)

		return reconcile.Result{}, fmt.Errorf("failed to update resource status: %w", err)
	}

	r.EventRecorder.Event(cu, corev1.EventTypeNormal, ReasonUploaded, "Uploaded to Cloudflare")

	return reconcile.Result{}, nil
}
