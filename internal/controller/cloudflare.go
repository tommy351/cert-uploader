package controller

import (
	"context"
	"errors"
	"fmt"

	"github.com/cloudflare/cloudflare-go"
	"github.com/tommy351/cert-uploader/pkg/apis/certuploader/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var (
	ErrMissingCloudflareToken = errors.New("either apiTokenSecretRef or apiKeySecretRef is required for cloudflare")
	ErrMissingCloudflareEmail = errors.New("email is required")
)

func (r *CertificateUploadReconciler) newCloudflareClient(ctx context.Context, cu *v1alpha1.CertificateUpload) (*cloudflare.API, bool, error) {
	if ref := cu.Spec.Cloudflare.APITokenSecretRef; ref != nil {
		secret := new(corev1.Secret)
		secretKey := types.NamespacedName{
			Namespace: cu.Namespace,
			Name:      ref.Name,
		}

		if err := r.Client.Get(ctx, secretKey, secret); err != nil {
			return nil, !kerrors.IsNotFound(err), fmt.Errorf("failed to get api token: %w", err)
		}

		api, err := cloudflare.NewWithAPIToken(string(secret.Data[ref.Key]))
		if err != nil {
			return nil, false, fmt.Errorf("failed to create cloudflare client: %w", err)
		}

		return api, false, nil
	}

	if ref := cu.Spec.Cloudflare.APIKeySecretRef; ref != nil {
		email := cu.Spec.Cloudflare.Email

		if email == "" {
			return nil, false, ErrMissingCloudflareEmail
		}

		secret := new(corev1.Secret)
		secretKey := types.NamespacedName{
			Namespace: cu.Namespace,
			Name:      ref.Name,
		}

		if err := r.Client.Get(ctx, secretKey, secret); err != nil {
			return nil, !kerrors.IsNotFound(err), fmt.Errorf("failed to get api key: %w", err)
		}

		api, err := cloudflare.NewWithAPIToken(string(secret.Data[ref.Key]))
		if err != nil {
			return nil, false, fmt.Errorf("failed to create cloudflare client: %w", err)
		}

		return api, false, nil
	}

	return nil, false, ErrMissingCloudflareToken
}

func (r *CertificateUploadReconciler) uploadToCloudflare(ctx context.Context, cu *v1alpha1.CertificateUpload, cert *corev1.Secret) (reconcile.Result, error) {
	logger := log.FromContext(ctx)
	api, retryable, err := r.newCloudflareClient(ctx, cu)
	if err != nil {
		logger.Error(err, "Failed to create Cloudflare client")
		r.EventRecorder.Eventf(cu, corev1.EventTypeWarning, ReasonFailed, "Failed to create Cloudflare client: %v", err)

		if !retryable {
			return reconcile.Result{}, nil
		}

		return reconcile.Result{}, err
	}

	var result cloudflare.ZoneCustomSSL
	zoneID := cu.Spec.Cloudflare.ZoneID
	sslOptions := cloudflare.ZoneCustomSSLOptions{
		Certificate:  string(cert.Data[corev1.TLSCertKey]),
		PrivateKey:   string(cert.Data[corev1.TLSPrivateKeyKey]),
		BundleMethod: cu.Spec.Cloudflare.BundleMethod,
		Type:         cu.Spec.Cloudflare.Type,
	}

	if cu.Status.Cloudflare != nil {
		sslOptions.Type = ""
		result, err = api.UpdateSSL(zoneID, cu.Status.Cloudflare.CertificateID, sslOptions)
	} else {
		result, err = api.CreateSSL(zoneID, sslOptions)
	}

	if err != nil {
		logger.Error(err, "Failed to upload certificate to Cloudflare")
		r.EventRecorder.Eventf(cu, corev1.EventTypeWarning, ReasonFailed, "Failed to upload certificate to Cloudflare: %v", err)

		return reconcile.Result{}, nil
	}

	cu.Status.SecretResourceVersion = cert.ResourceVersion
	cu.Status.UploadTime = timePtr(metav1.NewTime(result.UploadedOn))
	cu.Status.UpdateTime = timePtr(metav1.NewTime(result.ModifiedOn))
	cu.Status.ExpireTime = timePtr(metav1.NewTime(result.ExpiresOn))
	cu.Status.Cloudflare = &v1alpha1.CloudflareUploadStatus{
		CertificateID: result.ID,
	}

	if err := r.Client.Status().Update(ctx, cu); err != nil {
		r.EventRecorder.Eventf(cu, corev1.EventTypeWarning, ReasonFailed, "Failed to update status: %v", err)

		return reconcile.Result{}, fmt.Errorf("failed to update resource status: %w", err)
	}

	r.EventRecorder.Event(cu, corev1.EventTypeNormal, ReasonUploaded, "Uploaded to Cloudflare")

	return reconcile.Result{}, nil
}
