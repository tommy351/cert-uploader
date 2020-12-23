package controller

import (
	"context"
	"fmt"

	"github.com/tommy351/cert-uploader/pkg/apis/certuploader/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	ReasonCertNotFound     = "CertNotFound"
	ReasonInvalidCertType  = "InvalidCertType"
	ReasonCertUnchanged    = "CertUnchanged"
	ReasonAPITokenNotFound = "APITokenNotFound"
	ReasonUploaded         = "Uploaded"
	ReasonFailed           = "Failed"
)

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch;update
// +kubebuilder:rbac:groups=cert-uploader.dev,resources=certificateuploads,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-uploader.dev,resources=certificateuploads/status,verbs=get;update;patch

type CertificateUploadReconciler struct {
	Client        client.Client
	EventRecorder record.EventRecorder
}

func (r *CertificateUploadReconciler) SetupWithManager(mgr manager.Manager) error {
	return builder.
		ControllerManagedBy(mgr).
		For(&v1alpha1.CertificateUpload{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}

func (r *CertificateUploadReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	cu := new(v1alpha1.CertificateUpload)

	if err := r.Client.Get(ctx, req.NamespacedName, cu); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	return r.upload(ctx, cu)
}

func (r *CertificateUploadReconciler) upload(ctx context.Context, cu *v1alpha1.CertificateUpload) (reconcile.Result, error) {
	logger := log.FromContext(ctx)
	cert := new(corev1.Secret)
	certKey := types.NamespacedName{
		Namespace: cu.Namespace,
		Name:      cu.Spec.SecretName,
	}

	if err := r.Client.Get(ctx, certKey, cert); err != nil {
		if errors.IsNotFound(err) {
			logger.Error(err, "Secret does not exist")
			r.EventRecorder.Eventf(cu, corev1.EventTypeWarning, ReasonCertNotFound, "Secret %q does not exist", certKey)

			return reconcile.Result{}, nil
		}

		return reconcile.Result{}, fmt.Errorf("failed to get certificate: %w", err)
	}

	if cert.Type != corev1.SecretTypeTLS {
		logger.Info("Secret type must be kubernetes.io/tls")
		r.EventRecorder.Eventf(cu, corev1.EventTypeWarning, ReasonInvalidCertType, "Type of secret %q is not %s", certKey, corev1.SecretTypeTLS)

		return reconcile.Result{}, nil
	}

	if cu.Spec.Cloudflare != nil {
		return r.uploadToCloudflare(ctx, cu, cert)
	}

	return reconcile.Result{}, nil
}

func timePtr(t metav1.Time) *metav1.Time {
	return &t
}
