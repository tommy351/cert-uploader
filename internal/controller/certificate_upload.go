package controller

import (
	"context"
	"errors"
	"fmt"

	"github.com/tommy351/cert-uploader/pkg/apis/certuploader/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-uploader.dev,resources=certificateuploads,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-uploader.dev,resources=certificateuploads/status,verbs=get;update;patch

var ErrInvalidSecretType = errors.New("secret type must be kubernetes.io/tls")

type CertificateUploadReconciler struct {
	Client client.Client
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
	cert := new(corev1.Secret)

	if err := r.Client.Get(ctx, types.NamespacedName{
		Namespace: cu.Namespace,
		Name:      cu.Spec.SecretName,
	}, cert); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get certificate: %w", err)
	}

	if cert.Type != corev1.SecretTypeTLS {
		return reconcile.Result{}, ErrInvalidSecretType
	}

	if cu.Spec.Cloudflare != nil {
		return r.uploadToCloudflare(ctx, cu, cert)
	}

	return reconcile.Result{}, nil
}

func timePtr(t metav1.Time) *metav1.Time {
	return &t
}
