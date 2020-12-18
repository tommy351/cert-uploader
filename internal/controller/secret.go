package controller

import (
	"context"
	"fmt"

	"github.com/tommy351/cert-uploader/pkg/apis/certuploader/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const secretNameField = "spec.secretName"

type SecretReconciler struct {
	Client                      client.Client
	CertificateUploadReconciler *CertificateUploadReconciler
}

func (r *SecretReconciler) SetupWithManager(mgr manager.Manager) error {
	err := mgr.GetFieldIndexer().IndexField(context.TODO(), new(v1alpha1.CertificateUpload), secretNameField, func(object client.Object) []string {
		return []string{object.(*v1alpha1.CertificateUpload).Spec.SecretName}
	})
	if err != nil {
		return fmt.Errorf("index failed: %w", err)
	}

	return builder.
		ControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}

func (r *SecretReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	list := new(v1alpha1.CertificateUploadList)
	err := r.Client.List(ctx, list, client.InNamespace(req.Namespace), client.MatchingFields(map[string]string{
		secretNameField: req.Name,
	}))
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("list failed: %w", err)
	}

	for _, item := range list.Items {
		item := item
		result, err := r.CertificateUploadReconciler.upload(ctx, &item)
		if err != nil {
			return result, err
		}
	}

	return reconcile.Result{}, nil
}
