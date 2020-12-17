package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

type CertificateUpload struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateUploadSpec   `json:"spec,omitempty"`
	Status CertificateUploadStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

type CertificateUploadList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []CertificateUpload `json:"items"`
}

type CertificateUploadSpec struct {
	CertificateName string                `json:"certificateName"`
	CloudFlare      *CloudFlareUploadSpec `json:"cloudflare,omitempty"`
}

type CertificateUploadStatus struct {
	CertificateResourceVersion string                  `json:"certificateResourceVersion,omitempty"`
	UploadTime                 *metav1.Time            `json:"uploadTime,omitempty"`
	UpdateTime                 *metav1.Time            `json:"updateTime,omitempty"`
	ExpireTime                 *metav1.Time            `json:"expireTime,omitempty"`
	CloudFlare                 *CloudFlareUploadStatus `json:"cloudflare,omitempty"`
}

type CloudFlareUploadSpec struct {
	Email             string                   `json:"email"`
	APITokenSecretRef corev1.SecretKeySelector `json:"apiTokenSecretRef"`
	BundleMethod      string                   `json:"bundleMethod,omitempty"`
	Type              string                   `json:"type,omitempty"`
	ZoneID            string                   `json:"zoneId"`
}

type CloudFlareUploadStatus struct {
	CertificateID string `json:"certificateId,omitempty"`
}
