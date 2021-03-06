package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.spec.secretName`
// +kubebuilder:printcolumn:name="Upload",type=date,JSONPath=`.status.uploadTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

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
	SecretName string                `json:"secretName"`
	Cloudflare *CloudflareUploadSpec `json:"cloudflare,omitempty"`
}

type CertificateUploadStatus struct {
	SecretResourceVersion string                  `json:"secretResourceVersion,omitempty"`
	UploadTime            *metav1.Time            `json:"uploadTime,omitempty"`
	UpdateTime            *metav1.Time            `json:"updateTime,omitempty"`
	ExpireTime            *metav1.Time            `json:"expireTime,omitempty"`
	Cloudflare            *CloudflareUploadStatus `json:"cloudflare,omitempty"`
}

type CloudflareUploadSpec struct {
	ZoneID            string                     `json:"zoneId"`
	Email             string                     `json:"email,omitempty"`
	APIKeySecretRef   *corev1.SecretKeySelector  `json:"apiKeySecretRef,omitempty"`
	APITokenSecretRef *corev1.SecretKeySelector  `json:"apiTokenSecretRef,omitempty"`
	BundleMethod      string                     `json:"bundleMethod,omitempty"`
	Type              string                     `json:"type,omitempty"`
	GeoRestrictions   *CloudflareGeoRestrictions `json:"geoRestrictions,omitempty"`
}

type CloudflareGeoRestrictions struct {
	Label string `json:"label,omitempty"`
}

type CloudflareUploadStatus struct {
	CertificateID string `json:"certificateId,omitempty"`
}
