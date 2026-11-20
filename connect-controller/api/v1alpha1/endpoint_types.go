package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ConnectEndpoint struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConnectEndpointSpec   `json:"spec"`
	Status            ConnectEndpointStatus `json:"status,omitempty"`
}

type ConnectEndpointSpec struct {
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="identity is immutable"
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	CustomerProjectUID string `json:"customerProjectUID"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="identity is immutable"
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	GatewayUID string `json:"gatewayUID"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="identity is immutable"
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Metro string `json:"metro"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="identity is immutable"
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Hostname string `json:"hostname"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="identity is immutable"
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	CustomerProject string `json:"customerProject"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="identity is immutable"
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	GatewayNamespace string `json:"gatewayNamespace"`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="identity is immutable"
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	GatewayName string `json:"gatewayName"`
	// +kubebuilder:validation:Enum=Active;Deleting;Retired
	// +kubebuilder:validation:XValidation:rule="oldSelf != 'Deleting' || self != 'Active'",message="draining endpoint cannot reactivate"
	Lifecycle string `json:"lifecycle"`
	// +kubebuilder:validation:XValidation:rule="oldSelf.cell == '' || self == oldSelf",message="selected cell assignment is immutable"
	Assignment EndpointAssignment `json:"assignment"`
}

type EndpointAssignment struct {
	// +kubebuilder:validation:MaxLength=253
	Cell string `json:"cell"`
	// +kubebuilder:validation:MaxLength=253
	Provider string `json:"provider"`
	// +kubebuilder:validation:MaxLength=253
	Frontend string `json:"frontend"`
}

type EndpointVPCReference struct {
	// +kubebuilder:validation:MaxLength=253
	Namespace string `json:"namespace"`
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// +kubebuilder:validation:MaxLength=253
	UID string `json:"uid"`
}

type EndpointCertificateReference struct {
	Name string `json:"name"`
	UID  string `json:"uid,omitempty"`
}

type ConnectEndpointStatus struct {
	Phase               string                       `json:"phase,omitempty"`
	CertificateRef      EndpointCertificateReference `json:"certificateRef,omitempty"`
	Revision            int64                        `json:"revision,omitempty"`
	ActivationRevision  int64                        `json:"activationRevision,omitempty"`
	CertificateRevision string                       `json:"certificateRevision,omitempty"`
	DeliveredSecrets    []string                     `json:"deliveredSecrets,omitempty"`
	NotAfter            *metav1.Time                 `json:"notAfter,omitempty"`
	Ready               bool                         `json:"ready,omitempty"`
	Reason              string                       `json:"reason,omitempty"`
	CleanupStep         string                       `json:"cleanupStep,omitempty"`
	WithdrawnAt         *metav1.Time                 `json:"withdrawnAt,omitempty"`
	VerifiedAt          *metav1.Time                 `json:"verifiedAt,omitempty"`
}

// +kubebuilder:object:root=true
type ConnectEndpointList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConnectEndpoint `json:"items"`
}

func init() { SchemeBuilder.Register(&ConnectEndpoint{}, &ConnectEndpointList{}) }

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ConnectGrant struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConnectGrantSpec   `json:"spec"`
	Status            ConnectGrantStatus `json:"status,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="grant identity is immutable"
type ConnectGrantSpec struct {
	NetworkName string               `json:"networkName"`
	NetworkUID  string               `json:"networkUID"`
	VPC         EndpointVPCReference `json:"vpcRef"`
	// +kubebuilder:validation:MaxLength=253
	EndpointName string `json:"endpointName"`
	// +kubebuilder:validation:MaxLength=253
	EndpointUID string `json:"endpointUID"`
	// +kubebuilder:validation:MaxLength=253
	BindingName string `json:"bindingName"`
	// +kubebuilder:validation:MaxLength=253
	BindingUID string `json:"bindingUID"`
	// +kubebuilder:validation:MaxLength=253
	PolicyRevision string `json:"policyRevision"`
	// +kubebuilder:validation:MaxLength=253
	ConnectorID string `json:"connectorID"`
	// +kubebuilder:validation:MaxLength=253
	Cell string `json:"cell"`
}

type ConnectGrantStatus struct {
	Retiring bool `json:"retiring,omitempty"`
	Retired  bool `json:"retired,omitempty"`
}

// +kubebuilder:object:root=true
type ConnectGrantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConnectGrant `json:"items"`
}

func init() { SchemeBuilder.Register(&ConnectGrant{}, &ConnectGrantList{}) }
