package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// ConnectorClass declares the server-supported transports and capabilities for Connectors.
// It is cluster-scoped platform configuration, matching NSO's current API scope.
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Transports",type=string,JSONPath=`.spec.transports`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
type ConnectorClass struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConnectorClassSpec   `json:"spec,omitempty"`
	Status            ConnectorClassStatus `json:"status,omitempty"`
}

type ConnectorClassSpec struct {
	// Transports lists the wire transports this class permits.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:Enum=masque-v1
	Transports []string `json:"transports"`
	// Capabilities are named protocol features advertised to clients.
	// +kubebuilder:validation:items:Enum=connect-tcp;connect-udp;connect-ip
	Capabilities []string `json:"capabilities,omitempty"`
}

type ConnectorClassStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
type ConnectorClassList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConnectorClass `json:"items"`
}

// Connector represents one Connect installation in one project. The public key
// is the stable iroh identity; private material must never be stored in the API.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:metadata:annotations="discovery.miloapis.com/parent-contexts=Project"
// +kubebuilder:printcolumn:name="Class",type=string,JSONPath=`.spec.classRef`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
type Connector struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConnectorSpec   `json:"spec,omitempty"`
	Status            ConnectorStatus `json:"status,omitempty"`
}

type ConnectorSpec struct {
	// ClassRef names a cluster-scoped ConnectorClass in the management cluster.
	// +kubebuilder:validation:Required
	ClassRef string `json:"classRef"`
	// PublicKey is the lowercase or uppercase hex-encoded 32-byte iroh public key.
	// +kubebuilder:validation:Pattern=`^[a-fA-F0-9]{64}$`
	PublicKey string `json:"publicKey"`
	// Endpoint is the optional serialized iroh endpoint address for dialing.
	Endpoint string `json:"endpoint,omitempty"`
	// RelayURLs are optional relay URLs published by the Connector.
	RelayURLs []string `json:"relayURLs,omitempty"`
}

type ConnectorStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	AssignedAddresses  []string           `json:"assignedAddresses,omitempty"`
	LeaseRef           string             `json:"leaseRef,omitempty"`
}

// +kubebuilder:object:root=true
type ConnectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Connector `json:"items"`
}

// ConnectorAdvertisement publishes one Connector's application services.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:metadata:annotations="discovery.miloapis.com/parent-contexts=Project"
type ConnectorAdvertisement struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConnectorAdvertisementSpec   `json:"spec,omitempty"`
	Status            ConnectorAdvertisementStatus `json:"status,omitempty"`
}

type ConnectorAdvertisementSpec struct {
	// ConnectorRef names a Connector in this project.
	// +kubebuilder:validation:Required
	ConnectorRef string              `json:"connectorRef"`
	Services     []AdvertisedService `json:"services,omitempty"`
}

type AdvertisedService struct {
	// Protocol identifies the application protocol.
	// +kubebuilder:validation:Enum=TCP;UDP
	Protocol string `json:"protocol"`
	// Port is the destination port on the Connector.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port     int32  `json:"port"`
	Hostname string `json:"hostname,omitempty"`
}

type ConnectorAdvertisementStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
type ConnectorAdvertisementList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConnectorAdvertisement `json:"items"`
}

// ConnectGateway is an intent to attach a Connect Connector to a VPC network.
// This API reference does not itself create a workload or NetworkBinding; those
// integrations are intentionally reported as pending until implemented.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:metadata:annotations="discovery.miloapis.com/parent-contexts=Project"
type ConnectGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConnectGatewaySpec   `json:"spec,omitempty"`
	Status            ConnectGatewayStatus `json:"status,omitempty"`
}

type ConnectGatewaySpec struct {
	ConnectorRef string   `json:"connectorRef"`
	NetworkRef   string   `json:"networkRef"`
	LocationRef  string   `json:"locationRef,omitempty"`
	Routes       []string `json:"routes,omitempty"`
}

type ConnectGatewayStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
type ConnectGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConnectGateway `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ConnectorClass{}, &ConnectorClassList{}, &Connector{}, &ConnectorList{}, &ConnectorAdvertisement{}, &ConnectorAdvertisementList{}, &ConnectGateway{}, &ConnectGatewayList{})
}
