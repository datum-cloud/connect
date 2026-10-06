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
	// connector-authentication asserts that UID-scoped IAM policy and the trusted
	// OAuth token endpoint are deployed, allowing clients to leave bootstrap auth.
	// +kubebuilder:validation:items:Enum=connect-tcp;connect-udp;connect-ip;connector-authentication
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

// Connector represents one Connect installation in one project. PublicKey is
// the stable iroh transport identity. Authentication keys are independent
// control-plane identities; private material must never be stored in the API.
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
	// +kubebuilder:validation:XValidation:rule="oldSelf == null || self == oldSelf",message="publicKey is the immutable iroh transport identity; replace the Connector to rotate it"
	PublicKey string `json:"publicKey"`
	// Endpoint is the optional serialized iroh endpoint address for dialing.
	Endpoint string `json:"endpoint,omitempty"`
	// RelayURLs are optional relay URLs published by the Connector.
	RelayURLs []string `json:"relayURLs,omitempty"`
}

type ConnectorAuthenticationKey struct {
	// ID is a client-selected, DNS-label identifier for this key.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=63
	ID string `json:"id"`
	// PublicKey is a PEM encoded RSA public key. The matching private key remains
	// on the Connector and signs both enrollment proofs and OAuth JWT assertions.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=8192
	// +kubebuilder:validation:XValidation:rule="oldSelf == null || self == oldSelf",message="publicKey is immutable in an enrollment"
	PublicKey string `json:"publicKey"`
	// Proof is an unpadded base64url RSA-PSS/SHA-256 signature over the canonical
	// enrollment statement documented by the Connect API.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	// +kubebuilder:validation:XValidation:rule="oldSelf == null || self == oldSelf",message="proof is immutable for an enrolled key"
	Proof string `json:"proof"`
	// State must be Active for the initial enrollment key. Revocation and
	// rotation occur through a protected platform operation, not Connector edits.
	// +kubebuilder:validation:Enum=Active
	State string `json:"state"`
}

// ConnectorEnrollment is the protected bootstrap interface for a Connector's
// platform-owned identity. Grant create permission independently from ordinary
// Connector update permission. Its spec is immutable after creation.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:metadata:annotations="discovery.miloapis.com/parent-contexts=Project"
// +kubebuilder:validation:XValidation:rule="oldSelf == null || self.spec == oldSelf.spec",message="enrollment spec is immutable; use the protected platform rotation or recovery API"
type ConnectorEnrollment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConnectorEnrollmentSpec   `json:"spec"`
	Status            ConnectorEnrollmentStatus `json:"status,omitempty"`
}

type ConnectorEnrollmentSpec struct {
	ConnectorRef ConnectorEnrollmentReference `json:"connectorRef"`
	Key          ConnectorAuthenticationKey   `json:"key"`
}

type ConnectorEnrollmentReference struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

type ConnectorEnrollmentStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
type ConnectorEnrollmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConnectorEnrollment `json:"items"`
}

type ConnectorStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	AssignedAddresses  []string           `json:"assignedAddresses,omitempty"`
	LeaseRef           string             `json:"leaseRef,omitempty"`
	// Authentication identifies the platform principal bound to this immutable
	// Connector UID and the provider key IDs available for JWT assertions.
	Authentication *ConnectorAuthenticationStatus `json:"authentication,omitempty"`
}

type ConnectorAuthenticationStatus struct {
	ConnectorUID   string                      `json:"connectorUID"`
	PrincipalRef   ConnectorPrincipalReference `json:"principalRef"`
	RegisteredKeys []ConnectorRegisteredKey    `json:"registeredKeys,omitempty"`
}

type ConnectorPrincipalReference struct {
	Project     string `json:"project"`
	Name        string `json:"name"`
	UID         string `json:"uid,omitempty"`
	ClientID    string `json:"clientID,omitempty"`
	ClientEmail string `json:"clientEmail,omitempty"`
}

type ConnectorRegisteredKey struct {
	ID                   string `json:"id"`
	ServiceAccountKeyRef string `json:"serviceAccountKeyRef"`
	AuthProviderKeyID    string `json:"authProviderKeyID,omitempty"`
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

// ConnectGateway runs a managed gateway in a project VPC. Project Connectors
// attach through ConnectNetworkBinding resources.
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
	// +kubebuilder:validation:Required
	NetworkRef string `json:"networkRef"`
	// +kubebuilder:validation:Required
	LocationRef string `json:"locationRef,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	Routes []string `json:"routes,omitempty"`
	// Image must be a Linux gateway image with Datum CONNECT-IP support.
	// +kubebuilder:validation:Required
	Image string `json:"image"`
	// InstanceType selects the Compute instance size. The platform default is used when empty.
	InstanceType string `json:"instanceType,omitempty"`
	// RelayURLs pins the gateway to operator-managed iroh relays when set.
	RelayURLs []string `json:"relayURLs,omitempty"`
	// PeerRouting allows Connectors attached to this gateway to route directly
	// to the assigned addresses of the other attached Connectors. It is disabled
	// by default; VPC routes remain available regardless of this setting.
	PeerRouting bool `json:"peerRouting,omitempty"`
}

type ConnectGatewayStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	WorkloadRef        string             `json:"workloadRef,omitempty"`
	EndpointID         string             `json:"endpointID,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
type ConnectGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConnectGateway `json:"items"`
}

// ConnectNetworkBinding is a Connector's approved attachment to a managed
// ConnectGateway and its VPC routes.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:metadata:annotations="discovery.miloapis.com/parent-contexts=Project"
type ConnectNetworkBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConnectNetworkBindingSpec   `json:"spec,omitempty"`
	Status            ConnectNetworkBindingStatus `json:"status,omitempty"`
}

type ConnectNetworkBindingSpec struct {
	// +kubebuilder:validation:Required
	GatewayRef string `json:"gatewayRef"`
	// +kubebuilder:validation:Required
	ConnectorRef string `json:"connectorRef"`
}

type ConnectNetworkBindingStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	EndpointID         string             `json:"endpointID,omitempty"`
	AssignedAddress    string             `json:"assignedAddress,omitempty"`
	PeerAddress        string             `json:"peerAddress,omitempty"`
	Routes             []string           `json:"routes,omitempty"`
	RelayURLs          []string           `json:"relayURLs,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
type ConnectNetworkBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConnectNetworkBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ConnectorClass{}, &ConnectorClassList{}, &Connector{}, &ConnectorList{}, &ConnectorEnrollment{}, &ConnectorEnrollmentList{}, &ConnectorAdvertisement{}, &ConnectorAdvertisementList{}, &ConnectGateway{}, &ConnectGatewayList{}, &ConnectNetworkBinding{}, &ConnectNetworkBindingList{})
}
