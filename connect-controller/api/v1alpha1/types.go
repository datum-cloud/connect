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

// ConnectGatewayClass declares an operator-provided managed gateway service
// profile installed into an entitled project. Concrete Compute details live in
// the referenced operator ConfigMap rather than in project-owned resources.
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Controller",type=string,JSONPath=`.spec.controllerName`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
type ConnectGatewayClass struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConnectGatewayClassSpec   `json:"spec,omitempty"`
	Status            ConnectGatewayClassStatus `json:"status,omitempty"`
}

type ConnectGatewayClassSpec struct {
	// ControllerName identifies the controller responsible for this class.
	// +kubebuilder:validation:Required
	ControllerName string `json:"controllerName"`
	// Default marks the class selected by `datumctl connect join` when it creates
	// a gateway automatically. At most one Ready class should be marked default.
	Default bool `json:"default,omitempty"`
	// RelayURLs pins gateways created from this class to operator-managed relays.
	// +kubebuilder:validation:MaxItems=5
	RelayURLs []string `json:"relayURLs,omitempty"`
	// ParametersRef selects an operator-owned ConfigMap. Its image key is
	// required; instanceType is optional and defaults to the platform standard.
	ParametersRef ConnectGatewayClassParametersReference `json:"parametersRef"`
	// Scaling describes observable service lifecycle behavior. It deliberately
	// does not expose Compute resource sizing or replica implementation details.
	Scaling ConnectGatewayScalingPolicy `json:"scaling,omitempty"`
}

type ConnectGatewayClassParametersReference struct {
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// +kubebuilder:validation:Required
	Namespace string `json:"namespace"`
}

type ConnectGatewayScalingPolicy struct {
	// +kubebuilder:validation:Enum=AlwaysOn;OnDemand
	// +kubebuilder:default=OnDemand
	Mode string `json:"mode,omitempty"`
	// IdleTimeout is the grace period before an idle OnDemand Workload is
	// removed. It defaults to ten minutes and must be at least one minute.
	IdleTimeout metav1.Duration `json:"idleTimeout,omitempty"`
}

type ConnectGatewayClassStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
type ConnectGatewayClassList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConnectGatewayClass `json:"items"`
}

// Connector represents one Connect installation in one project. Its transport
// and control-plane authentication public keys are distinct immutable
// identities. Private material must never be stored in the API.
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
	ClassRef       string                      `json:"classRef"`
	Transport      ConnectorTransportSpec      `json:"transport"`
	Authentication ConnectorAuthenticationSpec `json:"authentication"`
}

type ConnectorTransportSpec struct {
	// PublicKey is the lowercase or uppercase hex-encoded 32-byte iroh public key.
	// +kubebuilder:validation:Pattern=`^[a-fA-F0-9]{64}$`
	// +kubebuilder:validation:XValidation:rule="oldSelf == null || self == oldSelf",message="publicKey is the immutable iroh transport identity; replace the Connector to rotate it"
	PublicKey string `json:"publicKey"`
}

type ConnectorAuthenticationSpec struct {
	// PublicKey is a PEM-encoded RSA public key. The matching private key remains
	// on the Connector and signs OAuth JWT assertions.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=8192
	// +kubebuilder:validation:XValidation:rule="oldSelf == null || self == oldSelf",message="publicKey is the immutable control-plane authentication identity; replace the Connector to rotate it"
	PublicKey string `json:"publicKey"`
}

type ConnectorStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
	AssignedAddresses  []string           `json:"assignedAddresses,omitempty"`
	LeaseRef           string             `json:"leaseRef,omitempty"`
	// Authentication identifies the platform principal bound to this immutable
	// Connector UID and the provider key IDs available for JWT assertions.
	Authentication *ConnectorAuthenticationStatus `json:"authentication,omitempty"`
	// Transport is Connector-reported observed reachability. The controller
	// preserves it and does not interpret these URLs as user-selected policy.
	Transport *ConnectorTransportStatus `json:"transport,omitempty"`
}

type ConnectorTransportStatus struct {
	// Endpoint is the Connector's serialized iroh EndpointAddr observation.
	// It is written by the Connector agent, not by users or the controller.
	// +kubebuilder:validation:MaxLength=16384
	Endpoint string `json:"endpoint,omitempty"`
	// RelayURLs are the relay addresses actually used by the Connector. They are
	// observed status, not a user-selectable relay policy.
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:items:MaxLength=2048
	RelayURLs []string `json:"relayURLs,omitempty"`
}

type ConnectorAuthenticationStatus struct {
	ConnectorUID         string                      `json:"connectorUID"`
	PrincipalRef         ConnectorPrincipalReference `json:"principalRef"`
	ServiceAccountKeyRef string                      `json:"serviceAccountKeyRef,omitempty"`
	AuthProviderKeyID    string                      `json:"authProviderKeyID,omitempty"`
}

type ConnectorPrincipalReference struct {
	Project     string `json:"project"`
	Name        string `json:"name"`
	UID         string `json:"uid,omitempty"`
	ClientID    string `json:"clientID,omitempty"`
	ClientEmail string `json:"clientEmail,omitempty"`
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
// +kubebuilder:printcolumn:name="Class",type=string,JSONPath=`.spec.gatewayClassRef`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
type ConnectGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConnectGatewaySpec   `json:"spec,omitempty"`
	Status            ConnectGatewayStatus `json:"status,omitempty"`
}

type ConnectGatewaySpec struct {
	// GatewayClassRef names a cluster-scoped ConnectGatewayClass in this project.
	// +kubebuilder:validation:Required
	GatewayClassRef string `json:"gatewayClassRef"`
	// +kubebuilder:validation:Required
	NetworkRef string `json:"networkRef"`
	// +kubebuilder:validation:Required
	LocationRef string `json:"locationRef,omitempty"`
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	Routes []string `json:"routes,omitempty"`
	// RelayURLs pins the gateway to operator-managed iroh relays when set.
	RelayURLs []string `json:"relayURLs,omitempty"`
	// PeerRouting allows Connectors attached to this gateway to route directly
	// to the assigned addresses of the other attached Connectors. It is disabled
	// by default; VPC routes remain available regardless of this setting.
	PeerRouting bool `json:"peerRouting,omitempty"`
}

type ConnectGatewayStatus struct {
	ObservedGeneration int64  `json:"observedGeneration,omitempty"`
	ClassRef           string `json:"classRef,omitempty"`
	// Phase summarizes this gateway's operational state without exposing the
	// underlying Compute implementation.
	// +kubebuilder:validation:Enum=Dormant;Provisioning;Available;Scaling
	Phase       string             `json:"phase,omitempty"`
	IdleSince   *metav1.Time       `json:"idleSince,omitempty"`
	WorkloadRef string             `json:"workloadRef,omitempty"`
	EndpointID  string             `json:"endpointID,omitempty"`
	Conditions  []metav1.Condition `json:"conditions,omitempty"`
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
	SchemeBuilder.Register(&ConnectorClass{}, &ConnectorClassList{}, &ConnectGatewayClass{}, &ConnectGatewayClassList{}, &Connector{}, &ConnectorList{}, &ConnectorAdvertisement{}, &ConnectorAdvertisementList{}, &ConnectGateway{}, &ConnectGatewayList{}, &ConnectNetworkBinding{}, &ConnectNetworkBindingList{})
}
