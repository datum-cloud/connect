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

// +kubebuilder:validation:XValidation:message="managed-network-v1 requires placement and forbids legacy gateway implementation fields",rule="self.contractVersion != 'managed-network-v1' || (has(self.placement) && !has(self.gatewayClassRef) && !has(self.locationRef) && !has(self.routes) && !has(self.relayURLs) && !has(self.peerRouting))"
// +kubebuilder:validation:XValidation:message="legacy-v1 requires gatewayClassRef, locationRef, and routes",rule="self.contractVersion != 'legacy-v1' || (has(self.gatewayClassRef) && has(self.locationRef) && has(self.routes))"
type ConnectGatewaySpec struct {
	// ContractVersion selects the reconciliation contract without exposing the
	// gateway provider. Existing preview objects default to legacy-v1; new
	// managed-network objects must set managed-network-v1 explicitly.
	// +kubebuilder:validation:Enum=legacy-v1;managed-network-v1
	// +kubebuilder:default=legacy-v1
	ContractVersion string `json:"contractVersion,omitempty"`
	// GatewayClassRef names a cluster-scoped ConnectGatewayClass in this project.
	GatewayClassRef string `json:"gatewayClassRef,omitempty"`
	// +kubebuilder:validation:Required
	NetworkRef string `json:"networkRef"`
	// LocationRef is the fully qualified Compute Location name (for example, us-central-1).
	LocationRef string `json:"locationRef,omitempty"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	Routes []string `json:"routes,omitempty"`
	// RelayURLs pins the gateway to operator-managed iroh relays when set.
	RelayURLs []string `json:"relayURLs,omitempty"`
	// PeerRouting allows Connectors attached to this gateway to route directly
	// to the assigned addresses of the other attached Connectors. It is disabled
	// by default; VPC routes remain available regardless of this setting.
	PeerRouting bool `json:"peerRouting,omitempty"`
	// Placement selects every platform Location where this logical gateway is
	// offered. It is used only by the managed-network-v1 contract.
	Placement *ConnectGatewayPlacementPolicy `json:"placement,omitempty"`
}

type ConnectGatewayPlacementPolicy struct {
	// +kubebuilder:validation:Required
	LocationSelector metav1.LabelSelector       `json:"locationSelector"`
	Availability     ConnectGatewayAvailability `json:"availability,omitempty"`
}

type ConnectGatewayAvailability struct {
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=1
	MinReady int32 `json:"minReady,omitempty"`
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
	// Placement counts are the only per-location information published on a
	// managed logical gateway. Details remain on ConnectGatewayPlacement.
	Matched     int32 `json:"matched,omitempty"`
	Ready       int32 `json:"ready,omitempty"`
	Unavailable int32 `json:"unavailable,omitempty"`
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
	ObservedGeneration      int64                      `json:"observedGeneration,omitempty"`
	EndpointID              string                     `json:"endpointID,omitempty"`
	AssignedAddress         string                     `json:"assignedAddress,omitempty"`
	PeerAddress             string                     `json:"peerAddress,omitempty"`
	Routes                  []string                   `json:"routes,omitempty"`
	RelayURLs               []string                   `json:"relayURLs,omitempty"`
	Conditions              []metav1.Condition         `json:"conditions,omitempty"`
	SelectedPlacementRef    string                     `json:"selectedPlacementRef,omitempty"`
	EffectivePolicyRevision string                     `json:"effectivePolicyRevision,omitempty"`
	NetworkPlan             *ConnectNetworkPlanSummary `json:"networkPlan,omitempty"`
}

type ConnectNetworkPlanSummary struct {
	ExpectedPrefix      string   `json:"expectedPrefix,omitempty"`
	DestinationPrefixes []string `json:"destinationPrefixes,omitempty"`
	MTU                 int32    `json:"mtu,omitempty"`
}

// +kubebuilder:object:root=true
type ConnectNetworkBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConnectNetworkBinding `json:"items"`
}

// ConnectGatewayPlacement is controller-owned per-location state for one
// logical ConnectGateway. Users select the parent gateway, never a placement.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:metadata:annotations="discovery.miloapis.com/parent-contexts=Project"
// +kubebuilder:printcolumn:name="Gateway",type=string,JSONPath=`.spec.gatewayRef`
// +kubebuilder:printcolumn:name="Location",type=string,JSONPath=`.spec.locationRef`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
type ConnectGatewayPlacement struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConnectGatewayPlacementSpec   `json:"spec,omitempty"`
	Status            ConnectGatewayPlacementStatus `json:"status,omitempty"`
}

type ConnectGatewayPlacementSpec struct {
	GatewayRef  string `json:"gatewayRef"`
	LocationRef string `json:"locationRef"`
}

type ConnectGatewayPlacementStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	AssignmentRef      string             `json:"assignmentRef,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
type ConnectGatewayPlacementList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConnectGatewayPlacement `json:"items"`
}

// ConnectConnectionPolicy grants protected Connector classifications access
// to logical gateways. Applicable policies compose additively over deny-all.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:metadata:annotations="discovery.miloapis.com/parent-contexts=Project"
type ConnectConnectionPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ConnectConnectionPolicySpec   `json:"spec,omitempty"`
	Status            ConnectConnectionPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:validation:XValidation:message="exactly one of gatewayRef or gatewaySelector is required",rule="(has(self.gatewayRef) ? 1 : 0) + (has(self.gatewaySelector) ? 1 : 0) == 1"
// +kubebuilder:validation:XValidation:message="gatewaySelector must use nonempty protected In/Exists requirements",rule="!has(self.gatewaySelector) || ((has(self.gatewaySelector.matchLabels) ? size(self.gatewaySelector.matchLabels) : 0) + (has(self.gatewaySelector.matchExpressions) ? size(self.gatewaySelector.matchExpressions) : 0) > 0 && (!has(self.gatewaySelector.matchLabels) || self.gatewaySelector.matchLabels.all(k, v, k.startsWith('policy.connect.datum.net/'))) && (!has(self.gatewaySelector.matchExpressions) || self.gatewaySelector.matchExpressions.all(r, r.key.startsWith('policy.connect.datum.net/') && (r.operator == 'In' || r.operator == 'Exists'))))"
// +kubebuilder:validation:XValidation:message="connectorSelector must use nonempty protected In/Exists requirements",rule="((has(self.connectorSelector.matchLabels) ? size(self.connectorSelector.matchLabels) : 0) + (has(self.connectorSelector.matchExpressions) ? size(self.connectorSelector.matchExpressions) : 0) > 0) && (!has(self.connectorSelector.matchLabels) || self.connectorSelector.matchLabels.all(k, v, k.startsWith('policy.connect.datum.net/'))) && (!has(self.connectorSelector.matchExpressions) || self.connectorSelector.matchExpressions.all(r, r.key.startsWith('policy.connect.datum.net/') && (r.operator == 'In' || r.operator == 'Exists')))"
type ConnectConnectionPolicySpec struct {
	GatewayRef      *LocalObjectReference `json:"gatewayRef,omitempty"`
	GatewaySelector *metav1.LabelSelector `json:"gatewaySelector,omitempty"`
	// ConnectorSelector is the prototype trusted subject mechanism. Only
	// controller/IAM-owned policy.connect.datum.net labels are accepted.
	ConnectorSelector metav1.LabelSelector `json:"connectorSelector"`
	Access            ConnectPolicyAccess  `json:"access"`
}

type LocalObjectReference struct {
	Name string `json:"name"`
}

type ConnectPolicyAccess struct {
	// +kubebuilder:validation:Enum=Network
	Permission string `json:"permission"`
}

type ConnectConnectionPolicyStatus struct {
	ObservedGeneration   int64              `json:"observedGeneration,omitempty"`
	ResolvedGatewayCount int32              `json:"resolvedGatewayCount,omitempty"`
	Revision             string             `json:"revision,omitempty"`
	Conditions           []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
type ConnectConnectionPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConnectConnectionPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ConnectorClass{}, &ConnectorClassList{}, &ConnectGatewayClass{}, &ConnectGatewayClassList{}, &Connector{}, &ConnectorList{}, &ConnectorAdvertisement{}, &ConnectorAdvertisementList{}, &ConnectGateway{}, &ConnectGatewayList{}, &ConnectNetworkBinding{}, &ConnectNetworkBindingList{}, &ConnectGatewayPlacement{}, &ConnectGatewayPlacementList{}, &ConnectConnectionPolicy{}, &ConnectConnectionPolicyList{})
}
