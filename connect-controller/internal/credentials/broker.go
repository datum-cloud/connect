// Package credentials implements the narrow sensitive minting boundary for
// managed-network bindings. Provider-specific issuance remains behind Issuer.
package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const TransportType = "masque.connect.datum.net/v1"

// Credential deliberately redacts every string/debug rendering while still
// encoding the opaque value in the one no-store minting response.
type Credential string

func (Credential) String() string                 { return "[REDACTED]" }
func (Credential) GoString() string               { return "[REDACTED]" }
func (c Credential) MarshalJSON() ([]byte, error) { return json.Marshal(string(c)) }

type NetworkPlan struct {
	ExpectedPrefix      string   `json:"expectedPrefix"`
	DestinationPrefixes []string `json:"destinationPrefixes"`
	MTU                 int32    `json:"mtu"`
}

type Transport struct {
	Type        string     `json:"type"`
	Authority   string     `json:"authority"`
	VPCSelector string     `json:"vpcSelector"`
	Credential  Credential `json:"credential"`
	ExpiresAt   time.Time  `json:"expiresAt"`
	Transports  []string   `json:"transports"`
}

type Descriptor struct {
	Binding        string      `json:"binding"`
	PolicyRevision string      `json:"policyRevision"`
	NetworkPlan    NetworkPlan `json:"networkPlan"`
	Transport      Transport   `json:"transport"`
}

// Redacted returns the only representation suitable for logs and snapshots.
func (d Descriptor) Redacted() Descriptor {
	d.Transport.Credential = Credential("[REDACTED]")
	return d
}

type Binding struct {
	Name           string
	Connector      string
	PolicyRevision string
	NetworkPlan    NetworkPlan
	Placement      string
}

type Resolver interface {
	Resolve(context.Context, string) (Binding, error)
}

type Authenticator interface {
	Authenticate(context.Context, string) (connector string, err error)
}

type IssuedTransport struct {
	Authority      string
	VPCSelector    string
	Credential     Credential
	ExpiresAt      time.Time
	Transports     []string
	ExpectedPrefix string
}

// Issuer is the provider boundary. A Galactic staging implementation brokers
// the existing masque-authority grant; the Connect controller never reads or
// writes Galactic grant records directly.
type Issuer interface {
	Mint(context.Context, Binding) (IssuedTransport, error)
}

type Broker struct {
	Resolver      Resolver
	Authenticator Authenticator
	Issuer        Issuer
	Now           func() time.Time
}

func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	fail := func(code int) { http.Error(w, http.StatusText(code), code) }
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		fail(http.StatusNotFound)
		return
	}
	const prefix = "/connectnetworkbindings/"
	const suffix = "/connection-credentials"
	if !strings.HasPrefix(r.URL.Path, prefix) || !strings.HasSuffix(r.URL.Path, suffix) {
		fail(http.StatusNotFound)
		return
	}
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), suffix)
	if name == "" || strings.Contains(name, "/") {
		fail(http.StatusBadRequest)
		return
	}
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") || len(authorization) <= len("Bearer ") {
		fail(http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	connector, err := b.Authenticator.Authenticate(ctx, strings.TrimPrefix(authorization, "Bearer "))
	if err != nil {
		fail(http.StatusUnauthorized)
		return
	}
	binding, err := b.Resolver.Resolve(ctx, name)
	if err != nil || binding.Connector != connector || binding.PolicyRevision == "" {
		fail(http.StatusForbidden)
		return
	}
	issued, err := b.Issuer.Mint(ctx, binding)
	if err != nil {
		fail(http.StatusServiceUnavailable)
		return
	}
	now := time.Now()
	if b.Now != nil {
		now = b.Now()
	}
	if issued.Authority == "" || issued.VPCSelector == "" || issued.Credential == "" || issued.ExpiresAt.Sub(now) <= 0 || issued.ExpiresAt.Sub(now) > 24*time.Hour || issued.ExpectedPrefix == "" {
		fail(http.StatusServiceUnavailable)
		return
	}
	plan := binding.NetworkPlan
	plan.ExpectedPrefix = issued.ExpectedPrefix
	descriptor := Descriptor{Binding: binding.Name, PolicyRevision: binding.PolicyRevision, NetworkPlan: plan, Transport: Transport{Type: TransportType, Authority: issued.Authority, VPCSelector: issued.VPCSelector, Credential: issued.Credential, ExpiresAt: issued.ExpiresAt, Transports: issued.Transports}}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(descriptor)
}

var ErrUnavailable = errors.New("credential issuer unavailable")
