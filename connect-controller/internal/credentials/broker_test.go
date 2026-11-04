package credentials

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type resolverFunc func(context.Context, string) (Binding, error)

func (f resolverFunc) Resolve(ctx context.Context, name string) (Binding, error) { return f(ctx, name) }

type authenticatorFunc func(context.Context, string) (string, error)

func (f authenticatorFunc) Authenticate(ctx context.Context, token string) (string, error) {
	return f(ctx, token)
}

type issuerFunc func(context.Context, Binding) (IssuedTransport, error)

func (f issuerFunc) Mint(ctx context.Context, binding Binding) (IssuedTransport, error) {
	return f(ctx, binding)
}

func TestBrokerReturnsCredentialOnlyFromNoStoreMintPath(t *testing.T) {
	now := time.Date(2026, 11, 4, 20, 0, 0, 0, time.UTC)
	secret := "opaque-do-not-log-this-credential"
	b := &Broker{
		Now: func() time.Time { return now },
		Authenticator: authenticatorFunc(func(_ context.Context, token string) (string, error) {
			if token != "platform-token" {
				return "", fmt.Errorf("denied")
			}
			return "laptop", nil
		}),
		Resolver: resolverFunc(func(_ context.Context, name string) (Binding, error) {
			return Binding{Name: name, Connector: "laptop", PolicyRevision: "rev-1", NetworkPlan: NetworkPlan{DestinationPrefixes: []string{"fd20:0:27::/48"}, MTU: 1280}}, nil
		}),
		Issuer: issuerFunc(func(_ context.Context, binding Binding) (IssuedTransport, error) {
			return IssuedTransport{Authority: "masque.example.test", VPCSelector: "default/vpc", Credential: Credential(secret), ExpiresAt: now.Add(time.Minute), Transports: []string{"h3", "h2"}, ExpectedPrefix: "fd20:0:27:10:1:1::/96"}, nil
		}),
	}
	req := httptest.NewRequest(http.MethodPost, "/connectnetworkbindings/laptop-production/connection-credentials", nil)
	req.Header.Set("Authorization", "Bearer platform-token")
	rsp := httptest.NewRecorder()
	b.ServeHTTP(rsp, req)
	if rsp.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", rsp.Code, rsp.Body.String())
	}
	if rsp.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", rsp.Header().Get("Cache-Control"))
	}
	if !strings.Contains(rsp.Body.String(), secret) {
		t.Fatal("mint response omitted credential")
	}
	var descriptor Descriptor
	if err := json.Unmarshal(rsp.Body.Bytes(), &descriptor); err != nil {
		t.Fatal(err)
	}
	if descriptor.NetworkPlan.ExpectedPrefix != "fd20:0:27:10:1:1::/96" || descriptor.Transport.Type != TransportType {
		t.Fatalf("descriptor = %#v", descriptor.Redacted())
	}
	if strings.Contains(fmt.Sprintf("%v %#v", descriptor.Transport.Credential, descriptor.Transport.Credential), secret) {
		t.Fatal("credential leaked through formatting")
	}
	redacted, _ := json.Marshal(descriptor.Redacted())
	if strings.Contains(string(redacted), secret) || !strings.Contains(string(redacted), "REDACTED") {
		t.Fatalf("redacted descriptor = %s", redacted)
	}
}

func TestBrokerDoesNotMintForAnotherConnector(t *testing.T) {
	called := false
	b := &Broker{
		Authenticator: authenticatorFunc(func(context.Context, string) (string, error) { return "other", nil }),
		Resolver: resolverFunc(func(context.Context, string) (Binding, error) {
			return Binding{Name: "b", Connector: "laptop", PolicyRevision: "r"}, nil
		}),
		Issuer: issuerFunc(func(context.Context, Binding) (IssuedTransport, error) { called = true; return IssuedTransport{}, nil }),
	}
	req := httptest.NewRequest(http.MethodPost, "/connectnetworkbindings/b/connection-credentials", nil)
	req.Header.Set("Authorization", "Bearer token")
	rsp := httptest.NewRecorder()
	b.ServeHTTP(rsp, req)
	if rsp.Code != http.StatusForbidden || called {
		t.Fatalf("status=%d issuerCalled=%v", rsp.Code, called)
	}
}
