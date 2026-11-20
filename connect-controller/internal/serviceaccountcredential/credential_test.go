package serviceaccountcredential

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestExchangeVerifiedAssertionAndRenewal(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}), 0600); err != nil {
		t.Fatal(err)
	}
	var mutex sync.Mutex
	seen := map[string]bool{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.ParseForm() != nil || request.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || request.Form.Get("scope") != "openid profile email urn:zitadel:iam:org:project:id:audience:aud" {
			t.Error("incorrect token exchange form")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		parts := strings.Split(request.Form.Get("assertion"), ".")
		if len(parts) != 3 {
			t.Error("invalid assertion")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil || rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest[:], signature) != nil {
			t.Error("invalid assertion signature")
		}
		var header map[string]string
		headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
		if json.Unmarshal(headerJSON, &header) != nil || header["kid"] != "key" || header["alg"] != "RS256" || header["typ"] != "JWT" {
			t.Error("invalid assertion header")
		}
		var claims struct {
			Issuer   string `json:"iss"`
			Subject  string `json:"sub"`
			Audience string `json:"aud"`
			Issued   int64  `json:"iat"`
			Expires  int64  `json:"exp"`
			ID       string `json:"jti"`
		}
		claimJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
		if json.Unmarshal(claimJSON, &claims) != nil || claims.Issuer != "service-account-uid" || claims.Subject != claims.Issuer || claims.Audience != "https://"+request.Host || claims.Expires-claims.Issued != 60 || time.Since(time.Unix(claims.Issued, 0)) > 10*time.Second {
			t.Error("incorrect identity/audience/lifetime claims")
		}
		if _, err := uuid.Parse(claims.ID); err != nil {
			t.Error("missing nonce")
		}
		mutex.Lock()
		if seen[claims.ID] {
			t.Error("assertion nonce reused")
		}
		seen[claims.ID] = true
		mutex.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"access_token":"test-only-token","token_type":"Bearer","expires_in":43199}`))
	}))
	defer server.Close()
	config := Config{TokenURL: server.URL + "/oauth/v2/token", Audience: "audience", Subject: "service-account-uid", KeyID: "key", PrivateKeyPath: keyPath, KeyExpiresAt: time.Now().Add(time.Hour)}
	for range 2 {
		before := time.Now()
		credential, err := Exchange(context.Background(), config, server.Client().Transport)
		if err != nil {
			t.Fatal(err)
		}
		if credential.APIVersion != "client.authentication.k8s.io/v1" || credential.Kind != "ExecCredential" || credential.Status.Token != "test-only-token" || credential.Status.ExpirationTimestamp.After(before.Add(5*time.Minute+time.Second)) || !credential.Status.ExpirationTimestamp.After(before.Add(4*time.Minute)) {
			t.Fatal("invalid exec credential or unbounded refresh expiry")
		}
	}
	if _, err := Exchange(context.Background(), config, nil); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
	for _, scenario := range []string{"http", "userinfo", "query", "expired-key", "scope-injection", "missing-identity"} {
		t.Run(scenario, func(t *testing.T) {
			bad := config
			switch scenario {
			case "http":
				bad.TokenURL = strings.Replace(config.TokenURL, "https:", "http:", 1)
			case "userinfo":
				bad.TokenURL = "https://user:password@example.test/token"
			case "query":
				bad.TokenURL += "?redirect=other"
			case "expired-key":
				bad.KeyExpiresAt = time.Now()
			case "scope-injection":
				bad.Audience = "audience another-scope"
			case "missing-identity":
				bad.Subject = ""
			}
			if _, err := Exchange(context.Background(), bad, server.Client().Transport); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	for _, response := range []string{`{}`, `{"access_token":"sensitive","token_type":"Bearer"}`, `{"access_token":"sensitive","token_type":"Basic","expires_in":3600}`, `{"access_token":"sensitive","token_type":"Bearer","expires_in":10}`, `{"access_token":"sensitive","token_type":"Bearer","expires_in":9223372036854775807}`, "sensitive-invalid-json"} {
		t.Run(response, func(t *testing.T) {
			badServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { _, _ = writer.Write([]byte(response)) }))
			defer badServer.Close()
			bad := config
			bad.TokenURL = badServer.URL
			if result, err := Exchange(context.Background(), bad, badServer.Client().Transport); err == nil || result != nil || strings.Contains(err.Error(), "sensitive") {
				t.Fatalf("invalid response accepted or leaked: %v", err)
			}
		})
	}
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, server.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	config.TokenURL = redirect.URL
	if _, err := Exchange(context.Background(), config, redirect.Client().Transport); err == nil {
		t.Fatal("redirect accepted")
	}
}

func TestLoadRejectsUnknownAndTrailingConfig(t *testing.T) {
	for _, content := range []string{`{"unknown":"secret"}`, `{} {}`, `null trailing`} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("malformed configuration accepted or leaked")
		}
	}
}
