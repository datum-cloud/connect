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
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthentication "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

type Config struct {
	TokenURL       string    `json:"tokenURL"`
	Audience       string    `json:"audience"`
	Subject        string    `json:"subject"`
	KeyID          string    `json:"keyID"`
	PrivateKeyPath string    `json:"privateKeyPath"`
	KeyExpiresAt   time.Time `json:"keyExpiresAt"`
}

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, errors.New("cannot open credential configuration")
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 65537))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, errors.New("invalid credential configuration")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return Config{}, errors.New("unexpected trailing credential configuration")
	}
	return config, nil
}

func Exchange(ctx context.Context, config Config, transport http.RoundTripper) (*clientauthentication.ExecCredential, error) {
	now := time.Now()
	endpoint, err := url.Parse(config.TokenURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("token endpoint must be an explicit HTTPS URL without credentials, query or fragment")
	}
	if config.Subject == "" || config.KeyID == "" || config.Audience == "" || strings.ContainsAny(config.Audience, " \t\r\n") || !config.KeyExpiresAt.After(now.Add(time.Minute)) {
		return nil, errors.New("credential identity, audience or key lifetime is invalid")
	}
	keyFile, err := os.Open(config.PrivateKeyPath)
	if err != nil {
		return nil, errors.New("cannot open private key")
	}
	defer keyFile.Close()
	encoded, err := io.ReadAll(io.LimitReader(keyFile, 65537))
	if err != nil || len(encoded) > 65536 {
		return nil, errors.New("cannot read bounded private key")
	}
	block, remainder := pem.Decode(encoded)
	if block == nil || len(strings.TrimSpace(string(remainder))) != 0 {
		return nil, errors.New("invalid private key PEM")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, errors.New("invalid RSA private key")
		}
		privateKey, _ = parsed.(*rsa.PrivateKey)
	}
	if privateKey == nil || privateKey.N.BitLen() < 2048 || privateKey.Validate() != nil {
		return nil, errors.New("RSA private key must be valid and at least 2048 bits")
	}
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": config.KeyID})
	claims, _ := json.Marshal(map[string]any{"iss": config.Subject, "sub": config.Subject, "aud": endpoint.Scheme + "://" + endpoint.Host, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": uuid.NewString()})
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return nil, errors.New("cannot sign service account assertion")
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)},
		"scope":      {"openid profile email urn:zitadel:iam:org:project:id:" + config.Audience + ":aud"},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, config.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errors.New("cannot construct token request")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if transport == nil {
		direct := http.DefaultTransport.(*http.Transport).Clone()
		direct.Proxy = nil
		defer direct.CloseIdleConnections()
		transport = direct
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("token redirects forbidden") }}
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("token exchange failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("token endpoint rejected exchange")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1048577))
	if err != nil || len(body) > 1048576 {
		return nil, errors.New("invalid token response size")
	}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if json.Unmarshal(body, &token) != nil || token.AccessToken == "" || strings.ContainsAny(token.AccessToken, " \t\r\n") || !strings.EqualFold(token.TokenType, "Bearer") || token.ExpiresIn < 60 || token.ExpiresIn > 86400 {
		return nil, errors.New("invalid bearer token or bounded expiry")
	}
	expires := now.Add(time.Duration(token.ExpiresIn)*time.Second - 30*time.Second)
	if maximum := now.Add(5 * time.Minute); expires.After(maximum) {
		expires = maximum
	}
	if maximum := config.KeyExpiresAt.Add(-30 * time.Second); expires.After(maximum) {
		expires = maximum
	}
	if !expires.After(time.Now().Add(15 * time.Second)) {
		return nil, errors.New("token expired during exchange")
	}
	return &clientauthentication.ExecCredential{
		TypeMeta: metav1.TypeMeta{APIVersion: "client.authentication.k8s.io/v1", Kind: "ExecCredential"},
		Status:   &clientauthentication.ExecCredentialStatus{Token: token.AccessToken, ExpirationTimestamp: &metav1.Time{Time: expires}},
	}, nil
}
