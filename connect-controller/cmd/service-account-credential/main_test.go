package main

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestInstallExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential-helper")
	if err := run("", path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0555 || info.Size() == 0 {
		t.Fatalf("invalid installed executable: %v", err)
	}
	if err := run("", path); err != nil {
		t.Fatalf("atomic reinstall: %v", err)
	}
	if err := run("config", path); err == nil {
		t.Fatal("ambiguous modes accepted")
	}
}

func TestExpiredExecRefreshFailureHasNoBearerFallback(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(state, []byte("succeed"), 0600); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Header.Get("Authorization") != "Bearer test-only-token" {
			t.Error("unexpected bearer")
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	config := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}, ExecProvider: &clientcmdapi.ExecConfig{
		Command: executable, Args: []string{"-test.run=^TestExecCredentialSubprocess$"}, APIVersion: "client.authentication.k8s.io/v1", InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
		Env: []clientcmdapi.ExecEnvVar{{Name: "CONNECT_TEST_EXEC_STATE", Value: state}},
	}}
	client, err := rest.HTTPClientFor(config)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if err := os.WriteFile(state, []byte("fail"), 0600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if response, err := client.Get(server.URL); err == nil {
			response.Body.Close()
			t.Fatal("failed refresh reused expired cached bearer")
		}
	}
	if requests.Load() != 1 {
		t.Fatal("failed refresh reached API with stale credential")
	}
}

func TestExecCredentialSubprocess(t *testing.T) {
	path := os.Getenv("CONNECT_TEST_EXEC_STATE")
	if path == "" {
		return
	}
	state, err := os.ReadFile(path)
	if err != nil || string(state) != "succeed" {
		os.Exit(1)
	}
	fmt.Print(`{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"test-only-token","expirationTimestamp":"2000-01-01T00:00:00Z"}}`)
	os.Exit(0)
}
