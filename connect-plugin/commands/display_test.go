package commands

import (
	"bytes"
	"encoding/json"
	"github.com/spf13/cobra"
	"strings"
	"testing"
)

func TestHumanOutput(t *testing.T) {
	for _, tt := range []struct {
		name, command, data string
		contains, absent    []string
	}{
		{"health", "health", `{"status":"ok"}`, []string{"daemon is reachable"}, []string{"{", "connected to project"}},
		{"new project", "status", `{"project":"demo","credential_configured":false}`, []string{"not configured", `up --project "demo"`, "datumctl login"}, []string{"/v1/up"}},
		{"down", "down", `{"project":"demo","credential_configured":true,"desired_up":false}`, []string{"Disconnected", `up --project "demo"`}, nil},
		{"running", "up", `{"project":"demo","running":true,"credential_configured":true,"connector":{"name":"device-a"}}`, []string{"Connected", "Connector: device-a", "No services"}, nil},
		{"oidc authentication", "status", `{"project":"demo","running":true,"credential_configured":true,"authentication":{"kind":"oidc","session":"personal"}}`, []string{"Authentication: datumctl session personal (user permissions)"}, nil},
		{"file authentication", "status", `{"project":"demo","running":true,"credential_configured":true,"authentication":{"kind":"credential_file"}}`, []string{"Authentication: credential file"}, nil},
		{"private", "serve", `{"id":"s1","endpoint":"localhost:22","protocol":"tcp","desired_active":true,"running":true,"ready":true}`, []string{"Sharing localhost:22 (TCP) in the background.", "project devices only", "unserve localhost:22"}, []string{"publicly available", "s1"}},
		{"pending public", "serve", `{"id":"s2","endpoint":"localhost:8080","protocol":"tcp","public":true,"desired_active":true,"running":true,"ready":false,"hostnames":["demo.example"]}`, []string{"pending", "no public URL is confirmed", "demo.example"}, []string{"active)"}},
		{"dial", "dial", `{"connector":"peer","port":22,"bind":2222,"local_port":2222,"protocol":"tcp","desired_active":true,"running":true}`, []string{"Listening", "127.0.0.1:2222", "depends on the remote service", "hangup 2222"}, []string{"Connected"}},
		{"retained error", "status", `{"project":"demo","credential_configured":true,"desired_up":true,"last_error":"authorization unavailable","last_error_stage":"renew","services":[{"id":"s1","endpoint":"localhost:22","protocol":"tcp","last_error":"origin refused","last_error_stage":"service_reconcile"}]}`, []string{"needs attention", "renew", "authorization unavailable", "s1", "origin refused"}, nil},
		{"unserve", "unserve", `{"deleted":true,"id":"s1"}`, []string{"Stopped exposing service s1"}, nil},
		{"hangup", "hangup", `{"deleted":true,"port":2222}`, []string{"Closed local port 2222"}, nil},
		{"failed ephemeral", "status", `{"project":"demo","credential_configured":true,"dials":[{"bind":0,"last_error":"peer unavailable"}]}`, []string{`hangup 0 --project "demo"`}, nil},
		{"ping", "ping", `{"address":"peer","latency_ms":12}`, []string{"Connector peer is reachable (12 ms)"}, nil},
		{"join", "join", `{"network":"vpc","assigned_address":"192.0.2.2/32","interface_name":"dcip0","routes":["10.78.0.0/24"],"running":true}`, []string{"Connected to vpc", "Route: 10.78.0.0/24", "Leave: datumctl connect leave vpc"}, []string{"192.0.2.2/32", "Ephemeral"}},
		{"IPv6 join", "join", `{"network":"vpc6","assigned_address":"2001:db8:20::2/128","interface_name":"dcip6","routes":["2001:db8:30::/64"],"running":true}`, []string{"Connected to vpc6", "Route: 2001:db8:30::/64", "Leave: datumctl connect leave vpc6"}, []string{"2001:db8:20::2/128", "dcip6"}},
		{"peer waiting join", "join", `{"network":"team","mode":"peer","peer":"peer-key","peer_address":"fd79::2/128","assigned_address":"fd79::1/128","interface_name":"dcip0","routes":["fd79::2/128"],"running":true,"connected":false,"state":"waiting_for_peer"}`, []string{"Waiting for the other device to join team", "On the other device: datumctl connect join team", "Route: fd79::2/128", "Leave: datumctl connect leave team"}, []string{"peer-key", "dcip0", "Ephemeral", "matching peer approvals"}},
		{"peer connected join", "join", `{"network":"team","mode":"peer","peer":"peer-key","peer_address":"fd79::2/128","assigned_address":"fd79::1/128","interface_name":"dcip0","routes":["fd79::2/128"],"running":true,"connected":true,"state":"connected"}`, []string{"Connected to team", "Route: fd79::2/128", "Leave: datumctl connect leave team"}, []string{"peer-key", "fd79::1/128", "dcip0"}},
		{"peer waiting status", "status", `{"project":"demo","running":true,"credential_configured":true,"networks":[{"network":"team","mode":"peer","peer":"peer-key","peer_address":"fd79::2/128","assigned_address":"fd79::1/128","running":true,"connected":false,"state":"waiting_for_peer"}]}`, []string{"Network team: waiting for peer", "traffic is not connected", "matching peer approvals"}, []string{"Network team: connected"}},
		{"peer diagnostics status", "status", `{"project":"demo","running":true,"credential_configured":true,"networks":[{"network":"team","mode":"peer","running":true,"connected":false,"last_connect_error":"peer is not approved","acl_drops":3}]}`, []string{"Last connection attempt: peer is not approved", "Packet policy dropped 3 packets", "JSON status includes denial reasons"}, []string{"Network team: connected", "Check the configured peer approvals"}},
		{"IPv6 network status", "status", `{"project":"demo","credential_configured":true,"running":true,"networks":[{"network":"vpc6","mode":"gateway","assigned_address":"2001:db8:20::2/128","interface_name":"dcip6","routes":["2001:db8:30::/64"],"running":true,"delivery_mode":"quic_datagram","effective_datagram_ip_capacity":1400,"local_tun_to_transport_packets":17,"transport_to_local_tun_packets":13}]}`, []string{"Network vpc6: connected", "2001:db8:20::2/128", "2001:db8:30::/64", "IP datagram capacity: 1400 bytes", "Packets: to gateway 17 (last never); from gateway 13 (last never)"}, nil},
		{"leave", "leave", `{"network":"vpc","left":true}`, []string{"Left vpc", "attachment removed"}, nil},
		{"network status", "status", `{"project":"demo","credential_configured":true,"running":true,"networks":[{"network":"vpc","assigned_address":"192.0.2.2/32","interface_name":"dcip0","routes":["10.78.0.0/24"],"running":true}]}`, []string{"Network vpc: connected", "ephemeral native preview"}, []string{"No services"}},
		{"datagram network status", "status", `{"project":"demo","credential_configured":true,"running":true,"networks":[{"network":"vpc","assigned_address":"192.0.2.2/32","interface_name":"dcip0","routes":["10.78.0.0/24"],"running":false,"delivery_mode":"quic_datagram","effective_datagram_ip_capacity":1200,"mtu_errors":1,"last_error":"gateway closed","last_transport_error":"path capacity 1200 is below approved MTU 1280"}]}`, []string{"Network vpc: disconnected", "Transport: quic_datagram", "IP datagram capacity: 1200 bytes", "MTU errors: 1", "path capacity 1200 is below approved MTU 1280"}, []string{"gateway closed"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			cmd := &cobra.Command{Use: tt.command}
			cmd.SetOut(&out)
			if err := writeHuman(cmd, json.RawMessage(tt.data)); err != nil {
				t.Fatal(err)
			}
			for _, s := range tt.contains {
				if !strings.Contains(out.String(), s) {
					t.Errorf("output lacks %q: %s", s, out.String())
				}
			}
			for _, s := range tt.absent {
				if strings.Contains(out.String(), s) {
					t.Errorf("output contains %q: %s", s, out.String())
				}
			}
		})
	}
}

func TestHumanCleanupPreservesProject(t *testing.T) {
	var out bytes.Buffer
	cmd := &cobra.Command{Use: "serve"}
	cmd.SetOut(&out)
	cmd.Flags().String("project", "different-project", "")
	if err := writeHuman(cmd, json.RawMessage(`{"id":"s1","endpoint":"localhost:22"}`)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `unserve localhost:22 --project different-project`) {
		t.Fatal(out.String())
	}
}

func TestServeOutputExplainsBothDevices(t *testing.T) {
	var out bytes.Buffer
	cmd := &cobra.Command{Use: "serve"}
	cmd.SetOut(&out)
	cmd.Flags().String("project", "datum-cloud", "")
	data := json.RawMessage(`{"connector":"scot-mac","id":"service-123","endpoint":"google.com:443","protocol":"tcp","desired_active":true,"running":true,"ready":true}`)
	if err := writeHuman(cmd, data); err != nil {
		t.Fatal(err)
	}
	want := `Sharing google.com:443 (TCP) in the background.
Access: devices in project "datum-cloud" only.

On the other device (skip up if already connected):
  datumctl connect up --project datum-cloud
  datumctl connect dial scot-mac:443 --bind 8443 --project datum-cloud

Connect your app to 127.0.0.1:8443 on that device.
Traffic forwards through this device to google.com:443.

Stop sharing:
  datumctl connect unserve google.com:443 --project datum-cloud
`
	if out.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestServeInstructionsRespectProtocolAccessAndState(t *testing.T) {
	for _, tt := range []struct {
		name, data       string
		contains, absent []string
	}{
		{"udp IPv6", `{"connector":"peer","id":"s1","endpoint":"[::1]:5353","protocol":"udp","desired_active":true,"running":true,"allow":["key-a"]}`, []string{"only the device you allowed", "dial peer:5353 --bind 5353 --protocol udp", "unserve '[::1]:5353'"}, []string{"project devices only", "key-a"}},
		{"failed", `{"connector":"peer","id":"s1","endpoint":"localhost:80","protocol":"tcp","desired_active":true,"running":true,"last_error":"authorization failed"}`, []string{"needs attention", "authorization failed"}, []string{"Sharing ", "connect dial", "Connect your app"}},
		{"stopped", `{"connector":"peer","id":"s1","endpoint":"localhost:80","protocol":"tcp","desired_active":false,"running":true}`, []string{"stopped"}, []string{"Sharing ", "connect dial"}},
		{"public", `{"connector":"peer","id":"s1","endpoint":"localhost:8080","protocol":"tcp","desired_active":true,"running":true,"ready":true,"public":true,"hostnames":["demo.example"]}`, []string{"Access: public", "demo.example"}, []string{"connect dial", "project devices only"}},
		{"legacy identifier", `{"connector":"connect-e913e322c930ca04359b6c9f5852e54152be1e62","id":"s1","endpoint":"localhost:22","protocol":"tcp","desired_active":true,"running":true}`, []string{"dial connect-e913e322c930ca04359b6c9f5852e54152be1e62:22 --bind 2222"}, []string{"unserve s1"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			cmd := &cobra.Command{Use: "serve"}
			cmd.SetOut(&out)
			if err := writeHuman(cmd, json.RawMessage(tt.data)); err != nil {
				t.Fatal(err)
			}
			for _, value := range tt.contains {
				if !strings.Contains(out.String(), value) {
					t.Errorf("missing %q in %s", value, out.String())
				}
			}
			for _, value := range tt.absent {
				if strings.Contains(out.String(), value) {
					t.Errorf("unexpected %q in %s", value, out.String())
				}
			}
		})
	}
}

func TestSuggestedLocalPortIsUnprivileged(t *testing.T) {
	for remote, want := range map[string]string{"22": "2222", "80": "8080", "443": "8443", "53": "10053", "1023": "11023", "1024": "1024", "8080": "8080", "65535": "65535"} {
		if got := suggestedLocalPort(remote); got != want {
			t.Errorf("%s: got %s, want %s", remote, got, want)
		}
	}
}

func TestServeJSONKeepsMachineReadableIdentifiers(t *testing.T) {
	var out bytes.Buffer
	cmd := &cobra.Command{Use: "serve"}
	cmd.SetOut(&out)
	cmd.Flags().String("output", "json", "")
	data := json.RawMessage(`{"id":"service-123","endpoint":"google.com:443","connector":"peer"}`)
	if err := writeJSON(cmd, data); err != nil {
		t.Fatal(err)
	}
	var got, want any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("changed JSON: %s", out.String())
	}
}

func TestHumanOutputDoesNotConfirmUnconfirmedDeletion(t *testing.T) {
	for _, command := range []string{"unserve", "hangup", "leave"} {
		if err := writeHuman(&cobra.Command{Use: command}, json.RawMessage(`{"deleted":false}`)); err == nil {
			t.Fatalf("%s reported success", command)
		}
	}
}
