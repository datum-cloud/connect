package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	connectapi "go.datum.net/datumctl-plugins/connect/internal/api"
	"go.datum.net/datumctl-plugins/connect/internal/daemonservice"
)

func TestWaitForPeerPollsUntilConnected(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		if requests == 1 {
			io.WriteString(w, `{"networks":[{"network":"vpc","mode":"peer","running":true,"connected":false}]}`)
			return
		}
		io.WriteString(w, `{"networks":[{"network":"vpc","mode":"peer","running":true,"connected":true}]}`)
	}))
	defer server.Close()
	client, err := connectapi.New(server.URL, "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	result, connected, err := waitForPeer(context.Background(), client, "demo", "vpc", 2*time.Second)
	if err != nil || !connected || requests < 2 {
		t.Fatalf("connected=%v requests=%d err=%v", connected, requests, err)
	}
	var value networkDisplay
	if err := json.Unmarshal(result, &value); err != nil || !value.Connected {
		t.Fatalf("result=%s err=%v", result, err)
	}
}

func TestRoutedJoinWaitsByDefaultBeforeReturning(t *testing.T) {
	t.Setenv("DATUM_CONNECT_TOKEN", "local-test-token")
	statusRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/health":
			io.WriteString(w, `{"status":"ok"}`)
		case "/v1/networks":
			io.WriteString(w, `{"network":"vpc","mode":"peer","running":true,"connected":false,"routes":["fd20:0:27::/48"]}`)
		case "/v1/status":
			statusRequests++
			connected := statusRequests > 1
			io.WriteString(w, fmt.Sprintf(`{"networks":[{"network":"vpc","mode":"peer","running":true,"connected":%t,"routes":["fd20:0:27::/48"]}]}`, connected))
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	var output bytes.Buffer
	cmd := newJoin(&options{baseURL: server.URL, timeout: time.Second})
	cmd.Flags().String("project", "demo", "")
	cmd.Flags().String("output", "json", "")
	cmd.SetOut(&output)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"vpc", "--wait-timeout", "3s"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if statusRequests < 2 || !strings.Contains(output.String(), `"connected":true`) {
		t.Fatalf("routed join returned before peer connected: polls=%d output=%s", statusRequests, output.String())
	}
}

func TestRoutedJoinNoWaitReturnsImmediately(t *testing.T) {
	t.Setenv("DATUM_CONNECT_TOKEN", "local-test-token")
	statusRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/health":
			io.WriteString(w, `{"status":"ok"}`)
		case "/v1/networks":
			io.WriteString(w, `{"network":"vpc","mode":"peer","running":true,"connected":false,"routes":["fd20:0:27::/48"]}`)
		case "/v1/status":
			statusRequests++
			io.WriteString(w, `{"networks":[]}`)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	cmd := newJoin(&options{baseURL: server.URL, timeout: time.Second})
	cmd.Flags().String("project", "demo", "")
	cmd.Flags().String("output", "json", "")
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"vpc", "--no-wait"})
	if err := cmd.Execute(); err != nil || statusRequests != 0 {
		t.Fatalf("err=%v status polls=%d; --no-wait should return immediately", err, statusRequests)
	}
}

func TestJoinGuidedApprovalAndAutomationBoundary(t *testing.T) {
	for _, test := range []struct {
		name, input            string
		guided, ready, success bool
		prompts                int
	}{
		{"first join accepted", "y\n", true, false, true, 1},
		{"declined", "n\n", true, false, false, 0},
		{"script never elevates", "", false, false, false, 0},
		{"saved ready", "", false, true, true, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("DATUM_CONNECT_TOKEN", "local-test-token")
			previousGuided, previousEnsure := guidedSetupEnabled, ensureNetworking
			t.Cleanup(func() { guidedSetupEnabled, ensureNetworking = previousGuided, previousEnsure })
			guidedSetupEnabled = func(*cobra.Command, *options) bool { return test.guided }
			approvals, prepared, joins := 0, 0, 0
			ensureNetworking = func(_ *cobra.Command, _, _ string, config daemonservice.HelperApprovals, _ bool) error {
				approvals++
				if len(config.Approvals) != 1 {
					t.Fatal("unexpected approval")
				}
				return nil
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v1/health":
					io.WriteString(w, `{"status":"ok"}`)
				case "/v1/status":
					io.WriteString(w, `{"running":true}`)
				case "/v1/networks/prepare":
					prepared++
					var body map[string]any
					json.NewDecoder(r.Body).Decode(&body)
					if body["peer"] != "friend-mac" || body["network"] != "friend" {
						t.Fatalf("wrong plan: %v", body)
					}
					io.WriteString(w, `{}`)
				case "/v1/networks/friend/setup":
					io.WriteString(w, `{"network":"friend","binding":{"peer":"pinned-key","assigned_address":"fd00::1/128","peer_address":"fd00::2/128","interface_name":"dcfriend","mtu":1280},"helper_config":{"allowed_uid":501,"approvals":[{"interface_name":"dcfriend","assigned_address":"fd00::1/128","peer_address":"fd00::2/128","mtu":1280}]}}`)
				case "/v1/networks":
					joins++
					if !test.ready && approvals == 0 {
						w.WriteHeader(409)
						io.WriteString(w, `{"error":"approval required","code":"network_setup_required"}`)
						return
					}
					io.WriteString(w, `{"network":"friend","running":true,"mode":"peer","connected":false}`)
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			cmd := newJoin(&options{baseURL: server.URL, timeout: time.Second})
			cmd.Flags().String("project", "demo", "")
			cmd.Flags().String("output", "json", "")
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetIn(strings.NewReader(test.input))
			cmd.SetArgs([]string{"friend", "--peer", "friend-mac", "--allow-tcp", "8080", "--allow-ping"})
			err := cmd.Execute()
			if (err == nil) != test.success || approvals != test.prompts || prepared != 1 || joins < 1 {
				t.Fatalf("err=%v approvals=%d prepared=%d joins=%d", err, approvals, prepared, joins)
			}
		})
	}
}

func TestJoinRejectsPermissionFlagsBeforeSetup(t *testing.T) {
	for _, args := range [][]string{{"friend", "--allow-ping"}, {"friend", "--peer", "mac"}, {"friend", "--peer", "mac", "--allow-tcp", "0"}} {
		cmd := newJoin(&options{})
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestSubnetJoinLimitsInitiationToClient(t *testing.T) {
	for _, flag := range []string{"--routes", "--advertise-routes"} {
		t.Run(flag, func(t *testing.T) {
			t.Setenv("DATUM_CONNECT_TOKEN", "local-test-token")
			var prepared bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v1/health":
					io.WriteString(w, `{"status":"ok"}`)
				case "/v1/status":
					io.WriteString(w, `{"running":true}`)
				case "/v1/networks/prepare":
					prepared = true
					var body struct {
						Inbound   []networkRule `json:"allow_inbound"`
						Outbound  []networkRule `json:"allow_outbound"`
						Routes    []string      `json:"routes"`
						Advertise []string      `json:"advertise_routes"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if flag == "--routes" {
						if len(body.Inbound) != 0 || len(body.Outbound) != 1 || len(body.Routes) != 1 || len(body.Advertise) != 0 {
							t.Errorf("unsafe client request: %+v", body)
						}
					} else if len(body.Inbound) != 1 || len(body.Outbound) != 0 || len(body.Routes) != 0 || len(body.Advertise) != 1 {
						t.Errorf("unsafe router request: %+v", body)
					}
					io.WriteString(w, `{}`)
				case "/v1/networks":
					io.WriteString(w, `{"network":"vpc","running":true}`)
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			cmd := newJoin(&options{baseURL: server.URL, timeout: time.Second})
			cmd.Flags().String("project", "demo", "")
			cmd.Flags().String("output", "json", "")
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{"vpc", "--peer", "other", flag, "fd20:27::/48", "--allow-tcp", "22"})
			if err := cmd.Execute(); err != nil || !prepared {
				t.Fatalf("err=%v prepared=%v", err, prepared)
			}
		})
	}
}

func TestJoinRejectsUnsafeSubnetFlagsBeforeSetup(t *testing.T) {
	for _, args := range [][]string{
		{"vpc", "--routes", "fd20::/64"},
		{"vpc", "--peer", "router", "--allow-ping", "--routes", "::/0"},
		{"vpc", "--peer", "router", "--allow-ping", "--routes", "10.0.0.0/24"},
		{"vpc", "--peer", "router", "--allow-ping", "--routes", "fd20::1/64"},
		{"vpc", "--peer", "router", "--allow-ping", "--routes", "fd20::/64", "--advertise-routes", "fd21::/64"},
	} {
		cmd := newJoin(&options{})
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("accepted unsafe flags: %v", args)
		}
	}
}

func TestApprovalPlanCannotHideSubnetRoutes(t *testing.T) {
	plan := networkPlan{Network: "vpc", HelperConfig: daemonservice.HelperApprovals{Approvals: []daemonservice.InterfaceApproval{{Routes: []string{"fd20::/64"}}}}}
	if validateNetworkPlan(plan, "vpc") == nil {
		t.Fatal("accepted undisplayed subnet route")
	}
	plan.Binding.Routes = []string{"fd20::/64"}
	if err := validateNetworkPlan(plan, "vpc"); err != nil {
		t.Fatal(err)
	}
	plan.HelperConfig.Approvals[0].AdvertiseRoutes = []string{"fd21::/64"}
	if validateNetworkPlan(plan, "vpc") == nil {
		t.Fatal("accepted undisplayed forwarding approval")
	}
}

func TestApprovalPlanCannotHideAdditionalHostPairs(t *testing.T) {
	plan := networkPlan{Network: "friend", HelperConfig: daemonservice.HelperApprovals{Approvals: []daemonservice.InterfaceApproval{{}, {}}}}
	if validateNetworkPlan(plan, "friend") == nil {
		t.Fatal("accepted hidden approval")
	}
	plan.HelperConfig.Approvals = plan.HelperConfig.Approvals[:1]
	plan.Binding.PeerAddress = "fd00::2/128"
	if validateNetworkPlan(plan, "friend") == nil {
		t.Fatal("accepted mismatched displayed route")
	}
}

func TestNetworkApprovalShowsOnlyActionableAccess(t *testing.T) {
	plan := networkPlan{}
	plan.Network = "staging-vpc-mac"
	plan.Binding.Peer = "85fc4c10068b0c1a4b267d1b2a429300a512f1507ada41ea7d5b6149f44f40aa"
	plan.Binding.Address = "fd2a:8117:ef61:b207:a145:c42:1a5:e593/128"
	plan.Binding.PeerAddress = "fdda:8ac3:e1a:5682:7cd:d3ce:afff:3acb/128"
	plan.Binding.Interface = "utun6"
	plan.Binding.Routes = []string{"fd20:0:27::/48"}
	plan.Binding.Outbound = []networkRule{{Protocol: "tcp", Ports: []uint16{8080}}, {Protocol: "udp", Ports: []uint16{5353}}, {Protocol: "icmp_echo"}}
	var output bytes.Buffer
	writeNetworkApproval(&output, plan, "connect-subnet-lab-router")
	want := "Connect IP: staging-vpc-mac\nPeer: connect-subnet-lab-router\nRoute via peer: fd20:0:27::/48\nTraffic to peer: TCP 8080, UDP 5353, ping\n"
	if output.String() != want {
		t.Fatalf("approval output:\n%s\nwant:\n%s", output.String(), want)
	}
	for _, hidden := range []string{plan.Binding.Peer, plan.Binding.Address, plan.Binding.PeerAddress, plan.Binding.Interface} {
		if strings.Contains(output.String(), hidden) {
			t.Errorf("approval output unexpectedly contains %q", hidden)
		}
	}
}

func TestManagedGatewayApprovalExplainsRouteAndFirewallBoundary(t *testing.T) {
	plan := networkPlan{Network: "staging-vpc", ManagedGateway: true}
	plan.Binding.Peer = "85fc4c10068b0c1a4b267d1b2a429300a512f1507ada41ea7d5b6149f44f40aa"
	plan.Binding.Routes = []string{"fd20:0:27::/48"}
	var output bytes.Buffer
	writeNetworkApproval(&output, plan, "")
	for _, want := range []string{"Routes through VPC gateway: fd20:0:27::/48", "VPC firewall rules still control access"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("approval output %q does not contain %q", output.String(), want)
		}
	}
	if strings.Contains(output.String(), "Traffic to peer: deny all") {
		t.Fatalf("managed VPC route was misleadingly described as denied: %s", output.String())
	}
}

func TestDoctorDisplaysSavedInactiveAttachments(t *testing.T) {
	cmd := &cobra.Command{Use: "doctor"}
	var output bytes.Buffer
	cmd.SetOut(&output)
	if err := writeHuman(cmd, json.RawMessage(`{"project":"demo","networking":{"state":"approval_required","saved_attachments":[{"network":"friend"}]}}`)); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"approval required", "connect join friend", "Read-only checks"} {
		if !strings.Contains(output.String(), text) {
			t.Fatalf("missing %q in %s", text, output.String())
		}
	}
}

func TestRouterJoinDoesNotClaimForwardingIsConfigured(t *testing.T) {
	cmd := &cobra.Command{Use: "join"}
	var output bytes.Buffer
	cmd.SetOut(&output)
	if err := writeHuman(cmd, json.RawMessage(`{"network":"vpc","mode":"peer","running":true,"connected":true,"routes":["fd00::2/128"],"advertise_routes":["fd20::/64"]}`)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Shared with peer: fd20::/64"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q in %s", want, output.String())
		}
	}
}
