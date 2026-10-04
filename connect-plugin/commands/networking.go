package commands

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	connectapi "go.datum.net/datumctl-plugins/connect/internal/api"
	"go.datum.net/datumctl-plugins/connect/internal/daemonservice"
)

var ensureNetworking = daemonservice.EnsureNetworking

type networkPlan struct {
	Network        string                        `json:"network"`
	ManagedGateway bool                          `json:"managed_gateway"`
	HelperConfig   daemonservice.HelperApprovals `json:"helper_config"`
	Binding        struct {
		Peer            string        `json:"peer"`
		Address         string        `json:"assigned_address"`
		PeerAddress     string        `json:"peer_address"`
		Interface       string        `json:"interface_name"`
		MTU             uint16        `json:"mtu"`
		Inbound         []networkRule `json:"allow_inbound"`
		Outbound        []networkRule `json:"allow_outbound"`
		Routes          []string      `json:"routes"`
		AdvertiseRoutes []string      `json:"advertise_routes"`
	} `json:"binding"`
}

const defaultJoinRequestTimeout = 4 * time.Minute

// A managed ConnectNetworkBinding can take up to 90 seconds to reconcile.
// Keep the ordinary commands snappy, but don't let the global 30-second
// default make a fresh join appear to fail while the controller is still
// approving it. An explicitly supplied --timeout remains authoritative.
func joinRequestTimeout(cmd *cobra.Command, opts *options) time.Duration {
	if timeoutFlag := cmd.Root().PersistentFlags().Lookup("timeout"); timeoutFlag != nil && timeoutFlag.Changed {
		return opts.timeout
	}
	if opts.timeout < defaultJoinRequestTimeout {
		return defaultJoinRequestTimeout
	}
	return opts.timeout
}

type networkRule struct {
	Protocol string   `json:"protocol"`
	Ports    []uint16 `json:"ports,omitempty"`
}

func formatNetworkRules(rules []networkRule) string {
	var text []string
	for _, rule := range rules {
		if rule.Protocol == "icmp_echo" {
			text = append(text, "ping")
			continue
		}
		var ports []string
		for _, port := range rule.Ports {
			ports = append(ports, strconv.Itoa(int(port)))
		}
		text = append(text, strings.ToUpper(rule.Protocol)+" "+strings.Join(ports, ","))
	}
	if len(text) == 0 {
		return "deny all"
	}
	return strings.Join(text, ", ")
}

func displayPeer(peer string) string {
	peer = strings.TrimSpace(peer)
	if peer == "" {
		return ""
	}
	if len(peer) > 24 && len(peer)%2 == 0 {
		if _, err := hex.DecodeString(peer); err == nil {
			return peer[:12] + "…" + peer[len(peer)-6:]
		}
	}
	return peer
}

func writeNetworkApproval(out io.Writer, plan networkPlan, peer string) {
	fmt.Fprintf(out, "Connect IP: %s\n", plan.Network)
	peerLabel := displayPeer(peer)
	if peerLabel == "" {
		peerLabel = displayPeer(plan.Binding.Peer)
	}
	if peerLabel != "" {
		fmt.Fprintf(out, "Peer: %s\n", peerLabel)
	}
	if plan.ManagedGateway {
		if len(plan.Binding.Routes) > 0 {
			fmt.Fprintf(out, "Routes through VPC gateway: %s\n", strings.Join(plan.Binding.Routes, ", "))
		}
		fmt.Fprintln(out, "This approves the local interface and these routes. VPC firewall rules still control access to workloads.")
		return
	}
	if len(plan.Binding.Routes) > 0 {
		fmt.Fprintf(out, "Route via peer: %s\n", strings.Join(plan.Binding.Routes, ", "))
		fmt.Fprintf(out, "Traffic to peer: %s\n", formatNetworkRules(plan.Binding.Outbound))
	}
	if len(plan.Binding.AdvertiseRoutes) > 0 {
		fmt.Fprintf(out, "Route shared with peer: %s\n", strings.Join(plan.Binding.AdvertiseRoutes, ", "))
		fmt.Fprintf(out, "Traffic from peer: %s\n", formatNetworkRules(plan.Binding.Inbound))
		fmt.Fprintln(out, "Forwarding must already be configured on this device.")
	}
	if len(plan.Binding.Routes) == 0 && len(plan.Binding.AdvertiseRoutes) == 0 {
		fmt.Fprintf(out, "Traffic to peer: %s\n", formatNetworkRules(plan.Binding.Outbound))
	}
}

func waitForPeer(ctx context.Context, client *connectapi.Client, project, network string, timeout time.Duration) (json.RawMessage, bool, error) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		data, err := client.Request(ctx, http.MethodGet, "/v1/status", project, nil)
		if err != nil {
			return nil, false, err
		}
		var status struct {
			Networks []json.RawMessage `json:"networks"`
		}
		if err := json.Unmarshal(data, &status); err != nil {
			return nil, false, err
		}
		for _, attachment := range status.Networks {
			var value networkDisplay
			if err := json.Unmarshal(attachment, &value); err != nil {
				return nil, false, err
			}
			if value.Network == network {
				if value.Connected != nil && *value.Connected {
					return attachment, true, nil
				}
				break
			}
		}
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-deadline.C:
			return nil, false, nil
		case <-ticker.C:
		}
	}
}

func validateNetworkPlan(plan networkPlan, network string) error {
	if plan.Network != network || len(plan.HelperConfig.Approvals) != 1 {
		return fmt.Errorf("daemon returned an ambiguous networking approval plan")
	}
	approval := plan.HelperConfig.Approvals[0]
	if approval.InterfaceName != plan.Binding.Interface || approval.AssignedAddress != plan.Binding.Address || approval.PeerAddress != plan.Binding.PeerAddress || approval.MTU != plan.Binding.MTU || !slices.Equal(approval.Routes, plan.Binding.Routes) || !slices.Equal(approval.AdvertiseRoutes, plan.Binding.AdvertiseRoutes) {
		return fmt.Errorf("daemon approval differs from displayed attachment; nothing was elevated")
	}
	return nil
}

func shouldWaitForJoin(wait, noWait bool, network networkDisplay) bool {
	if noWait {
		return false
	}
	// Routed attachments are useful only after their peer session is live. Wait
	// by default so a following curl does not race the tunnel handshake.
	return wait || (network.Mode == "peer" && hasSubnetRoutes(network))
}

func hasSubnetRoutes(network networkDisplay) bool {
	for _, route := range network.Routes {
		if route != network.PeerAddress {
			return true
		}
	}
	return false
}

func newJoin(opts *options) *cobra.Command {
	var peer, executable string
	var tcp, udp []string
	var routes, advertise []string
	var ping, upgrade, wait, noWait bool
	var waitTimeout time.Duration
	cmd := &cobra.Command{Use: "join NETWORK", Short: "Join a VPC gateway or direct Connector", Long: "Join the ready ConnectGateway configured for NETWORK. Connect creates or reuses this device's ConnectNetworkBinding, then asks for Administrator approval before installing the local interface and approved routes.\n\nIf no managed gateway exists, pass --peer and explicit traffic permissions\nfor direct Connector setup. Both peers use the same network name and approve\neach other. Routed direct attachments wait for the peer by default.\n\nLocal attachments disappear on daemon restart; run an explicit rejoin to\nreattach. The project binding remains. Scripts never prompt or elevate.", Example: "  datumctl connect join staging-vpc\n  datumctl connect join friend --peer laptop --allow-tcp 22", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if wait && noWait {
			return fmt.Errorf("choose either --wait or --no-wait")
		}
		if peer == "" && (len(tcp) > 0 || len(udp) > 0 || ping || len(routes) > 0 || len(advertise) > 0) {
			return fmt.Errorf("traffic flags require --peer on first-time setup; saved permissions are not silently changed")
		}
		if len(routes) > 0 && len(advertise) > 0 {
			return fmt.Errorf("choose --routes on the client or --advertise-routes on the router, not both")
		}
		for _, route := range append(append([]string{}, routes...), advertise...) {
			prefix, err := netip.ParsePrefix(route)
			if err != nil || !prefix.Addr().Is6() || prefix.Addr().Is4In6() || prefix.Bits() < 16 || prefix != prefix.Masked() {
				return fmt.Errorf("guided subnet setup requires canonical IPv6 prefixes of /16 or narrower; invalid route %q", route)
			}
		}
		rules := []networkRule{}
		for _, item := range []struct {
			protocol string
			ports    []string
		}{{"tcp", tcp}, {"udp", udp}} {
			if len(item.ports) == 0 {
				continue
			}
			rule := networkRule{Protocol: item.protocol}
			for _, value := range item.ports {
				port, err := parsePort(value)
				if err != nil {
					return err
				}
				rule.Ports = append(rule.Ports, port)
			}
			rules = append(rules, rule)
		}
		if ping {
			rules = append(rules, networkRule{Protocol: "icmp_echo"})
		}
		if peer != "" && len(rules) == 0 {
			return fmt.Errorf("choose permitted traffic with --allow-tcp PORT, --allow-udp PORT, or --allow-ping; IP access is not granted implicitly")
		}
		if handled, err := prepareServe(cmd, opts); handled || err != nil {
			return err
		}
		project, err := project(cmd)
		if err != nil {
			return err
		}
		joinOpts := *opts
		joinOpts.timeout = joinRequestTimeout(cmd, opts)
		client, err := joinOpts.client(cmd, true)
		if err != nil {
			return err
		}
		if peer != "" {
			inbound, outbound := rules, rules
			if len(routes) > 0 {
				inbound = []networkRule{}
			}
			if len(advertise) > 0 {
				outbound = []networkRule{}
			}
			body := map[string]any{"network": args[0], "peer": peer, "allow_inbound": inbound, "allow_outbound": outbound}
			if len(routes) > 0 {
				body["routes"] = routes
			}
			if len(advertise) > 0 {
				body["advertise_routes"] = advertise
			}
			_, err = client.Request(cmd.Context(), http.MethodPost, "/v1/networks/prepare", project, body)
			if err != nil {
				return friendlyError(cmd, opts, project, err)
			}
		}
		join := func() (json.RawMessage, error) {
			return client.Request(cmd.Context(), http.MethodPost, "/v1/networks", project, map[string]string{"network": args[0]})
		}
		var result json.RawMessage
		if !upgrade {
			result, err = join()
		}
		var apiError *connectapi.HTTPError
		needsSetup := errors.As(err, &apiError) && apiError.Code == "network_setup_required"
		if upgrade || needsSetup {
			if !guidedSetupEnabled(cmd, opts) {
				return fmt.Errorf("networking needs local administrator approval. Run this join interactively on the daemon's device; scripts and remote API clients never elevate")
			}
			data, planErr := client.Request(cmd.Context(), http.MethodPost, "/v1/networks/"+url.PathEscape(args[0])+"/setup", project, nil)
			if planErr != nil {
				return friendlyError(cmd, opts, project, planErr)
			}
			var plan networkPlan
			if err := json.Unmarshal(data, &plan); err != nil {
				return err
			}
			if err := validateNetworkPlan(plan, args[0]); err != nil {
				return err
			}
			writeNetworkApproval(cmd.ErrOrStderr(), plan, peer)
			question := "Install the privileged helper and approve this access?"
			if upgrade {
				question = "Upgrade the helper? Active IP attachments will disconnect; services and local ports stay running."
			}
			if err := confirmSetup(cmd, question); err != nil {
				return err
			}
			if err := ensureNetworking(cmd, cmd.Root().Version, executable, plan.HelperConfig, upgrade); err != nil {
				return err
			}
			// launchd/systemd acknowledging Start is not yet helper readiness.
			for attempt := 0; attempt < 30; attempt++ {
				result, err = join()
				if err == nil || !errors.As(err, &apiError) || apiError.Code != "network_setup_required" {
					break
				}
				select {
				case <-cmd.Context().Done():
					return cmd.Context().Err()
				case <-time.After(100 * time.Millisecond):
				}
			}
		}
		if err != nil {
			return friendlyError(cmd, opts, project, err)
		}
		if waitTimeout > 0 {
			var joined networkDisplay
			if json.Unmarshal(result, &joined) == nil && shouldWaitForJoin(wait, noWait, joined) && joined.Mode == "peer" && (joined.Connected == nil || !*joined.Connected) {
				if hasSubnetRoutes(joined) {
					fmt.Fprintf(cmd.ErrOrStderr(), "Waiting for the VPC connection to become ready (up to %s; Ctrl+C stops waiting, not the attachment)…\n", waitTimeout)
				} else {
					fmt.Fprintf(cmd.ErrOrStderr(), "Waiting for the peer to connect (up to %s; Ctrl+C stops waiting, not the attachment)…\n", waitTimeout)
				}
				connected, ok, waitErr := waitForPeer(cmd.Context(), client, project, args[0], waitTimeout)
				if waitErr != nil {
					return waitErr
				}
				if ok {
					result = connected
				} else {
					return fmt.Errorf("network %q is still waiting for its peer after %s; the attachment remains active. Retry `datumctl connect join %s` when the peer is available, or use `datumctl connect status` to inspect it", args[0], waitTimeout, args[0])
				}
			}
		}
		return writeJSON(cmd, result)
	}}
	cmd.Flags().StringVar(&peer, "peer", "", "Connector name or public key for first-time direct IP setup")
	cmd.Flags().StringSliceVar(&routes, "routes", nil, "Approved IPv6 destinations reached through this peer (client role)")
	cmd.Flags().StringSliceVar(&advertise, "advertise-routes", nil, "Approved IPv6 destinations forwarded for this peer (router role; forwarding/NAT configured separately)")
	cmd.Flags().StringSliceVar(&tcp, "allow-tcp", nil, "Approved destination TCP ports (subnet mode: client to subnet; host mode: both directions)")
	cmd.Flags().StringSliceVar(&udp, "allow-udp", nil, "Approved destination UDP ports (subnet mode: client to subnet; host mode: both directions)")
	cmd.Flags().BoolVar(&ping, "allow-ping", false, "Permit ping (subnet mode: client to subnet; host mode: both directions)")
	cmd.Flags().StringVar(&executable, "helper-executable", "", "Explicit local helper build instead of downloading this plugin's release")
	cmd.Flags().BoolVar(&upgrade, "upgrade-helper", false, "Approve matching-helper upgrade; active IP attachments disconnect")
	cmd.Flags().BoolVar(&wait, "wait", false, "Wait for the peer to connect after joining")
	cmd.Flags().BoolVar(&noWait, "no-wait", false, "Return immediately even if a routed peer is not connected yet")
	cmd.Flags().DurationVar(&waitTimeout, "wait-timeout", 5*time.Minute, "Maximum time to wait with --wait (for example 30s or 5m)")
	return cmd
}

func newDoctor(opts *options) *cobra.Command {
	return &cobra.Command{Use: "doctor", Short: "Check daemon and networking-helper health without changing anything", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		project, err := project(cmd)
		if err != nil {
			return err
		}
		return runRequest(cmd, opts, true, http.MethodGet, "/v1/status", project, nil)
	}}
}
