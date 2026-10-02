package commands

import (
	"encoding/json"
	"errors"
	"fmt"
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
	Network      string                        `json:"network"`
	HelperConfig daemonservice.HelperApprovals `json:"helper_config"`
	Binding      struct {
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
	return strings.Join(text, "; ")
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

func newJoin(opts *options) *cobra.Command {
	var peer, executable string
	var tcp, udp []string
	var routes, advertise []string
	var ping, upgrade bool
	cmd := &cobra.Command{Use: "join NETWORK", Short: "Join an IP attachment; guide peer or subnet setup on first use", Long: "Join a saved IP attachment. For first-time peer setup, pass --peer\nand explicit traffic permissions. Both devices use the same network name\nand approve each other. Connect generates matching IPv6 host addresses.\nAdministrator approval enables only the displayed routes; your daemon keeps\nyour ordinary login. No cloud VPC membership is created.\n\nFor IPv6 subnet access, the client uses --routes and the router uses\n--advertise-routes with exactly matching prefixes. Traffic flags allow only\nclient-initiated traffic to those destinations, plus tracked replies.\nThe router operator separately configures forwarding, firewall, and source NAT\nor return routes. Connect does not change global forwarding or NAT settings.\nWithout route flags, permissions apply in both directions between peer hosts.\nSaved configuration survives restart; active attachments require explicit rejoin.\nScripts never prompt or elevate. Existing operator-managed IP configurations still work.", Example: "  datumctl connect join friend --peer susquehanna --allow-tcp 8080 --allow-ping\n  datumctl connect join vpc --peer router --routes fd20:1::/64 --allow-tcp 22\n  datumctl connect join vpc --peer laptop --advertise-routes fd20:1::/64 --allow-tcp 22\n  datumctl connect join friend", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
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
		client, err := opts.client(cmd, true)
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
			data, planErr := client.Request(cmd.Context(), http.MethodGet, "/v1/networks/"+url.PathEscape(args[0])+"/setup", project, nil)
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
			fmt.Fprintf(cmd.ErrOrStderr(), "IP attachment %q\n  Peer key: %s\n  This device: %s\n  Peer: %s\n", plan.Network, plan.Binding.Peer, plan.Binding.Address, plan.Binding.PeerAddress)
			fmt.Fprintf(cmd.ErrOrStderr(), "  Inbound: %s\n  Outbound: %s\n", formatNetworkRules(plan.Binding.Inbound), formatNetworkRules(plan.Binding.Outbound))
			if len(plan.Binding.Routes) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "  Routes through peer: %s\n", strings.Join(plan.Binding.Routes, ", "))
			}
			if len(plan.Binding.AdvertiseRoutes) > 0 {
				fmt.Fprintf(cmd.ErrOrStderr(), "  Forward for peer: %s\n  Configure forwarding, firewall, and a return path on this router separately.\n", strings.Join(plan.Binding.AdvertiseRoutes, ", "))
			}
			question := "Approve a privileged networking helper for these exact routes? Your daemon and login stay unprivileged."
			if upgrade {
				question = "Upgrade the networking helper? Active IP attachments will disconnect and need rejoining; TCP/UDP serve and dial stay running."
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
