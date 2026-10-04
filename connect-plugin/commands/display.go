package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type serviceDisplay struct {
	Connector      string   `json:"connector"`
	ID             string   `json:"id"`
	Endpoint       string   `json:"endpoint"`
	Protocol       string   `json:"protocol"`
	Public         bool     `json:"public"`
	Allow          []string `json:"allow"`
	DesiredActive  bool     `json:"desired_active"`
	Running        bool     `json:"running"`
	Ready          bool     `json:"ready"`
	Hostnames      []string `json:"hostnames"`
	LastError      string   `json:"last_error"`
	LastErrorStage string   `json:"last_error_stage"`
}

type dialDisplay struct {
	Connector      string  `json:"connector"`
	ConnectorName  string  `json:"connector_name"`
	Port           uint16  `json:"port"`
	Bind           uint16  `json:"bind"`
	LocalPort      *uint16 `json:"local_port"`
	Protocol       string  `json:"protocol"`
	DesiredActive  bool    `json:"desired_active"`
	Running        bool    `json:"running"`
	LastError      string  `json:"last_error"`
	LastErrorStage string  `json:"last_error_stage"`
}

type networkDisplay struct {
	Network                    string   `json:"network"`
	Mode                       string   `json:"mode"`
	Peer                       string   `json:"peer"`
	PeerAddress                string   `json:"peer_address"`
	Connected                  bool     `json:"connected"`
	State                      string   `json:"state"`
	Address                    string   `json:"assigned_address"`
	Interface                  string   `json:"interface_name"`
	Routes                     []string `json:"routes"`
	AdvertiseRoutes            []string `json:"advertise_routes"`
	Running                    bool     `json:"running"`
	LastError                  string   `json:"last_error"`
	LastConnectError           string   `json:"last_connect_error"`
	ACLDrops                   uint64   `json:"acl_drops"`
	DeliveryMode               string   `json:"delivery_mode"`
	DatagramCapacity           uint64   `json:"effective_datagram_ip_capacity"`
	MTUErrors                  uint64   `json:"mtu_errors"`
	LastTransportError         string   `json:"last_transport_error"`
	LocalTunToTransportPackets uint64   `json:"local_tun_to_transport_packets"`
	TransportToLocalTunPackets uint64   `json:"transport_to_local_tun_packets"`
	LastPacketSentAtUnixMS     *uint64  `json:"last_packet_sent_at_unix_ms"`
	LastPacketReceivedAtUnixMS *uint64  `json:"last_packet_received_at_unix_ms"`
}

// writeHuman renders the daemon's observed state, never assuming that saved
// intent or a listening port proves that a public URL or remote origin works.
func writeHuman(cmd *cobra.Command, data json.RawMessage) error {
	w := cmd.OutOrStdout()
	var out strings.Builder
	switch cmd.Name() {
	case "health":
		var value struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		if value.Status == "ok" {
			out.WriteString("Connect daemon is reachable.\n")
		} else {
			fmt.Fprintf(&out, "Connect daemon health: %s\n", value.Status)
		}
	case "status", "up", "down", "doctor":
		var value struct {
			Project              string `json:"project"`
			DesiredUp            bool   `json:"desired_up"`
			Running              bool   `json:"running"`
			Enrolled             bool   `json:"enrolled"`
			CredentialConfigured bool   `json:"credential_configured"`
			Authentication       *struct {
				Kind    string `json:"kind"`
				Session string `json:"session"`
			} `json:"authentication"`
			Connector *struct {
				Name      string `json:"name"`
				PublicKey string `json:"public_key"`
			} `json:"connector"`
			Services   []serviceDisplay `json:"services"`
			Dials      []dialDisplay    `json:"dials"`
			Networks   []networkDisplay `json:"networks"`
			Networking *struct {
				State     string `json:"state"`
				LastError string `json:"last_error"`
				Saved     []struct {
					Network string `json:"network"`
				} `json:"saved_attachments"`
			} `json:"networking"`
			LastError      string `json:"last_error"`
			LastErrorStage string `json:"last_error_stage"`
		}
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		switch {
		case value.LastError != "":
			fmt.Fprintf(&out, "Connect needs attention in project %q.\n", value.Project)
		case value.Running:
			fmt.Fprintf(&out, "Connected to project %q.\n", value.Project)
		case !value.CredentialConfigured:
			fmt.Fprintf(&out, "Connect is not configured for project %q.\n", value.Project)
		case value.DesiredUp:
			fmt.Fprintf(&out, "Connecting to project %q.\n", value.Project)
		default:
			fmt.Fprintf(&out, "Disconnected from project %q.\n", value.Project)
		}
		writeFailure(&out, value.LastErrorStage, value.LastError)
		if value.Authentication != nil {
			switch value.Authentication.Kind {
			case "oidc":
				fmt.Fprintf(&out, "Authentication: datumctl session %s (user permissions)\n", value.Authentication.Session)
			case "credential_file":
				out.WriteString("Authentication: credential file\n")
			}
		}
		if value.Connector != nil {
			fmt.Fprintf(&out, "Connector: %s\n", value.Connector.Name)
		}
		shownNetworks := make(map[string]bool)
		if value.Networking != nil && value.Networking.State != "not_required" {
			fmt.Fprintf(&out, "IP networking helper: %s\n", strings.ReplaceAll(value.Networking.State, "_", " "))
			if value.Networking.LastError != "" {
				fmt.Fprintf(&out, "  %s\n", value.Networking.LastError)
			}
			for _, saved := range value.Networking.Saved {
				shownNetworks[saved.Network] = true
				active := false
				for _, network := range value.Networks {
					if network.Network == saved.Network && network.Running {
						active = true
					}
				}
				if !active {
					fmt.Fprintf(&out, "  Saved attachment %s: inactive. Join: datumctl connect join %s%s\n", saved.Network, shellArg(saved.Network), displayProjectFlag(cmd))
				}
			}
		}
		for _, network := range value.Networks {
			if network.Mode == "gateway" && !network.Running && network.Network != "" && !shownNetworks[network.Network] {
				fmt.Fprintf(&out, "Saved VPC attachment %s: inactive. Join: datumctl connect join %s%s\n", network.Network, shellArg(network.Network), displayProjectFlag(cmd))
				if network.LastError != "" {
					writeFailure(&out, "network", network.LastError)
				}
			}
		}
		if cmd.Name() == "doctor" {
			out.WriteString("Read-only checks; no interface, service, or route was changed. Helper readiness does not prove peer reachability.\n")
		}
		if !value.CredentialConfigured {
			fmt.Fprintf(&out, "\nNext: %s\n", setupCommand(value.Project))
			out.WriteString("Sign in with datumctl login first. Connect uses your user permissions; unattended servers can use --credentials-file PATH.\n")
		} else if !value.DesiredUp && value.LastError == "" {
			fmt.Fprintf(&out, "Resume: %s\n", setupCommand(value.Project))
		}
		if len(value.Services) > 0 {
			out.WriteString("\nServices\n")
			table := tabwriter.NewWriter(&out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(table, "NAME\tENDPOINT\tPROTOCOL\tACCESS\tSTATE")
			for _, s := range value.Services {
				state := serviceState(s)
				if !value.DesiredUp && s.DesiredActive && s.LastError == "" {
					state = "paused (project down)"
				}
				fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n", s.ID, s.Endpoint, strings.ToUpper(s.Protocol), serviceAccess(s), state)
			}
			_ = table.Flush()
			for _, s := range value.Services {
				if len(s.Hostnames) > 0 {
					fmt.Fprintf(&out, "  %s hostnames: %s\n", s.ID, strings.Join(s.Hostnames, ", "))
				}
				if s.LastError != "" {
					fmt.Fprintf(&out, "  %s: ", s.ID)
					writeFailure(&out, s.LastErrorStage, s.LastError)
					fmt.Fprintf(&out, "  Remove saved service: datumctl connect unserve %s --project %q\n", s.ID, value.Project)
				}
			}
		}
		if len(value.Dials) > 0 {
			out.WriteString("\nLocal ports\n")
			table := tabwriter.NewWriter(&out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(table, "LOCAL\tDESTINATION\tPROTOCOL\tSTATE")
			for _, d := range value.Dials {
				state := dialState(d)
				if !value.DesiredUp && d.DesiredActive && d.LastError == "" {
					state = "paused (project down)"
				}
				fmt.Fprintf(table, "%s\t%s:%d\t%s\t%s\n", dialAddress(d), dialPeerName(d), d.Port, strings.ToUpper(d.Protocol), state)
			}
			_ = table.Flush()
			for _, d := range value.Dials {
				if d.LastError != "" {
					fmt.Fprintf(&out, "  %s: ", dialAddress(d))
					writeFailure(&out, d.LastErrorStage, d.LastError)
					fmt.Fprintf(&out, "  Remove saved local port: datumctl connect hangup %d --project %q\n", d.Bind, value.Project)
				}
			}
		}
		for _, network := range value.Networks {
			state := "disconnected"
			if network.Running && (network.Mode != "peer" || network.Connected) {
				state = "connected"
			} else if network.Running && network.Mode == "peer" {
				state = "waiting for peer"
			}
			fmt.Fprintf(&out, "Network %s: %s, %s on %s (ephemeral native preview).\n", network.Network, state, network.Address, network.Interface)
			fmt.Fprintf(&out, "  Routes: %s\n", strings.Join(network.Routes, ", "))
			if len(network.AdvertiseRoutes) > 0 {
				fmt.Fprintf(&out, "  Approved subnet access for peer: %s\n  Forwarding, firewall, and return routing are managed separately on this device.\n", strings.Join(network.AdvertiseRoutes, ", "))
			}
			if network.Mode == "peer" {
				fmt.Fprintf(&out, "  Peer: %s (%s)\n", network.Peer, network.PeerAddress)
				if network.Running && !network.Connected {
					fmt.Fprintf(&out, "  The local attachment is ready, but peer traffic is not connected. Run datumctl connect join %s on the other device using its configured project. Both devices need matching peer approvals.\n", network.Network)
				}
				if network.LastConnectError != "" {
					fmt.Fprintf(&out, "  Last connection attempt: %s\n", network.LastConnectError)
				}
				if network.ACLDrops > 0 {
					fmt.Fprintf(&out, "  Packet policy dropped %d packets. JSON status includes denial reasons; drops do not necessarily indicate a connection failure.\n", network.ACLDrops)
				}
			}
			if network.DeliveryMode != "" {
				fmt.Fprintf(&out, "  Transport: %s; IP datagram capacity: %d bytes; MTU errors: %d\n", network.DeliveryMode, network.DatagramCapacity, network.MTUErrors)
			}
			if cmd.Name() == "status" && network.Mode == "gateway" && network.DeliveryMode != "" {
				fmt.Fprintf(&out, "  Packets: to gateway %d (last %s); from gateway %d (last %s)\n",
					network.LocalTunToTransportPackets, packetAge(network.LastPacketSentAtUnixMS),
					network.TransportToLocalTunPackets, packetAge(network.LastPacketReceivedAtUnixMS))
			}
			failure := network.LastError
			if network.LastTransportError != "" {
				failure = network.LastTransportError
			}
			writeFailure(&out, "connect_ip", failure)
		}
		if value.Running && len(value.Services) == 0 && len(value.Dials) == 0 && len(value.Networks) == 0 {
			out.WriteString("No services or local ports configured.\n")
		}
		if cmd.Name() == "status" {
			fmt.Fprintf(&out, "\nFor transport diagnostics: datumctl connect status --project %q --output json\n", value.Project)
		}
	case "serve":
		var s serviceDisplay
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		project, _ := cmd.Flags().GetString("project")
		projectFlag := ""
		if project != "" {
			projectFlag = " --project " + shellArg(project)
		}
		if serviceState(s) == "active" {
			fmt.Fprintf(&out, "Sharing %s (%s) in the background.\n", s.Endpoint, strings.ToUpper(s.Protocol))
		} else {
			fmt.Fprintf(&out, "%s (%s): %s.\n", s.Endpoint, strings.ToUpper(s.Protocol), serviceState(s))
		}
		if s.Public {
			if s.Ready {
				out.WriteString("Access: public.\n")
			} else {
				out.WriteString("Public access is pending gateway readiness; no public URL is confirmed yet.\n")
			}
			if len(s.Hostnames) > 0 {
				fmt.Fprintf(&out, "Hostnames: %s\n", strings.Join(s.Hostnames, ", "))
			}
		} else if len(s.Allow) > 0 {
			if len(s.Allow) == 1 {
				out.WriteString("Access: only the device you allowed.\n")
			} else {
				fmt.Fprintf(&out, "Access: only the %d devices you allowed.\n", len(s.Allow))
			}
		} else if project != "" {
			fmt.Fprintf(&out, "Access: devices in project %q only.\n", project)
		} else {
			out.WriteString("Access: project devices only.\n")
		}
		writeFailure(&out, s.LastErrorStage, s.LastError)
		if !s.Public && serviceState(s) == "active" && s.Connector != "" {
			if _, port, err := net.SplitHostPort(s.Endpoint); err == nil {
				protocol := ""
				if s.Protocol == "udp" {
					protocol = " --protocol udp"
				}
				localPort := suggestedLocalPort(port)
				fmt.Fprintf(&out, "\nOn the other device (skip up if already connected):\n  datumctl connect up%s\n  datumctl connect dial %s --bind %s%s%s\n", projectFlag, shellArg(s.Connector+":"+port), localPort, protocol, projectFlag)
				fmt.Fprintf(&out, "\nConnect your app to 127.0.0.1:%s on that device.\nTraffic forwards through this device to %s.\n", localPort, s.Endpoint)
			}
		}
		selector := s.Endpoint
		if selector == "" {
			selector = s.ID
		}
		fmt.Fprintf(&out, "\nStop sharing:\n  datumctl connect unserve %s%s\n", shellArg(selector), projectFlag)
	case "dial":
		var d dialDisplay
		if err := json.Unmarshal(data, &d); err != nil {
			return err
		}
		fmt.Fprintf(&out, "%s: %s -> %s:%d (%s).\n", strings.Title(dialState(d)), dialAddress(d), dialPeerName(d), d.Port, strings.ToUpper(d.Protocol))
		if d.Running {
			out.WriteString("Applications can use this local port; each new connection still depends on the remote service.\n")
		}
		writeFailure(&out, d.LastErrorStage, d.LastError)
		port := d.Bind
		if d.LocalPort != nil {
			port = *d.LocalPort
		}
		fmt.Fprintf(&out, "Close: datumctl connect hangup %d%s\n", port, displayProjectFlag(cmd))
	case "unserve":
		var value struct {
			Deleted bool   `json:"deleted"`
			ID      string `json:"id"`
		}
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		if !value.Deleted {
			return fmt.Errorf("daemon did not confirm service removal")
		}
		fmt.Fprintf(&out, "Stopped exposing service %s.\n", value.ID)
	case "hangup":
		var value struct {
			Deleted bool   `json:"deleted"`
			Port    uint16 `json:"port"`
		}
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		if !value.Deleted {
			return fmt.Errorf("daemon did not confirm local port removal")
		}
		if value.Port == 0 {
			out.WriteString("Removed saved automatic-port dial.\n")
		} else {
			fmt.Fprintf(&out, "Closed local port %d.\n", value.Port)
		}
	case "join":
		var network networkDisplay
		if err := json.Unmarshal(data, &network); err != nil {
			return err
		}
		if !network.Running {
			return fmt.Errorf("network attachment is not running; inspect datumctl connect status%s", displayProjectFlag(cmd))
		}
		if network.Mode == "peer" && !network.Connected {
			if hasSubnetRoutes(network) {
				fmt.Fprintf(&out, "Waiting for the VPC connection to become ready for %s.\n", network.Network)
			} else {
				fmt.Fprintf(&out, "Waiting for the other device to join %s.\n", network.Network)
				fmt.Fprintf(&out, "On the other device: datumctl connect join %s%s\n", shellArg(network.Network), displayProjectFlag(cmd))
			}
			if network.LastConnectError != "" {
				fmt.Fprintf(&out, "Connection issue: %s\n", network.LastConnectError)
			}
		} else {
			fmt.Fprintf(&out, "Connected to %s.\n", network.Network)
		}
		if len(network.Routes) > 0 {
			fmt.Fprintf(&out, "Route: %s\n", strings.Join(network.Routes, ", "))
		}
		if len(network.AdvertiseRoutes) > 0 {
			fmt.Fprintf(&out, "Shared with peer: %s\n", strings.Join(network.AdvertiseRoutes, ", "))
		}
		fmt.Fprintf(&out, "Leave: datumctl connect leave %s%s\n", shellArg(network.Network), displayProjectFlag(cmd))
	case "leave":
		var value struct {
			Network string `json:"network"`
			Left    bool   `json:"left"`
		}
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		if !value.Left {
			return fmt.Errorf("daemon did not confirm network removal")
		}
		fmt.Fprintf(&out, "Left %s; local attachment removed.\n", value.Network)
	case "ping":
		var value struct {
			Address string `json:"address"`
			Latency uint64 `json:"latency_ms"`
		}
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		fmt.Fprintf(&out, "Connector %s is reachable (%d ms).\n", value.Address, value.Latency)
	default:
		return fmt.Errorf("human output is not available for %s; use --output json or --output yaml", cmd.Name())
	}
	_, err := io.WriteString(w, out.String())
	return err
}

func packetAge(timestamp *uint64) string {
	if timestamp == nil || *timestamp == 0 {
		return "never"
	}
	age := time.Since(time.UnixMilli(int64(*timestamp)))
	if age < 0 {
		return "clock skew"
	}
	if age < time.Second {
		return "just now"
	}
	return fmt.Sprintf("%s ago", age.Truncate(time.Second))
}

// Suggest an unprivileged port on the other device, not an allocated local port.
// The peer can change --bind if this port is already in use.
func suggestedLocalPort(remote string) string {
	switch remote {
	case "22":
		return "2222"
	case "80":
		return "8080"
	case "443":
		return "8443"
	}
	port, err := strconv.ParseUint(remote, 10, 16)
	if err == nil && port < 1024 {
		return strconv.Itoa(10000 + int(port))
	}
	return remote
}

func displayProjectFlag(cmd *cobra.Command) string {
	project, _ := cmd.Flags().GetString("project")
	if project == "" {
		return ""
	}
	return fmt.Sprintf(" --project %q", project)
}

func writeFailure(w io.Writer, stage, failure string) {
	if failure == "" {
		return
	}
	if stage == "" {
		fmt.Fprintf(w, "Last error: %s\n", failure)
	} else {
		fmt.Fprintf(w, "Last error (%s): %s\n", stage, failure)
	}
}

func serviceAccess(s serviceDisplay) string {
	if s.Public {
		return "public"
	}
	if len(s.Allow) > 0 {
		return "private (allowlist)"
	}
	return "private (same project)"
}

func serviceState(s serviceDisplay) string {
	if s.LastError != "" {
		return "needs attention"
	}
	if !s.DesiredActive {
		return "stopped"
	}
	if s.Public && !s.Ready {
		return "pending"
	}
	if !s.Running {
		return "starting"
	}
	return "active"
}

func dialState(d dialDisplay) string {
	if d.LastError != "" {
		return "needs attention"
	}
	if !d.DesiredActive {
		return "stopped"
	}
	if d.Running {
		return "listening"
	}
	return "pending"
}

func dialAddress(d dialDisplay) string {
	port := d.Bind
	if d.LocalPort != nil {
		port = *d.LocalPort
	}
	if port == 0 {
		return "not allocated"
	}
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func dialPeerName(d dialDisplay) string {
	if d.ConnectorName != "" {
		return d.ConnectorName
	}
	return d.Connector
}

// POSIX shell quoting for copyable commands; resource names normally need none.
func shellArg(value string) string {
	if value != "" && strings.IndexFunc(value, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-._:", r))
	}) == -1 {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
