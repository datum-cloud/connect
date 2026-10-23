package commands

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"go.datum.net/datumctl-plugins/connect/internal/daemonservice"
)

// shareTicketPrefixes mark a project-less share ticket (connect-lib/share),
// newest first; DCSHARE2 tickets saved before the rename still dial. Tickets
// are case-insensitive.
var shareTicketPrefixes = []string{"DATUMTUN1", "DCSHARE2"}

var foregroundExecutable = daemonservice.ForegroundExecutable

func isShareTicket(value string) bool {
	value = strings.ToUpper(strings.TrimSpace(value))
	for _, prefix := range shareTicketPrefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func newLocal(opts *options) *cobra.Command {
	var port uint16
	var host string
	var maxPeers int
	var name string
	var udpPort uint16
	var publicAddrs []string
	var keyFile string
	cmd := &cobra.Command{
		Use:   "local [HOST:PORT]",
		Short: "Share a local service with your own devices, without signing in",
		Long: "Share one local TCP service with devices that hold a pairing ticket. No Datum\n" +
			"account, login, or project is needed, and nothing is saved unless you pass\n" +
			"--key-file.\n\n" +
			"The command prints a ticket and a QR code. Scan the QR code with the Datum\n" +
			"Connect Android app, or run the printed dial command on another computer.\n" +
			"Traffic goes directly between the devices when possible and otherwise through\n" +
			"a public iroh relay.\n\n" +
			"Anyone with the ticket can pair, up to --max-peers devices, until you stop\n" +
			"this command. The ticket also contains this computer's IP addresses. Each run\n" +
			"prints a new ticket, unless --key-file names a file that keeps the share's\n" +
			"identity: the first run creates it, later runs print a ticket that devices\n" +
			"paired before still accept. Delete the file for a new ticket.\n\n" +
			"Devices show the share as --name, which defaults to HOSTNAME:PORT. Each device\n" +
			"can rename it.",
		Example: "  datumctl connect local --port 9999\n" +
			"  datumctl connect local --port 3000 --name \"API dev server\"\n" +
			"  datumctl connect local 127.0.0.1:3000 --max-peers 1\n" +
			"  datumctl connect local --port 3000 --key-file ~/.config/datum/api-share.key",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := localTarget(args, host, port, cmd.Flags().Changed("port"))
			if err != nil {
				return err
			}
			if maxPeers < 1 {
				return fmt.Errorf("--max-peers must be at least 1")
			}
			name, err = shareName(name, target, cmd.Flags().Changed("name"))
			if err != nil {
				return err
			}
			if err := validatePublicAddrs(publicAddrs); err != nil {
				return err
			}
			extra := []string{}
			if udpPort != 0 {
				extra = append(extra, "--udp-port", strconv.Itoa(int(udpPort)))
			}
			for _, addr := range publicAddrs {
				extra = append(extra, "--public-addr", addr)
			}
			if keyFile != "" {
				// The daemon may run from another directory.
				abs, err := filepath.Abs(keyFile)
				if err != nil {
					return fmt.Errorf("--key-file: %w", err)
				}
				extra = append(extra, "--key-file", abs)
			}
			return runLocal(cmd, opts, target, name, maxPeers, extra)
		},
	}
	cmd.Flags().Uint16Var(&port, "port", 0, "Local port to share")
	cmd.Flags().StringVar(&host, "host", "localhost", "Local host to share with --port")
	cmd.Flags().IntVar(&maxPeers, "max-peers", 4, "Devices that may pair before pairing closes")
	cmd.Flags().StringVar(&name, "name", "", "Name devices show for this share (default HOSTNAME:PORT)")
	cmd.Flags().Uint16Var(&udpPort, "udp-port", 0, "Bind iroh's UDP socket to this port, so a load balancer or firewall can forward to it (default random)")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "Keep the share's identity in this file, created on first use, so its ticket works across runs")
	cmd.Flags().StringArrayVar(&publicAddrs, "public-addr", nil, "IP:PORT where peers can reach this share directly, such as a load balancer forwarding to --udp-port; repeatable")
	return cmd
}

// validatePublicAddrs requires literal IP:PORT addresses, because they go
// into the ticket as-is and peers dial them without a DNS lookup.
func validatePublicAddrs(addrs []string) error {
	for _, addr := range addrs {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || net.ParseIP(host) == nil {
			return fmt.Errorf("--public-addr %q must be IP:PORT, with IPv6 in brackets, such as [2001:db8::1]:4433", addr)
		}
		if _, err := parsePort(port); err != nil {
			return fmt.Errorf("--public-addr %q: %w", addr, err)
		}
	}
	return nil
}

// maxShareName matches the limit connect-share applies to names.
const maxShareName = 64

// shareName validates an explicit --name or derives HOSTNAME:PORT.
func shareName(name, target string, set bool) (string, error) {
	if !set {
		_, port, _ := net.SplitHostPort(target)
		return deviceNameHint() + ":" + port, nil
	}
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return "", fmt.Errorf("--name must not be empty")
	case utf8.RuneCountInString(name) > maxShareName:
		return "", fmt.Errorf("--name must be at most %d characters", maxShareName)
	case strings.IndexFunc(name, unicode.IsControl) >= 0:
		return "", fmt.Errorf("--name must not contain control characters")
	}
	return name, nil
}

func localTarget(args []string, host string, port uint16, portSet bool) (string, error) {
	switch {
	case len(args) == 1 && portSet:
		return "", fmt.Errorf("use either HOST:PORT or --port, not both")
	case len(args) == 1:
		return args[0], validateEndpoint(args[0])
	case portSet && port != 0:
		target := net.JoinHostPort(host, strconv.Itoa(int(port)))
		return target, validateEndpoint(target)
	default:
		return "", fmt.Errorf("choose a local service with --port PORT or HOST:PORT.\nExample: datumctl connect local --port 9999")
	}
}

func runLocal(cmd *cobra.Command, opts *options, target, name string, maxPeers int, extra []string) error {
	out := cmd.OutOrStdout()
	jsonOut := outputFormat(cmd) == "json"
	daemonArgs := append([]string{"local", target, "--max-peers", strconv.Itoa(maxPeers), "--name", name}, extra...)
	names := map[string]string{}
	return runForeground(cmd, opts, daemonArgs, func(line []byte, event foregroundEvent) {
		if jsonOut {
			fmt.Fprintln(out, string(line))
			return
		}
		switch event.Event {
		case "share_ready":
			_, port, _ := net.SplitHostPort(target)
			fmt.Fprintf(out, "Sharing %s as %q. Anyone with this ticket can connect until you press Ctrl+C.\n", target, name)
			fmt.Fprintln(out, "The ticket also contains this computer's IP addresses.")
			switch {
			case event.KeyFile == "":
			case event.KeyCreated != nil && *event.KeyCreated:
				fmt.Fprintf(out, "Saved the share's key to %s. Later runs with --key-file print a ticket paired devices still accept.\n", event.KeyFile)
			default:
				fmt.Fprintf(out, "Ticket reused from %s; delete the file for a new one.\n", event.KeyFile)
			}
			if terminalWriter(out) {
				fmt.Fprintln(out)
				if err := writeQR(out, event.Ticket); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "could not draw QR code: %v\n", err)
				}
				fmt.Fprintln(out, "Scan with the Datum Connect Android app, or on another computer run:")
			} else {
				fmt.Fprintln(out, "On another computer, run:")
			}
			fmt.Fprintf(out, "\n  datumctl connect dial %s --bind %s\n\n", event.Ticket, port)
			fmt.Fprintln(out, "Waiting for devices…")
		case "share_paired":
			name := event.Name
			if name == "" {
				name = "device"
			}
			names[event.Peer] = name
			fmt.Fprintf(out, "✓ Paired %s (%s)\n", name, shortID(event.Peer))
		case "share_path":
			name := names[event.Peer]
			if name == "" {
				name = shortID(event.Peer)
			}
			fmt.Fprintf(out, "  %s: %s\n", name, describePath(event))
		}
	})
}

func runTicketDial(cmd *cobra.Command, opts *options, ticket string, bind uint16, protocol string) error {
	if protocol != "tcp" {
		return fmt.Errorf("share tickets support TCP only")
	}
	out := cmd.OutOrStdout()
	jsonOut := outputFormat(cmd) == "json"
	daemonArgs := []string{
		"local-dial", strings.TrimSpace(ticket),
		"--bind", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(bind))),
		"--name", deviceNameHint(),
	}
	lastFailure := "" // a browser retrying a down service repeats the same reason
	return runForeground(cmd, opts, daemonArgs, func(line []byte, event foregroundEvent) {
		if jsonOut {
			fmt.Fprintln(out, string(line))
			return
		}
		switch event.Event {
		case "dial_path":
			fmt.Fprintf(out, "  Path: %s\n", describePath(event))
			return
		case "dial_connect_failed":
			if event.Reason != lastFailure || lastFailure == "" {
				fmt.Fprintf(out, "✗ %s\n", sentence(event.Reason, "The shared service is unreachable"))
			}
			lastFailure = event.Reason
			return
		case "dial_forwarded":
			lastFailure = ""
			fmt.Fprintln(out, "✓ The shared service is reachable again.")
			return
		}
		if event.Event == "dial_ready" {
			if event.SharerName != "" {
				fmt.Fprintf(out, "✓ Paired with %q. The shared service is at %s until you press Ctrl+C.\n", event.SharerName, event.LocalAddr)
			} else {
				fmt.Fprintf(out, "✓ Paired. The shared service is at %s until you press Ctrl+C.\n", event.LocalAddr)
			}
		}
	})
}

// foregroundEvent is one stdout line from a project-less datum-connectd mode.
type foregroundEvent struct {
	Event      string `json:"event"`
	Ticket     string `json:"ticket,omitempty"`
	Peer       string `json:"peer,omitempty"`
	Name       string `json:"name,omitempty"`
	LocalAddr  string `json:"local_addr,omitempty"`
	SharerName string `json:"sharer_name,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Path       string `json:"path,omitempty"`
	Remote     string `json:"remote,omitempty"`
	RTTMs      *int64 `json:"rtt_ms,omitempty"`
	KeyFile    string `json:"key_file,omitempty"`
	KeyCreated *bool  `json:"key_created,omitempty"`
}

// runForeground runs datum-connectd in a project-less foreground mode until it
// exits or the user interrupts it. It needs no daemon service, login, or
// project, and passes no Datum credentials to the child.
func runForeground(cmd *cobra.Command, opts *options, args []string, onEvent func([]byte, foregroundEvent)) error {
	if format := outputFormat(cmd); format == "yaml" {
		return fmt.Errorf("%s streams events; use --output json or table", cmd.Name())
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	exe, err := foregroundExecutable(ctx, cmd.Root().Version, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	child := exec.Command(exe, args...)
	child.Env = foregroundEnv(os.Environ(), opts.verbose)
	stdout, err := child.StdoutPipe()
	if err != nil {
		return err
	}
	logs := &logTail{}
	child.Stderr = logs
	if opts.verbose {
		child.Stderr = io.MultiWriter(logs, cmd.ErrOrStderr())
	}
	// The child receives Ctrl+C from the terminal and shuts down cleanly. Keep
	// the plugin alive until it does, and forward termination requests.
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	if err := child.Start(); err != nil {
		return fmt.Errorf("start %s: %w", exe, err)
	}
	interrupted := make(chan struct{})
	var once sync.Once
	go func() {
		for sig := range signals {
			once.Do(func() { close(interrupted) })
			if runtime.GOOS == "windows" {
				_ = child.Process.Kill()
			} else {
				_ = child.Process.Signal(sig)
			}
		}
	}()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		var event foregroundEvent
		if json.Unmarshal(line, &event) != nil || event.Event == "" {
			continue
		}
		onEvent(line, event)
	}
	err = child.Wait()
	select {
	case <-interrupted:
		return nil
	default:
	}
	if err != nil {
		if message := logs.lastError(); message != "" {
			return errors.New(message)
		}
		return fmt.Errorf("datum-connectd %s failed: %w", args[0], err)
	}
	return nil
}

// foregroundEnv drops Datum session variables the child never needs and keeps
// its logs quiet unless --verbose or RUST_LOG asks otherwise.
func foregroundEnv(env []string, verbose bool) []string {
	result := make([]string, 0, len(env)+1)
	hasRustLog := false
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "DATUM_SESSION", "DATUM_CREDENTIALS_HELPER", "DATUM_CONNECT_TOKEN":
			continue
		case "RUST_LOG":
			hasRustLog = true
		}
		result = append(result, entry)
	}
	if !hasRustLog {
		level := "warn"
		if verbose {
			level = "info"
		}
		result = append(result, "RUST_LOG="+level)
	}
	return result
}

// logTail keeps the last JSON log lines from the child for error reporting.
type logTail struct {
	mu      sync.Mutex
	partial []byte
	lines   [][]byte
}

func (l *logTail) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.partial = append(l.partial, p...)
	for {
		i := strings.IndexByte(string(l.partial), '\n')
		if i < 0 {
			break
		}
		l.lines = append(l.lines, append([]byte(nil), l.partial[:i]...))
		l.partial = l.partial[i+1:]
		if len(l.lines) > 32 {
			l.lines = l.lines[1:]
		}
	}
	return len(p), nil
}

// lastError returns the most recent error the child logged, or its last
// non-JSON output (for example a clap usage error).
func (l *logTail) lastError() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	lines := l.lines
	if len(l.partial) > 0 {
		lines = append(lines, l.partial)
	}
	var plain []string
	for i := len(lines) - 1; i >= 0; i-- {
		var record struct {
			Fields struct {
				Error string `json:"error"`
			} `json:"fields"`
		}
		if json.Unmarshal(lines[i], &record) == nil {
			if record.Fields.Error != "" {
				return record.Fields.Error
			}
			continue
		}
		text := strings.TrimSpace(string(lines[i]))
		// Drop clap's help hints and its "error: " prefix; the caller adds its own.
		if text == "" || strings.HasPrefix(text, "For more information") {
			continue
		}
		plain = append([]string{strings.TrimPrefix(text, "error: ")}, plain...)
	}
	return strings.Join(plain, "\n")
}

// sentence capitalizes a reason from datum-connectd for display on its own
// line, or returns fallback when the reason is empty.
func sentence(reason, fallback string) string {
	if reason == "" {
		return fallback
	}
	r, size := utf8.DecodeRuneInString(reason)
	return string(unicode.ToUpper(r)) + reason[size:]
}

// describePath renders a path report, for example "direct to
// [2001:db8::1]:4433, 12 ms" or "relayed via https://relay.example./, 150 ms".
func describePath(event foregroundEvent) string {
	var b strings.Builder
	switch event.Path {
	case "direct":
		b.WriteString("direct")
		if event.Remote != "" {
			b.WriteString(" to " + event.Remote)
		}
	case "relay":
		b.WriteString("relayed")
		if event.Remote != "" {
			b.WriteString(" via " + event.Remote)
		}
	default:
		b.WriteString("path unknown")
	}
	if event.RTTMs != nil {
		fmt.Fprintf(&b, ", %d ms", *event.RTTMs)
	}
	return b.String()
}

func outputFormat(cmd *cobra.Command) string {
	format, _ := cmd.Flags().GetString("output")
	return format
}

func terminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12] + "…"
	}
	return id
}
