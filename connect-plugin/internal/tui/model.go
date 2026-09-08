// Package tui implements the live dashboard for `tunnel interactive`.
//
// The Model consumes the same typed JSON message stream that `listen`
// prints as plain lines (internal/supervise.Run's callback) and renders it
// as a scrolling event log under a status header, instead of printing it
// directly. It does not yet have per-request traffic data (method/path/
// status/latency, or even the connection-level tunnel_metrics polling
// planned for the Rust side) — that's the next layer on top of this one.
package tui

import (
	"encoding/json"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	rexec "go.datum.net/datumctl-plugins/connect/internal/exec"
	"go.datum.net/datumctl-plugins/connect/internal/supervise"
)

// maxLogLines bounds the in-memory scrollback so a long-running session
// doesn't grow without limit.
const maxLogLines = 500

var (
	styleBold   = lipgloss.NewStyle().Bold(true)
	styleMuted  = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	styleAccent = lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Bold(true)
	styleOK     = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	styleWarn   = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	styleErr    = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
)

// MessageMsg wraps a typed message from the Rust child for delivery into
// the bubbletea Update loop via Program.Send.
type MessageMsg struct{ Msg rexec.TypedMessage }

// RequestMsg reports a single request observed by the dummy origin server
// (internal/dummyorigin's onRequest hook) — the only source of per-request
// traffic today, since the real Rust tunnel proxy doesn't parse HTTP.
type RequestMsg struct {
	Method string
	Path   string
	At     time.Time
}

type logLine struct {
	at   time.Time
	text string
}

// stepLabels mirrors connect-lib's ProgressStepKind::label() (connect-lib/
// lib/src/tunnels.rs) — the Go side has no access to that Rust method, so
// the human-readable text for each snake_case `step` value is duplicated
// here. An unrecognized step (e.g. a newer Rust binary added one) falls
// back to the raw snake_case string rather than disappearing silently.
var stepLabels = map[string]string{
	"proxy_accepted":                "tunnel accepted",
	"certificates_ready":            "TLS certificate issued",
	"connector_ready":               "connector ready",
	"iroh_dns_published":            "iroh DNS published",
	"proxy_programmed":              "route programmed",
	"connector_metadata_programmed": "envoy metadata propagated",
}

func stepLabel(step string) string {
	if l, ok := stepLabels[step]; ok {
		return l
	}
	return step
}

// Model is the interactive dashboard's bubbletea model.
type Model struct {
	label       string
	origin      string
	dummyOrigin string // "" when not serving a dummy origin

	status      string // connecting | ready | degraded | error | stopping
	currentStep string // most recent setup-phase step/URL, shown next to status while connecting
	hostnames   []string
	lastErr     string

	log []logLine

	width, height int

	onQuit     func()
	quitCalled bool
}

// New constructs the dashboard model. onQuit is called exactly once, the
// first time the user asks to quit ('q' or ctrl+c). Because bubbletea puts
// the terminal in raw mode, that keypress never reaches this process as a
// real SIGINT — onQuit is the caller's hook to trigger the actual tunnel
// shutdown (e.g. by signaling itself), and the caller is responsible for
// calling Program.Quit() once that shutdown has actually finished, so the
// dashboard stays up through teardown instead of snapping back to the
// shell mid-shutdown.
func New(label, origin, dummyOrigin string, onQuit func()) Model {
	return Model{
		label:       label,
		origin:      origin,
		dummyOrigin: dummyOrigin,
		status:      "connecting",
		onQuit:      onQuit,
	}
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.KeyPressMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			if !m.quitCalled {
				m.quitCalled = true
				m.status = "stopping"
				if m.onQuit != nil {
					m.onQuit()
				}
			}
		}
	case MessageMsg:
		m.apply(msg.Msg)
	case RequestMsg:
		m.appendLog(msg.At, styleAccent.Render("→ "+msg.Method+" "+msg.Path))
	}
	return m, nil
}

func (m *Model) appendLog(at time.Time, text string) {
	m.log = append(m.log, logLine{at: at, text: text})
	if len(m.log) > maxLogLines {
		m.log = m.log[len(m.log)-maxLogLines:]
	}
}

// apply updates model state from one typed message and appends a
// human-readable log line for it — see connect-lib/bin/src/progress.rs and
// main.rs for the JSON event contract (field names per message type).
func (m *Model) apply(msg rexec.TypedMessage) {
	now := time.Now()
	switch msg.Type {
	case "tunnel_ready":
		var ready supervise.TunnelReady
		data, _ := json.Marshal(msg.Fields)
		_ = json.Unmarshal(data, &ready)
		m.hostnames = ready.Hostnames
		m.currentStep = ""
		if m.status != "stopping" {
			m.status = "ready"
		}
		m.appendLog(now, styleOK.Render("✓ tunnel ready"))

	case "tunnel_created":
		id, _ := msg.Fields["id"].(string)
		m.appendLog(now, "tunnel created"+parenSuffix(id))

	case "tunnel_updated":
		m.appendLog(now, "tunnel updated")

	case "tunnel_progress":
		step, _ := msg.Fields["step"].(string)
		status, _ := msg.Fields["status"].(string)
		resource, _ := msg.Fields["resource"].(string)
		label := stepLabel(step)
		m.currentStep = label
		icon := "○"
		if status == "ready" {
			icon = "✓"
		}
		m.appendLog(now, icon+" "+label+parenSuffix(resource))

	case "tunnel_verifying":
		url, _ := msg.Fields["url"].(string)
		m.currentStep = "verifying " + url
		m.appendLog(now, "○ verifying "+url+"…")

	case "tunnel_verified":
		url, _ := msg.Fields["url"].(string)
		m.appendLog(now, "✓ verified "+url)

	case "error":
		m.lastErr = msg.Message
		if m.status != "stopping" {
			m.status = "error"
		}
		if msg.Message != "" {
			m.appendLog(now, styleErr.Render("error: "+msg.Message))
		}

	case "tunnel_terminal_failure", "tunnel_login_lost", "tunnel_deleted_upstream":
		m.lastErr = msg.Message
		if m.status != "stopping" {
			m.status = "degraded"
		}
		if msg.Message != "" {
			m.appendLog(now, styleErr.Render(msg.Message))
		}
	}
}

func parenSuffix(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

func (m Model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	return v
}

func (m Model) render() string {
	width := m.width
	if width <= 0 {
		width = 80
	}
	rule := styleMuted.Render(strings.Repeat("─", width))

	var b strings.Builder
	b.WriteString(m.renderHeader())
	b.WriteString("\n")
	b.WriteString(rule)
	b.WriteString("\n")
	b.WriteString(m.renderLog())
	b.WriteString(rule)
	b.WriteString("\n")
	b.WriteString(m.renderFooter())
	return b.String()
}

func (m Model) renderHeader() string {
	title := styleBold.Render(labelOr(m.label, "tunnel"))
	statusLine := title + "  " + m.renderStatus()
	if m.status == "connecting" && m.currentStep != "" {
		statusLine += styleMuted.Render(" — " + m.currentStep)
	}
	lines := []string{statusLine}

	if len(m.hostnames) > 0 {
		lines = append(lines, styleAccent.Render("https://"+m.hostnames[0])+styleMuted.Render(" → "+m.origin))
	} else {
		lines = append(lines, styleMuted.Render("origin: "+m.origin))
	}
	if m.dummyOrigin != "" {
		lines = append(lines, styleMuted.Render("dummy origin serving on http://"+m.dummyOrigin))
	}
	return strings.Join(lines, "\n")
}

func (m Model) renderStatus() string {
	switch m.status {
	case "ready":
		return styleOK.Render("● ready")
	case "connecting":
		return styleWarn.Render("○ " + m.status)
	case "stopping":
		return styleWarn.Render("○ stopping…")
	case "degraded", "error":
		return styleErr.Render("● " + m.status)
	default:
		return styleMuted.Render(m.status)
	}
}

func (m Model) renderLog() string {
	// header (up to 3 lines) + 2 rules + footer (1 line)
	logHeight := m.height - 6
	if logHeight < 1 {
		logHeight = 1
	}
	start := 0
	if len(m.log) > logHeight {
		start = len(m.log) - logHeight
	}
	var b strings.Builder
	for _, entry := range m.log[start:] {
		b.WriteString(styleMuted.Render(entry.at.Format(time.RFC3339)) + "  " + entry.text + "\n")
	}
	return b.String()
}

func (m Model) renderFooter() string {
	hint := styleBold.Render("[q]") + " " + styleMuted.Render("quit")
	if m.lastErr != "" && (m.status == "error" || m.status == "degraded") {
		return styleErr.Render(m.lastErr) + "   " + hint
	}
	return hint
}

func labelOr(label, fallback string) string {
	if label == "" {
		return fallback
	}
	return label
}
