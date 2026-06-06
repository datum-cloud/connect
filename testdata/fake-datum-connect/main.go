// fake-datum-connect emulates the datum-connect Rust binary for testing.
//
// Modes (controlled by FAKE_DUMMY_MODE env var):
//   missing-token: exits 1 with error about missing token
//   expired-token: prints ready JSON with "status": "expired"
//   401-then-recover: first call returns 401 JSON, second returns ready JSON
//   child-crash: exits with code 1
//
// Subcommands: list, listen, update, delete
// Flags: --json
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	args := os.Args[1:]

	// Parse --json flag
	jsonOut := false
	var subcmd string
	for i, arg := range args {
		if arg == "--json" {
			jsonOut = true
			args = append(args[:i], args[i+1:]...)
			break
		}
	}
	if len(args) > 0 {
		subcmd = args[0]
	}

	mode := os.Getenv("FAKE_DUMMY_MODE")

	// Handle child-crash mode
	if mode == "child-crash" {
		os.Exit(1)
	}

	// Handle 401-then-recover mode (check for a counter file)
	if mode == "401-then-recover" {
		counterPath := "/tmp/fake-datum-connect-401-counter"
		count := 0
		if data, err := os.ReadFile(counterPath); err == nil {
			count, _ = strconv.Atoi(string(data))
		}
		count++
		os.WriteFile(counterPath, []byte(strconv.Itoa(count)), 0644)
		if count == 1 {
			if jsonOut {
				fmt.Println(`{"status":"error","code":401,"message":"unauthorized"}`)
			} else {
				fmt.Fprintln(os.Stderr, "error: unauthorized (401)")
			}
			os.Exit(1)
		}
		// Fall through to normal handling on second call
	}

	switch subcmd {
	case "list":
		handleList(jsonOut)
	case "listen":
		handleListen(jsonOut)
	case "update":
		handleUpdate(jsonOut)
	case "delete":
		handleDelete(jsonOut)
	default:
		fmt.Fprintln(os.Stderr, "Usage: fake-datum-connect [--json] [list|listen|update|delete]")
		os.Exit(2)
	}
}

func handleList(jsonOut bool) {
	token := os.Getenv("DATUM_ACCESS_TOKEN")
	if token == "" && os.Getenv("FAKE_DUMMY_MODE") != "expired-token" {
		if os.Getenv("FAKE_DUMMY_MODE") != "missing-token" {
			fmt.Fprintln(os.Stderr, "error: missing DATUM_ACCESS_TOKEN")
			os.Exit(1)
		}
	}

	if os.Getenv("FAKE_DUMMY_MODE") == "expired-token" {
		if jsonOut {
			fmt.Println(`[{"id":"tun-123","label":"dev-server","endpoint":"localhost:8080","status":"expired"}]`)
		}
		return
	}

	if jsonOut {
		tunnels := []map[string]string{
			{"id": "tun-123", "label": "dev-server", "endpoint": "localhost:8080", "status": "ready"},
			{"id": "tun-456", "label": "staging-api", "endpoint": "localhost:3000", "status": "ready"},
		}
		data, _ := json.Marshal(tunnels)
		fmt.Println(string(data))
	} else {
		fmt.Println("ID        LABEL          ENDPOINT           STATUS")
		fmt.Println("---       ----          -------           ------")
		fmt.Println("tun-123   dev-server    localhost:8080     ready")
		fmt.Println("tun-456   staging-api   localhost:3000     ready")
	}
}

func handleListen(jsonOut bool) {
	token := os.Getenv("DATUM_ACCESS_TOKEN")
	if token == "" && os.Getenv("FAKE_DUMMY_MODE") != "expired-token" {
		fmt.Fprintln(os.Stderr, "error: missing DATUM_ACCESS_TOKEN")
		os.Exit(1)
	}

	if os.Getenv("FAKE_DUMMY_MODE") == "expired-token" {
		if jsonOut {
			fmt.Println(`{"type":"error","message":"token expired"}`)
		} else {
			fmt.Fprintln(os.Stderr, "error: token expired")
		}
		os.Exit(1)
	}

	// Always emit typed JSON (listen command reads stdout regardless of --json flag)
	fmt.Println(`{"type":"ready","id":"tun-123","label":"dev-server","endpoint":"localhost:8080","hostnames":["tun-123.datum.dev"],"status":"ready"}`)

	// Block until SIGINT
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}

func handleUpdate(jsonOut bool) {
	if jsonOut {
		fmt.Println(`{"id":"tun-123","label":"dev-server","endpoint":"localhost:9090","status":"ready","updated":true}`)
	} else {
		fmt.Println("Tunnel updated: endpoint -> localhost:9090")
	}
}

func handleDelete(jsonOut bool) {
	if jsonOut {
		fmt.Println(`{"id":"tun-123","deleted":true}`)
	} else {
		fmt.Println("Tunnel deleted: tun-123")
	}
}

func contains(args []string, s string) bool {
	for _, a := range args {
		if strings.Contains(a, s) {
			return true
		}
	}
	return false
}

func getEnv(args []string, key string) string {
	for _, a := range args {
		if strings.HasPrefix(a, key+"=") {
			return a[len(key)+1:]
		}
	}
	return ""
}
