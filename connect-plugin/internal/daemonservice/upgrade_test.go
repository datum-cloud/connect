package daemonservice

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDaemonExecutableVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "datum-connectd")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'datum-connectd v1.2.3-preview.4\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	version, err := daemonExecutableVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	if version != "1.2.3-preview.4" {
		t.Fatalf("version = %q", version)
	}
}

func TestReplaceLaunchdExecutablePreservesArguments(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><plist><dict><key>ProgramArguments</key><array><string>/Users/test/old/datum-connect-daemon</string><string>--repo</string><string>/Users/test/Connect State</string></array><key>KeepAlive</key><true/></dict></plist>`)
	old, updated, err := replaceLaunchdExecutable(input, "/Users/test/new/datum-connectd")
	if err != nil {
		t.Fatal(err)
	}
	if old != "/Users/test/old/datum-connect-daemon" {
		t.Fatalf("old executable = %q", old)
	}
	for _, want := range []string{"<string>/Users/test/new/datum-connectd</string>", "<string>--repo</string>", "<string>/Users/test/Connect State</string>", "<key>KeepAlive</key>"} {
		if !strings.Contains(string(updated), want) {
			t.Errorf("updated service definition does not contain %q", want)
		}
	}
}

func TestReplaceLaunchdExecutableRejectsUnknownProgram(t *testing.T) {
	input := []byte(`<plist><dict><key>ProgramArguments</key><array><string>/tmp/other-daemon</string></array></dict></plist>`)
	if _, _, err := replaceLaunchdExecutable(input, "/tmp/datum-connectd"); err == nil {
		t.Fatal("expected an unrecognized service executable to be rejected")
	}
}

func TestReplaceSystemdExecutablePreservesArgumentsAndServiceSettings(t *testing.T) {
	input := []byte("[Service]\nExecStart=/home/test/old/datum-connect-daemon --repo \"/home/test/Connect State\"\nConditionFileIsExecutable=/home/test/old/datum-connect-daemon\nRestart=always\n")
	old, updated, err := replaceSystemdExecutable(input, "/home/test/new/datum-connectd")
	if err != nil {
		t.Fatal(err)
	}
	if old != "/home/test/old/datum-connect-daemon" {
		t.Fatalf("old executable = %q", old)
	}
	for _, want := range []string{"ExecStart=/home/test/new/datum-connectd --repo \"/home/test/Connect State\"", "ConditionFileIsExecutable=/home/test/new/datum-connectd", "Restart=always"} {
		if !strings.Contains(string(updated), want) {
			t.Errorf("updated service definition does not contain %q", want)
		}
	}
}

func TestReplaceSystemdExecutableRejectsUnknownOrAmbiguousExecStart(t *testing.T) {
	for _, input := range []string{
		"[Service]\nExecStart=/usr/bin/other-daemon\n",
		"[Service]\nExecStart=/home/test/datum-connectd\nExecStart=/home/test/datum-connectd\n",
	} {
		if _, _, err := replaceSystemdExecutable([]byte(input), "/home/test/new/datum-connectd"); err == nil {
			t.Errorf("expected service definition to be rejected: %q", input)
		}
	}
}
