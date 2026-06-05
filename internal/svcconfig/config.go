// Package svcconfig provides tunnel configuration serialization.
package svcconfig

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// TunnelConfig represents a persisted tunnel configuration.
type TunnelConfig struct {
	Name      string `yaml:"name"`
	Label     string `yaml:"label"`
	Endpoint  string `yaml:"endpoint"`
	Project   string `yaml:"project"`
	Session   string `yaml:"session"`
	Org       string `yaml:"org,omitempty"`
	APIHost   string `yaml:"api_host,omitempty"`
	CreatedAt string `yaml:"created_at,omitempty"`
}

// Save writes a TunnelConfig to the given path as YAML.
func Save(cfg TunnelConfig, path string) error {
	// TODO: Phase 5 — implement config saving
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	dir := path[:strings.LastIndexByte(path, '/')]
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Load reads a TunnelConfig from the given path.
func Load(path string) (TunnelConfig, error) {
	// TODO: Phase 5 — implement config loading
	var cfg TunnelConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}
