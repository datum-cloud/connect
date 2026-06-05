// Package svcunit provides service unit generation.
package svcunit

// Install registers a service unit using kardianos/service config.
// Returns the service instance (not started).
func Install(cfg interface{}) (interface{}, error) {
	// TODO: Phase 6 — implement service installation
	// Requires kardianos/service package (added in Phase 6)
	_ = cfg
	return nil, nil
}

// Uninstall removes a service unit by name.
func Uninstall(name string) error {
	// TODO: Phase 6 — implement service uninstallation
	_ = name
	return nil
}
