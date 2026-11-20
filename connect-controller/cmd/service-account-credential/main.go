package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.datum.net/connect-controller/internal/serviceaccountcredential"
)

func main() {
	configPath := flag.String("config", "", "Private service account credential configuration file")
	installPath := flag.String("install-to", "", "Copy this executable into a shared init-container volume")
	flag.Parse()
	if err := run(*configPath, *installPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(configPath, installPath string) error {
	if installPath != "" {
		if configPath != "" || !filepath.IsAbs(installPath) {
			return fmt.Errorf("installation requires only an absolute destination")
		}
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		source, err := os.Open(executable)
		if err != nil {
			return err
		}
		defer source.Close()
		temporary, err := os.CreateTemp(filepath.Dir(installPath), ".credential-helper-*")
		if err != nil {
			return err
		}
		defer os.Remove(temporary.Name())
		defer temporary.Close()
		if _, err := io.Copy(temporary, source); err != nil {
			return err
		}
		if err := temporary.Chmod(0555); err != nil {
			return err
		}
		if err := temporary.Close(); err != nil {
			return err
		}
		return os.Rename(temporary.Name(), installPath)
	}
	if configPath == "" {
		return fmt.Errorf("credential configuration is required")
	}
	config, err := serviceaccountcredential.Load(configPath)
	if err != nil {
		return err
	}
	credential, err := serviceaccountcredential.Exchange(context.Background(), config, nil)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(credential)
}
