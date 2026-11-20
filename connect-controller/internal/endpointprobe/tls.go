package endpointprobe

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func ClientTLS(caFile, certificateFile, keyFile string) (*tls.Config, error) {
	if caFile == "" || certificateFile == "" || keyFile == "" {
		return nil, fmt.Errorf("probe CA and client certificate/key are required")
	}
	pool, err := CertificatePool(caFile)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(certificateFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{certificate}}, nil
}

func CertificatePool(path string) (*x509.CertPool, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(encoded) {
		return nil, fmt.Errorf("CA file contains no certificates")
	}
	return pool, nil
}
