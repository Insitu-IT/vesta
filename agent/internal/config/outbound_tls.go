package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
)

// OutboundTLSConfig trusts system roots plus an explicitly supplied local CA.
// The callback client identity is separate from the agent's HTTPS serving pair.
// Client credentials reload for new handshakes to support certificate rotation.
func (c *Config) OutboundTLSConfig() (*tls.Config, error) {
	if !c.OrchestratorVerifySSL {
		return nil, errors.New("orchestrator TLS verification is required")
	}
	configuration := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.TLSCAFile != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, errors.New("system callback trust unavailable")
		}
		data, err := os.ReadFile(c.TLSCAFile)
		if err != nil || !roots.AppendCertsFromPEM(data) {
			return nil, errors.New("configured callback CA unavailable")
		}
		configuration.RootCAs = roots
	}
	cert, key := c.CallbackClientCertFile, c.CallbackClientKeyFile
	if (cert == "") != (key == "") {
		return nil, errors.New("callback mTLS requires a certificate/key pair")
	}
	if cert != "" {
		if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
			return nil, errors.New("configured callback certificate unavailable")
		}
		configuration.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			current, err := tls.LoadX509KeyPair(cert, key)
			if err != nil {
				return nil, errors.New("configured callback certificate unavailable")
			}
			return &current, nil
		}
	}
	return configuration, nil
}
