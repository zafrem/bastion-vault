package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc/credentials"
)

// reloadingCert serves a key pair from disk and picks up a rotated pair without a restart:
// on each TLS handshake it checks the files' modification times and reloads when they changed.
// If a replacement cannot be loaded (for example the cert was written but the key is not yet),
// the previous working pair is kept, and the next change to either file triggers another attempt.
type reloadingCert struct {
	certFile, keyFile string

	mu              sync.Mutex
	cert            *tls.Certificate
	certMod, keyMod time.Time
}

func newReloadingCert(certFile, keyFile string) (*reloadingCert, error) {
	r := &reloadingCert{certFile: certFile, keyFile: keyFile}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load gRPC TLS key pair: %w", err)
	}
	r.cert = &pair
	r.certMod, r.keyMod = modTime(certFile), modTime(keyFile)
	return r, nil
}

func modTime(path string) time.Time {
	if fi, err := os.Stat(path); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *reloadingCert) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cm, km := modTime(r.certFile), modTime(r.keyFile)
	if !cm.Equal(r.certMod) || !km.Equal(r.keyMod) {
		r.certMod, r.keyMod = cm, km // remember the attempt: retry only after the next change
		if pair, err := tls.LoadX509KeyPair(r.certFile, r.keyFile); err != nil {
			log.Printf("[grpc] TLS certificate reload failed, keeping the previous one: %v", err)
		} else {
			r.cert = &pair
			log.Printf("[grpc] TLS certificate reloaded from %s", r.certFile)
		}
	}
	return r.cert, nil
}

// TLSCredentials builds gRPC transport credentials from PEM files.
//
//   - all three empty: TLS is not configured, and (nil, nil) is returned;
//   - certFile and keyFile must be set together;
//   - clientCAFile (optional) turns on mutual TLS: clients must present a certificate signed by it.
func TLSCredentials(certFile, keyFile, clientCAFile string) (credentials.TransportCredentials, error) {
	if certFile == "" && keyFile == "" && clientCAFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("grpc_tls_cert and grpc_tls_key must be set together (grpc_tls_client_ca also needs both)")
	}
	rc, err := newReloadingCert(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: rc.GetCertificate}
	if clientCAFile != "" {
		pemBytes, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read grpc_tls_client_ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("grpc_tls_client_ca %s contains no PEM certificates", clientCAFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return credentials.NewTLS(cfg), nil
}
