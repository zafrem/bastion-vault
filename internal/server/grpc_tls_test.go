package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/zafrem/bastion-vault/internal/access"
)

// ─── test PKI ────────────────────────────────────────────────────────────────

type pki struct {
	dir                           string
	caKey                         *ecdsa.PrivateKey
	caCert                        *x509.Certificate
	caFile, certFile, keyFile     string
	clientCertFile, clientKeyFile string
	serial                        int64
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newCA(t *testing.T, name string) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert, der
}

func (p *pki) issue(t *testing.T, certPath, keyPath, cn string, server bool) {
	t.Helper()
	p.serial++
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100 + p.serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	writePEM(t, certPath, "CERTIFICATE", der)
	writePEM(t, keyPath, "EC PRIVATE KEY", kder)
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	p := &pki{dir: t.TempDir()}
	var der []byte
	p.caKey, p.caCert, der = newCA(t, "test-ca")
	p.caFile = filepath.Join(p.dir, "ca.pem")
	writePEM(t, p.caFile, "CERTIFICATE", der)
	p.certFile, p.keyFile = filepath.Join(p.dir, "server.pem"), filepath.Join(p.dir, "server.key")
	p.clientCertFile, p.clientKeyFile = filepath.Join(p.dir, "client.pem"), filepath.Join(p.dir, "client.key")
	p.issue(t, p.certFile, p.keyFile, "server-1", true)
	p.issue(t, p.clientCertFile, p.clientKeyFile, "client-1", false)
	return p
}

// rotate replaces the server key pair on disk with a new one from the same CA.
func (p *pki) rotate(t *testing.T) {
	t.Helper()
	p.issue(t, p.certFile, p.keyFile, "server-2", true)
	later := time.Now().Add(5 * time.Second) // make sure the mtime differs on coarse filesystems
	_ = os.Chtimes(p.certFile, later, later)
	_ = os.Chtimes(p.keyFile, later, later)
}

// ─── server / client helpers ─────────────────────────────────────────────────

// serveVaultGRPC starts a real Vault gRPC server (JWT interceptor, JSON codec) on a TCP port,
// optionally with TLS credentials, and returns its address.
func serveVaultGRPC(t *testing.T, creds credentials.TransportCredentials) string {
	t.Helper()
	g := testGRPCServer(t)
	g.enableAuth(grpcTestCfg(false, false), access.NewController(""), nil)
	opts := []grpc.ServerOption{grpc.UnaryInterceptor(g.UnaryInterceptor())}
	if creds != nil {
		opts = append(opts, grpc.Creds(creds))
	}
	srv := grpc.NewServer(opts...)
	g.Register(srv)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func healthCall(addr string, creds credentials.TransportCredentials, token string) error {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if token != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	}
	var out map[string]any
	return conn.Invoke(ctx, grpcMethodHealth, map[string]any{}, &out)
}

func clientTLS(t *testing.T, caFile, certFile, keyFile string) credentials.TransportCredentials {
	t.Helper()
	pemBytes, _ := os.ReadFile(caFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemBytes)
	cfg := &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
	if certFile != "" {
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return credentials.NewTLS(cfg)
}

func peerSerial(t *testing.T, addr string) int64 {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}) //nolint:gosec // reading the presented certificate only
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestTLS_NotConfiguredReturnsNoCredentials(t *testing.T) {
	creds, err := TLSCredentials("", "", "")
	if err != nil || creds != nil {
		t.Fatalf("TLSCredentials with nothing configured = (%v, %v), want (nil, nil)", creds, err)
	}
	if err := healthCall(serveVaultGRPC(t, nil), insecure.NewCredentials(), ""); err != nil {
		t.Errorf("plaintext health check: %v", err)
	}
}

func TestTLS_MisconfigurationIsAnError(t *testing.T) {
	p := newPKI(t)
	garbage := filepath.Join(p.dir, "garbage.pem")
	_ = os.WriteFile(garbage, []byte("not a pem"), 0o600)
	cases := map[string][3]string{
		"cert without key":           {p.certFile, "", ""},
		"key without cert":           {"", p.keyFile, ""},
		"client CA without a server": {"", "", p.caFile},
		"missing cert file":          {filepath.Join(p.dir, "nope.pem"), p.keyFile, ""},
		"mismatched key pair":        {p.certFile, p.clientKeyFile, ""},
		"garbage client CA":          {p.certFile, p.keyFile, garbage},
	}
	for name, c := range cases {
		if _, err := TLSCredentials(c[0], c[1], c[2]); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestTLS_ServesOverTLSAndRejectsPlaintext(t *testing.T) {
	p := newPKI(t)
	creds, err := TLSCredentials(p.certFile, p.keyFile, "")
	if err != nil {
		t.Fatal(err)
	}
	addr := serveVaultGRPC(t, creds)

	if err := healthCall(addr, clientTLS(t, p.caFile, "", ""), ""); err != nil {
		t.Errorf("TLS client trusting the CA: %v", err)
	}
	if err := healthCall(addr, insecure.NewCredentials(), ""); err == nil {
		t.Error("a plaintext client must not be able to talk to a TLS server")
	}
	_, _, otherDER := newCA(t, "other-ca")
	other := filepath.Join(p.dir, "other-ca.pem")
	writePEM(t, other, "CERTIFICATE", otherDER)
	if err := healthCall(addr, clientTLS(t, other, "", ""), ""); err == nil {
		t.Error("a client that does not trust the server certificate must fail")
	}
}

func TestTLS_MutualTLSRequiresAClientCertificate(t *testing.T) {
	p := newPKI(t)
	creds, err := TLSCredentials(p.certFile, p.keyFile, p.caFile)
	if err != nil {
		t.Fatal(err)
	}
	addr := serveVaultGRPC(t, creds)

	if err := healthCall(addr, clientTLS(t, p.caFile, "", ""), ""); err == nil {
		t.Error("mTLS: a client without a certificate must be rejected")
	}
	if err := healthCall(addr, clientTLS(t, p.caFile, p.clientCertFile, p.clientKeyFile), ""); err != nil {
		t.Errorf("mTLS: client with a certificate from the trusted CA: %v", err)
	}
	rogue := &pki{dir: t.TempDir()}
	rogue.caKey, rogue.caCert, _ = newCA(t, "rogue-ca")
	rc, rk := filepath.Join(rogue.dir, "c.pem"), filepath.Join(rogue.dir, "c.key")
	rogue.issue(t, rc, rk, "rogue", false)
	if err := healthCall(addr, clientTLS(t, p.caFile, rc, rk), ""); err == nil {
		t.Error("mTLS: a client certificate from an untrusted CA must be rejected")
	}
}

func TestTLS_RotatedCertificateIsPickedUpWithoutARestart(t *testing.T) {
	p := newPKI(t)
	creds, err := TLSCredentials(p.certFile, p.keyFile, "")
	if err != nil {
		t.Fatal(err)
	}
	addr := serveVaultGRPC(t, creds)

	before := peerSerial(t, addr)
	p.rotate(t)
	if after := peerSerial(t, addr); after == before {
		t.Fatalf("server still presents the old certificate (serial %d) after the files were replaced", after)
	}
	if err := healthCall(addr, clientTLS(t, p.caFile, "", ""), ""); err != nil {
		t.Errorf("health check with the rotated certificate: %v", err)
	}
}

func TestTLS_BrokenReplacementKeepsTheWorkingCertificate(t *testing.T) {
	p := newPKI(t)
	creds, err := TLSCredentials(p.certFile, p.keyFile, "")
	if err != nil {
		t.Fatal(err)
	}
	addr := serveVaultGRPC(t, creds)
	before := peerSerial(t, addr)

	_ = os.WriteFile(p.certFile, []byte("half-written"), 0o600)
	later := time.Now().Add(5 * time.Second)
	_ = os.Chtimes(p.certFile, later, later)
	if got := peerSerial(t, addr); got != before {
		t.Errorf("a broken replacement changed the served certificate (%d -> %d)", before, got)
	}
}

func TestTLS_JWTStillAppliesOverTLS(t *testing.T) {
	p := newPKI(t)
	creds, err := TLSCredentials(p.certFile, p.keyFile, "")
	if err != nil {
		t.Fatal(err)
	}
	addr := serveVaultGRPC(t, creds)
	tc := clientTLS(t, p.caFile, "", "")

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(tc))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var out map[string]any
	err = conn.Invoke(context.Background(), grpcMethodClassify, map[string]any{"records": []map[string]any{{"a": "b"}}}, &out)
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("over TLS without a JWT: code = %v, want Unauthenticated", status.Code(err))
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+
		mustToken(t))
	if err := conn.Invoke(ctx, grpcMethodClassify, map[string]any{"records": []map[string]any{{"a": "b"}}}, &out); err != nil {
		t.Errorf("over TLS with a valid JWT: %v", err)
	}
}

func mustToken(t *testing.T) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "mia", "iss": "bastion", "tenant": "acme", "dept": "marketing", "role": "manager",
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(grpcTestSecret))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
