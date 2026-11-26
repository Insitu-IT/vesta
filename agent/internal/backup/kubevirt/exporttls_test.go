package kubevirt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// The defect (#45): StreamToS3 hardcoded InsecureSkipVerify, so the bearer token
// authorising the export and the VM disk image behind it both crossed a connection
// whose peer was never authenticated. The remedy is not "add a CA path" — KubeVirt
// publishes the right root inside the export resource — so these tests are about
// the two things that can still go wrong once it is wired up: accepting a CA that
// verifies nothing, and treating the published field as something other than PEM.

func testCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vmexport-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestExportTLSConfigAcceptsThePublishedPEM(t *testing.T) {
	// Positive control. Without it the failure cases below pass just as happily
	// against a function that rejects everything, which is "fail closed" in the
	// useless sense.
	cfg, err := exportTLSConfig(testCAPEM(t))
	if err != nil {
		t.Fatalf("a valid PEM CA must be accepted: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs is nil, so Go would fall back to the system pool — which " +
			"cannot vouch for an in-cluster export endpoint")
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify set — this is the whole defect")
	}
	if cfg.MinVersion == 0 {
		t.Error("MinVersion unset, leaving the floor to whatever the toolchain defaults to")
	}
}

func TestExportTLSConfigRefusesAnAbsentCA(t *testing.T) {
	// An export that is Ready but publishes no cert. Failing closed here is the
	// decision recorded on the issue: the CA ships with the URL, so there is no
	// legitimate "CA unavailable but export usable" state to accommodate.
	_, err := exportTLSConfig("")
	if err == nil {
		t.Fatal("expected an error for an empty CA")
	}
	if !strings.Contains(err.Error(), "no CA certificate") {
		t.Errorf("error should say the link carried no CA; got %q", err)
	}
}

func TestExportTLSConfigRefusesUnusableCA(t *testing.T) {
	for _, tc := range []struct{ name, ca string }{
		{"not pem at all", "cert: yes please"},
		{"pem envelope, garbage payload",
			"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"},
		{"whitespace", "   \n\t "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := exportTLSConfig(tc.ca); err == nil {
				t.Fatal("expected an error; an empty pool would reject every peer " +
					"at handshake time and report it as a server problem")
			}
		})
	}
}

func TestBase64DecodingThePublishedFieldIsWrong(t *testing.T) {
	// The upstream field comment calls Cert "the public CA certificate base64
	// encoded", which invites exactly one wrong move: decode it first. The value
	// is PEM, and PEM's armour is what that comment means. Pinned as a test
	// because the resulting error blames the certificate, not the reader — so
	// whoever hits it goes looking in the cluster instead of in this file.
	caPEM := testCAPEM(t)

	if _, err := exportTLSConfig(caPEM); err != nil {
		t.Fatalf("the published PEM must be used as-is: %v", err)
	}

	// Both outcomes are asserted. An earlier version of this test returned early
	// when the decode failed — which is what actually happens, every time, since
	// PEM's header lines and newlines are not valid standard base64. That made the
	// half of the test its name is about unreachable, so it passed while checking
	// nothing: the exact shape this file exists to catch elsewhere.
	decoded, err := base64.StdEncoding.DecodeString(caPEM)
	if err == nil {
		if _, cfgErr := exportTLSConfig(string(decoded)); cfgErr == nil {
			t.Fatal("base64-decoding the field produced something accepted as a CA; " +
				"if that is ever true the guidance in exporttls.go needs revisiting")
		}
		return
	}
	if !strings.Contains(err.Error(), "illegal base64") {
		t.Errorf("expected PEM to be rejected as base64 (it is armoured text, not "+
			"a base64 payload); got a different failure: %v", err)
	}
}
