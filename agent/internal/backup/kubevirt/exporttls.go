package kubevirt

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// No build tag, deliberately. Everything here is pure and has no KubeVirt or
// libvirt dependency, so `go test ./...` covers it in the default build rather
// than only under `-tags kubevirt`. Same reasoning as convert.go in the kubevirt
// provider package. The end-to-end export path cannot be exercised without a
// cluster running KubeVirt; this is the part that can be.

// exportTLSConfig builds the client TLS config for pulling a VMExport.
//
// The root comes from the export resource itself — VirtualMachineExportLink.Cert
// — so the CA that authenticates the download endpoint is delivered alongside the
// URL that names it. The field's upstream comment describes it as "base64
// encoded", which reads as though it needs decoding first; it does not. The value
// is PEM, whose own armour is what that comment refers to, and virtctl passes it
// straight to AppendCertsFromPEM. Decoding it first yields bytes that parse as
// nothing, and the resulting error blames the certificate rather than the reader.
//
// This fails closed. There is no escape hatch and no fallback to the system pool,
// because the CA arrives in the same object as the URL: an export that is Ready
// but carries no usable certificate is not a case to be tolerated, it is a case to
// be reported. Falling back to the system roots would be worse than either — it
// silently swaps the trust anchor for one that cannot vouch for an in-cluster
// endpoint, which is the failure ClientTLSConfig was fixed for.
func exportTLSConfig(caPEM string) (*tls.Config, error) {
	if caPEM == "" {
		return nil, fmt.Errorf("export link carries no CA certificate; refusing to " +
			"pull backup data over an unverified connection")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, fmt.Errorf("export CA certificate contains no usable certificate "+
			"(%d bytes); it is PEM as published and must not be base64-decoded first",
			len(caPEM))
	}

	return &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}, nil
}
