package certinfo

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsPublicIP(t *testing.T) {
	cases := []struct {
		ip     string
		public bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"2606:4700:4700::1111", true},
		{"127.0.0.1", false},
		{"127.16.0.1", false},
		{"0.0.0.0", false},
		{"10.0.0.5", false},
		{"172.16.5.4", false},
		{"172.31.255.255", false},
		{"192.168.1.1", false},
		{"169.254.169.254", false},
		{"100.64.0.1", false},
		{"192.0.0.1", false},
		{"192.0.2.1", false},
		{"192.88.99.1", false},
		{"198.18.0.1", false},
		{"198.51.100.1", false},
		{"203.0.113.1", false},
		{"240.0.0.1", false},
		{"255.255.255.255", false},
		{"::", false},
		{"::1", false},
		{"::ffff:10.0.0.5", false},
		{"::ffff:127.0.0.1", false},
		{"64:ff9b::10.0.0.5", false},
		{"64:ff9b::8.8.8.8", true},
		{"fc00::1", false},
		{"fd00::1", false},
		{"fe80::1", false},
		{"ff02::1", false},
		{"100::1", false},
		{"2001::1", false},
		{"2001:db8::1", false},
		{"2002::1", false},
	}

	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("could not parse test address %s", c.ip)
		}

		if got := isPublicIP(ip); got != c.public {
			t.Errorf("isPublicIP(%s) = %v, want %v", c.ip, got, c.public)
		}
	}
}

func TestPublicAddressOnly(t *testing.T) {
	if err := publicAddressOnly("tcp", "8.8.8.8:443", nil); err != nil {
		t.Errorf("public address rejected: %v", err)
	}

	if err := publicAddressOnly("tcp", "127.0.0.1:8443", nil); err == nil {
		t.Error("loopback address accepted")
	}

	if err := publicAddressOnly("unix", "/var/run/socket", nil); err == nil {
		t.Error("non-tcp network accepted")
	}

	if err := publicAddressOnly("tcp", "example.com:443", nil); err == nil {
		t.Error("unresolved address accepted")
	}
}

// TestParseCertificateDomainRejectsInternalHost checks that the SSRF guard
// covers the whole dial path: a TLS server on the loopback interface must be
// unreachable through ParseCertificateDomain, both by IP literal and through a
// name that resolves to it, while the unrestricted variant still reaches it.
func TestParseCertificateDomainRejectsInternalHost(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	addr := strings.TrimPrefix(server.URL, "https://")
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("unexpected test server address %s: %v", addr, err)
	}

	for _, domain := range []string{addr, net.JoinHostPort("localhost", port)} {
		cert, err := ParseCertificateDomain(domain)
		if err == nil {
			t.Fatalf("ParseCertificateDomain(%s) reached an internal service and returned %v", domain, cert)
		}

		if !strings.Contains(err.Error(), "refusing to dial") {
			t.Errorf("ParseCertificateDomain(%s) failed with an unexpected error: %v", domain, err)
		}
	}

	cert, err := ParseCertificateDomainUnrestricted(addr)
	if err != nil {
		t.Fatalf("ParseCertificateDomainUnrestricted(%s) failed: %v", addr, err)
	}

	if cert.RawPEM == "" {
		t.Error("no certificate returned by ParseCertificateDomainUnrestricted")
	}
}

// TestParseCertificateDomainDefaultPort makes sure the guard also applies when
// the domain carries no port and the default TLS port is appended.
func TestParseCertificateDomainDefaultPort(t *testing.T) {
	if _, err := ParseCertificateDomain("localhost"); err == nil {
		t.Error("ParseCertificateDomain(localhost) was allowed to dial")
	} else if !strings.Contains(err.Error(), "refusing to dial") {
		t.Errorf("unexpected error: %v", err)
	}
}
