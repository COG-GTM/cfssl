package serve

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/signer/local"
)

func TestServe(t *testing.T) {
	registerHandlers()
	ts := httptest.NewServer(http.DefaultServeMux)
	defer ts.Close()
	expected := make(map[string]int)
	for endpoint := range endpoints {
		expected[v1APIPath(endpoint)] = http.StatusOK
	}

	// Disabled endpoints should return '404 Not Found'
	expected[v1APIPath("sign")] = http.StatusNotFound
	expected[v1APIPath("authsign")] = http.StatusNotFound
	expected[v1APIPath("newcert")] = http.StatusNotFound
	expected[v1APIPath("info")] = http.StatusNotFound
	expected[v1APIPath("ocspsign")] = http.StatusNotFound
	expected[v1APIPath("crl")] = http.StatusNotFound
	expected[v1APIPath("gencrl")] = http.StatusNotFound
	expected[v1APIPath("revoke")] = http.StatusNotFound

	// Enabled endpoints should return '405 Method Not Allowed'
	expected[v1APIPath("init_ca")] = http.StatusMethodNotAllowed
	expected[v1APIPath("newkey")] = http.StatusMethodNotAllowed
	expected[v1APIPath("bundle")] = http.StatusMethodNotAllowed
	expected[v1APIPath("certinfo")] = http.StatusMethodNotAllowed
	expected[v1APIPath("certadd")] = http.StatusMethodNotAllowed

	// POST-only endpoints should return '400 Bad Request'
	expected[v1APIPath("scan")] = http.StatusBadRequest

	// Redirected HTML endpoints should return '200 OK'
	expected["/scan"] = http.StatusOK
	expected["/bundle"] = http.StatusOK

	// Non-existent endpoints should return '404 Not Found'
	expected["/bad_endpoint"] = http.StatusNotFound

	for endpoint, status := range expected {
		resp, err := http.Get(ts.URL + endpoint)
		if err != nil {
			t.Error(err)
		}
		if resp.StatusCode != status {
			t.Fatalf("%s: '%s' (expected '%s')", endpoint, resp.Status, http.StatusText(status))
		}
	}

	var c cli.Config
	var test = []string{"test"}
	if err := serverMain(test, c); err == nil {
		t.Fatalf("There should be an error for argument")
	}
}

func TestSignEndpointRequiresAuthentication(t *testing.T) {
	oldConf, oldSigner := conf, s
	defer func() { conf, s = oldConf, oldSigner }()

	var err error
	s, err = local.NewSignerFromFile("../../api/testdata/ca.pem", "../../api/testdata/ca_key.pem", nil)
	if err != nil {
		t.Fatal(err)
	}

	conf = cli.Config{}
	if _, err := endpoints["sign"](); err != errUnauthenticatedSign {
		t.Fatalf("sign endpoint should fail closed without authentication, got %v", err)
	}

	conf = cli.Config{TLSCertFile: "cert.pem", TLSKeyFile: "key.pem", MutualTLSCAFile: "ca.pem"}
	if _, err := endpoints["sign"](); err != nil {
		t.Fatalf("sign endpoint should be served under mutual TLS: %v", err)
	}

	conf = cli.Config{AllowUnauthenticatedSign: true}
	if _, err := endpoints["sign"](); err != nil {
		t.Fatalf("sign endpoint should be served when unauthenticated signing is allowed: %v", err)
	}
}
