package generator

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/auth"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/signer/local"
)

const (
	testCaFile    = "testdata/ca.pem"
	testCaKeyFile = "testdata/ca_key.pem"
	testCABundle  = "../../bundler/testdata/ca-bundle.pem"
	testIntBundle = "../../bundler/testdata/int-bundle.pem"
)

func csrData(t *testing.T) *bytes.Reader {
	req := &csr.CertificateRequest{
		Names: []csr.Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		CN:         "cloudflare.com",
		Hosts:      []string{"cloudflare.com"},
		KeyRequest: csr.NewKeyRequest(),
	}
	csrBytes, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(csrBytes)
}

func TestGeneratorRESTfulVerbs(t *testing.T) {
	handler, _ := NewHandler(CSRValidate)
	ts := httptest.NewServer(handler)
	data := csrData(t)
	// POST should work.
	req, _ := http.NewRequest("POST", ts.URL, data)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.Status)
	}

	// Test GET, PUT, DELETE and whatever, expect 400 errors.
	req, _ = http.NewRequest("GET", ts.URL, data)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal(resp.Status)
	}
	req, _ = http.NewRequest("PUT", ts.URL, data)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal(resp.Status)
	}
	req, _ = http.NewRequest("DELETE", ts.URL, data)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal(resp.Status)
	}
	req, _ = http.NewRequest("WHATEVER", ts.URL, data)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal(resp.Status)
	}
}

func TestCSRValidate(t *testing.T) {
	req := &csr.CertificateRequest{
		Names: []csr.Name{
			{
				C:  "US",
				ST: "California",
				L:  "San Francisco",
				O:  "CloudFlare",
				OU: "Systems Engineering",
			},
		},
		CN:         "cloudflare.com",
		Hosts:      []string{},
		KeyRequest: csr.NewKeyRequest(),
	}
	err := CSRValidate(req)
	if err != nil {
		t.Fatal("There should be not an error for missing Hosts parameter")
	}
}

func TestNewCertGeneratorHandlerFromSigner(t *testing.T) {
	var expiry = 1 * time.Minute
	var CAConfig = &config.Config{
		Signing: &config.Signing{
			Profiles: map[string]*config.SigningProfile{
				"signature": {
					Usage:  []string{"digital signature"},
					Expiry: expiry,
				},
			},
			Default: &config.SigningProfile{
				Usage:        []string{"cert sign", "crl sign"},
				ExpiryString: "43800h",
				Expiry:       expiry,
				CAConstraint: config.CAConstraint{IsCA: true},

				ClientProvidesSerialNumbers: true,
			},
		},
	}
	s, err := local.NewSignerFromFile(testCaFile, testCaKeyFile, CAConfig.Signing)
	if err != nil {
		t.Fatal(err)
	}

	h := NewCertGeneratorHandlerFromSigner(CSRValidate, s)
	_, ok := h.(http.Handler)
	if !ok {
		t.Fatal("A HTTP handler has not been returned")
	}

	apiH, ok := h.(api.HTTPHandler)
	if !ok {
		t.Fatal("An api.HTTPHandler has not been returned")
	}

	cg, ok := apiH.Handler.(*CertGeneratorHandler)
	if !ok {
		t.Fatal("A CertGeneratorHandler has not been set")
	}

	if err := cg.SetBundler(testCABundle, testIntBundle); err != nil {
		t.Fatal(err)
	}
}

func TestCertGeneratorHandlerRejectsAuthProfiles(t *testing.T) {
	provider, err := auth.New("0123456789ABCDEF0123456789ABCDEF", nil)
	if err != nil {
		t.Fatal(err)
	}

	var expiry = 1 * time.Minute
	policy := &config.Signing{
		Profiles: map[string]*config.SigningProfile{
			"authed": {
				Usage:    []string{"digital signature"},
				Expiry:   expiry,
				Provider: provider,
			},
		},
		Default: &config.SigningProfile{
			Usage:  []string{"server auth"},
			Expiry: expiry,
		},
	}
	s, err := local.NewSignerFromFile(testCaFile, testCaKeyFile, policy)
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(NewCertGeneratorHandlerFromSigner(CSRValidate, s))
	defer ts.Close()

	newCertBody := func(profile string) *bytes.Reader {
		req := map[string]interface{}{
			"request": &csr.CertificateRequest{
				CN:         "cloudflare.com",
				Hosts:      []string{"cloudflare.com"},
				KeyRequest: csr.NewKeyRequest(),
			},
			"profile": profile,
		}
		body, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		return bytes.NewReader(body)
	}

	resp, err := http.Post(ts.URL, "application/json", newCertBody("authed"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected %d for auth-required profile, got %d: %s",
			http.StatusBadRequest, resp.StatusCode, body)
	}
	if bytes.Contains(body, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("a certificate was issued for a profile that requires authentication")
	}

	resp, err = http.Post(ts.URL, "application/json", newCertBody(""))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d for unauthenticated profile, got %d",
			http.StatusOK, resp.StatusCode)
	}
}
