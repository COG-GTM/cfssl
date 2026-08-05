package signhandler

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

const (
	testCaFile    = "../testdata/ca.pem"
	testCaKeyFile = "../testdata/ca_key.pem"
	testCSRFile   = "../testdata/csr.pem"
)

// GetUnexpiredCertificates sometimes doesn't return a certificate with an
// expiry of 1m as above
var validLocalConfigLongerExpiry = `
{
	"signing": {
		"default": {
		    "usages": ["digital signature", "email protection"],
			"expiry": "10m"
		}
	}
}`

var dbAccessor certdb.Accessor

func TestSignerDBPersistence(t *testing.T) {
	conf, err := config.LoadConfig([]byte(validLocalConfigLongerExpiry))
	if err != nil {
		t.Fatal(err)
	}

	var s *local.Signer
	s, err = local.NewSignerFromFile(testCaFile, testCaKeyFile, conf.Signing)
	if err != nil {
		t.Fatal(err)
	}

	db := testdb.SQLiteDB("../../certdb/testdb/certstore_development.db")
	if err != nil {
		t.Fatal(err)
	}

	dbAccessor = sql.NewAccessor(db)
	s.SetDBAccessor(dbAccessor)

	var handler *api.HTTPHandler
	handler, err = NewUnauthenticatedHandlerFromSigner(signer.Signer(s))
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(handler)
	defer ts.Close()

	var csrPEM, body []byte
	csrPEM, err = os.ReadFile(testCSRFile)
	if err != nil {
		t.Fatal(err)
	}

	blob, err := json.Marshal(&map[string]string{"certificate_request": string(csrPEM)})
	if err != nil {
		t.Fatal(err)
	}

	var resp *http.Response
	resp, err = http.Post(ts.URL, "application/json", bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.Status, string(body))
	}

	message := new(api.Response)
	err = json.Unmarshal(body, message)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if !message.Success {
		t.Fatal("API operation failed")
	}

	crs, err := dbAccessor.GetUnexpiredCertificates()
	if err != nil {
		t.Fatal("Failed to get unexpired certificates")
	}

	if len(crs) != 1 {
		t.Fatal("Expected 1 unexpired certificate in the database after signing 1: len(crs)=", len(crs))
	}
}

// The default handler has no auth provider of its own, so it must refuse to
// sign requests that were not authenticated by mutual TLS.
func TestSignRejectsUnauthenticatedRequest(t *testing.T) {
	conf, err := config.LoadConfig([]byte(validLocalConfigLongerExpiry))
	if err != nil {
		t.Fatal(err)
	}

	s, err := local.NewSignerFromFile(testCaFile, testCaKeyFile, conf.Signing)
	if err != nil {
		t.Fatal(err)
	}

	handler, err := NewHandlerFromSigner(signer.Signer(s))
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(handler)
	defer ts.Close()

	csrPEM, err := os.ReadFile(testCSRFile)
	if err != nil {
		t.Fatal(err)
	}

	blob, err := json.Marshal(&map[string]interface{}{
		"certificate_request": string(csrPEM),
		"hosts":               []string{"attacker.example.net"},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected the request to be rejected, got %s: %s", resp.Status, string(body))
	}

	if bytes.Contains(body, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("unauthenticated request was issued a certificate")
	}
}

// Clients authenticated by the server's mutual TLS configuration are served by
// the default handler.
func TestSignAcceptsMutualTLSRequest(t *testing.T) {
	conf, err := config.LoadConfig([]byte(validLocalConfigLongerExpiry))
	if err != nil {
		t.Fatal(err)
	}

	s, err := local.NewSignerFromFile(testCaFile, testCaKeyFile, conf.Signing)
	if err != nil {
		t.Fatal(err)
	}

	handler, err := NewHandlerFromSigner(signer.Signer(s))
	if err != nil {
		t.Fatal(err)
	}

	clientCA, clientCert := selfSignedClientCert(t)

	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCA,
	}
	ts.StartTLS()
	defer ts.Close()

	client := ts.Client()
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig.Certificates = []tls.Certificate{clientCert}

	csrPEM, err := os.ReadFile(testCSRFile)
	if err != nil {
		t.Fatal(err)
	}

	blob, err := json.Marshal(&map[string]string{"certificate_request": string(csrPEM)})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Post(ts.URL, "application/json", bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected the request to be signed, got %s: %s", resp.Status, string(body))
	}
}

// selfSignedClientCert returns a certificate pool holding a freshly generated
// CA, along with a client certificate issued by it.
func selfSignedClientCert(t *testing.T) (*x509.CertPool, tls.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test client"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return pool, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
}
