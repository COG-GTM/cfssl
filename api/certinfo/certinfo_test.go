package certinfo

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandleDomainRejectsInternalHost checks that the unauthenticated certinfo
// endpoint cannot be used to make the server dial an internal service and
// disclose its certificate.
func TestHandleDomainRejectsInternalHost(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	internal := strings.TrimPrefix(target.URL, "https://")
	_, port, err := net.SplitHostPort(internal)
	if err != nil {
		t.Fatalf("unexpected test server address %s: %v", internal, err)
	}

	handler := NewHandler()

	for _, domain := range []string{internal, net.JoinHostPort("localhost", port)} {
		body, err := json.Marshal(map[string]string{"domain": domain})
		if err != nil {
			t.Fatalf("could not encode request: %v", err)
		}

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/cfssl/certinfo", bytes.NewReader(body)))

		if w.Code == http.StatusOK {
			t.Fatalf("certinfo handler fetched the certificate of internal host %s: %s", domain, w.Body.String())
		}

		if bytes.Contains(w.Body.Bytes(), []byte("BEGIN CERTIFICATE")) {
			t.Fatalf("certinfo handler leaked the certificate of internal host %s", domain)
		}
	}
}
