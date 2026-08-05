// Package sign implements the HTTP handler for the certificate signing command.
package sign

import (
	"net/http"

	"github.com/cloudflare/cfssl/api/signhandler"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/universal"
)

// NewHandler generates a new Handler using the certificate
// authority private key and certficate to sign certificates. If remote
// is not an empty string, the handler will send signature requests to
// the CFSSL instance contained in remote by default. The handler signs
// requests carrying no auth token, so it only serves clients authenticated
// by mutual TLS.
func NewHandler(caFile, caKeyFile string, policy *config.Signing) (http.Handler, error) {
	s, err := newSigner(caFile, caKeyFile, policy)
	if err != nil {
		return nil, err
	}

	return signhandler.NewHandlerFromSigner(s)
}

// NewUnauthenticatedHandler is NewHandler without the mutual TLS
// requirement: it will sign any request it can parse, for any identity, so
// the endpoint must be protected by other means.
func NewUnauthenticatedHandler(caFile, caKeyFile string, policy *config.Signing) (http.Handler, error) {
	s, err := newSigner(caFile, caKeyFile, policy)
	if err != nil {
		return nil, err
	}

	return signhandler.NewUnauthenticatedHandlerFromSigner(s)
}

func newSigner(caFile, caKeyFile string, policy *config.Signing) (signer.Signer, error) {
	root := universal.Root{
		Config: map[string]string{
			"cert-file": caFile,
			"key-file":  caKeyFile,
		},
	}
	s, err := universal.NewSigner(root, policy)
	if err != nil {
		log.Errorf("setting up signer failed: %v", err)
		return nil, err
	}

	return s, nil
}

// NewAuthHandler generates a new AuthHandler using the certificate
// authority private key and certficate to sign certificates. If remote
// is not an empty string, the handler will send signature requests to
// the CFSSL instance contained in remote by default.
func NewAuthHandler(caFile, caKeyFile string, policy *config.Signing) (http.Handler, error) {
	s, err := newSigner(caFile, caKeyFile, policy)
	if err != nil {
		return nil, err
	}

	return signhandler.NewAuthHandlerFromSigner(s)
}
