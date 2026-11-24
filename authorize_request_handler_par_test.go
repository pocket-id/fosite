// Copyright © 2026 Pocket ID
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	. "github.com/pocket-id/fosite"
	"github.com/pocket-id/fosite/storage"
)

func TestNewAuthorizeRequestRefusesPushedRequestWhoseRedirectURIWasRemoved(t *testing.T) {
	const requestURI = "urn:ietf:params:oauth:request_uri:pushed"
	client := &DefaultClient{ID: "client", RedirectURIs: []string{"https://client.example/kept"}}
	store := storage.NewMemoryStore()
	provider := &Fosite{Store: store, Config: &Config{}}

	for redirectURI, expected := range map[string]error{
		"https://client.example/kept":    nil,
		"https://client.example/removed": ErrInvalidRequest,
	} {
		// The request was pushed while the client still listed the redirect URI
		pushed := NewAuthorizeRequest()
		pushed.Client = client
		pushed.RedirectURI, _ = url.Parse(redirectURI)
		require.NoError(t, store.CreatePARSession(t.Context(), requestURI, pushed))

		r := &http.Request{Form: url.Values{"client_id": {client.ID}, "request_uri": {requestURI}}}
		_, err := provider.NewAuthorizeRequest(t.Context(), r)
		require.ErrorIs(t, err, expected)
	}
}
