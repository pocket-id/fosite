// Copyright © 2026 Pocket ID
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/pocket-id/fosite"
	"github.com/pocket-id/fosite/storage"
)

const parTestRequestURI = "urn:ietf:params:oauth:request_uri:pushed"

// pushedRequest stores a pushed authorization request with the client as it was when the request was pushed.
func pushedRequest(t *testing.T, store *storage.MemoryStore, pushedClient Client, redirectURI string, scope, responseTypes []string) {
	t.Helper()

	pushed := NewAuthorizeRequest()
	pushed.Client = pushedClient
	pushed.RedirectURI, _ = url.Parse(redirectURI)
	pushed.RequestedScope = scope
	pushed.ResponseTypes = responseTypes
	pushed.Form = url.Values{"response_type": {strings.Join(responseTypes, " ")}}
	require.NoError(t, store.CreatePARSession(t.Context(), parTestRequestURI, pushed))
}

// A pushed authorization request is stored with the client as it was when it was pushed. When it is used, it is
// checked against the client as it is now: the redirect URI, the scopes, the response types and the client's existence.
func TestNewAuthorizeRequestChecksPushedRequestAgainstTheCurrentClient(t *testing.T) {
	pushedClient := &DefaultClient{
		ID:            "client",
		RedirectURIs:  []string{"https://client.example/kept", "https://client.example/removed"},
		Scopes:        []string{"read", "write"},
		ResponseTypes: []string{"code", "token"},
	}

	for _, tc := range []struct {
		name          string
		current       Client // nil: the client was deleted
		redirectURI   string
		scope         []string
		responseTypes []string
		expected      error
	}{
		{
			name:          "unchanged client",
			current:       &DefaultClient{ID: "client", RedirectURIs: []string{"https://client.example/kept", "https://client.example/removed"}, Scopes: []string{"read", "write"}, ResponseTypes: []string{"code", "token"}},
			redirectURI:   "https://client.example/removed",
			scope:         []string{"read", "write"},
			responseTypes: []string{"code"},
		},
		{
			name:          "the redirect URI was removed",
			current:       &DefaultClient{ID: "client", RedirectURIs: []string{"https://client.example/kept"}, Scopes: []string{"read", "write"}, ResponseTypes: []string{"code", "token"}},
			redirectURI:   "https://client.example/removed",
			scope:         []string{"read"},
			responseTypes: []string{"code"},
			expected:      ErrInvalidRequest,
		},
		{
			name:          "a scope was removed",
			current:       &DefaultClient{ID: "client", RedirectURIs: []string{"https://client.example/kept"}, Scopes: []string{"read"}, ResponseTypes: []string{"code", "token"}},
			redirectURI:   "https://client.example/kept",
			scope:         []string{"read", "write"},
			responseTypes: []string{"code"},
			expected:      ErrInvalidScope,
		},
		{
			name:          "a response type was removed",
			current:       &DefaultClient{ID: "client", RedirectURIs: []string{"https://client.example/kept"}, Scopes: []string{"read"}, ResponseTypes: []string{"code"}},
			redirectURI:   "https://client.example/kept",
			scope:         []string{"read"},
			responseTypes: []string{"token"},
			expected:      ErrUnsupportedResponseType,
		},
		{
			name:          "the client was deleted",
			redirectURI:   "https://client.example/kept",
			scope:         []string{"read"},
			responseTypes: []string{"code"},
			expected:      ErrInvalidClient,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()
			if tc.current != nil {
				store.Clients[pushedClient.ID] = tc.current
			}
			provider := &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy}}
			pushedRequest(t, store, pushedClient, tc.redirectURI, tc.scope, tc.responseTypes)

			r := &http.Request{Form: url.Values{"client_id": {pushedClient.ID}, "request_uri": {parTestRequestURI}}}
			_, err := provider.NewAuthorizeRequest(t.Context(), r)
			if tc.expected == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.expected)
			}
		})
	}
}

// RFC 6749 4.1.2.1: when the client is invalid, or the pushed request is refused, the error is not redirected to the
// redirect URI the request was pushed with, which belongs to the client as it was then.
func TestNewAuthorizeRequestNeverRedirectsAPushedRequestError(t *testing.T) {
	pushedClient := &DefaultClient{
		ID:            "client",
		RedirectURIs:  []string{"https://client.example/dropped"},
		Scopes:        []string{"read"},
		ResponseTypes: []string{"code"},
	}
	otherClient := &DefaultClient{ID: "other", RedirectURIs: []string{"https://other.example/cb"}, Scopes: []string{"read"}, ResponseTypes: []string{"code"}}

	for _, tc := range []struct {
		name     string
		clientID string // the client_id of the request that uses the pushed request
		current  map[string]Client
	}{
		{name: "the client was deleted", clientID: "client", current: map[string]Client{}},
		{name: "another client uses the pushed request", clientID: "other", current: map[string]Client{
			"client": &DefaultClient{ID: "client", RedirectURIs: []string{"https://client.example/new"}, Scopes: []string{"read"}, ResponseTypes: []string{"code"}},
			"other":  otherClient,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStore()
			for id, client := range tc.current {
				store.Clients[id] = client
			}
			provider := &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy}}
			pushedRequest(t, store, pushedClient, "https://client.example/dropped", []string{"read"}, []string{"code"})

			r := &http.Request{Form: url.Values{"client_id": {tc.clientID}, "request_uri": {parTestRequestURI}}}
			ar, err := provider.NewAuthorizeRequest(t.Context(), r)
			require.Error(t, err)
			require.False(t, ar.IsRedirectURIValid())

			rw := httptest.NewRecorder()
			provider.WriteAuthorizeError(t.Context(), rw, ar, err)
			assert.Empty(t, rw.Header().Get("Location"))
			assert.GreaterOrEqual(t, rw.Code, 400)
		})
	}
}
