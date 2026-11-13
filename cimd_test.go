// Copyright © 2026 Pocket ID
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLooksLikeCIMDURL(t *testing.T) {
	cases := map[string]bool{
		"https://app.example.com/oauth/client": true,
		"https://app.example.com/c":            true,
		"my-app":                               false,
		"client-1234":                          false,
		"http://app.example.com/oauth/client":  false,
		"":                                     false,
	}
	for in, want := range cases {
		assert.Equalf(t, want, LooksLikeCIMDURL(in), "input %q", in)
	}
}

func TestValidateCIMDURL(t *testing.T) {
	valid := []string{
		"https://app.example.com/oauth/client",
		// Section 3 explicitly permits a port, and states that a URL carrying the default port is
		// NOT equivalent to one without it, so both forms are valid and distinct identifiers.
		"https://app.example.com:8443/oauth/client",
		"https://app.example.com:443/oauth/client",
	}
	for _, in := range valid {
		u, err := url.Parse(in)
		require.NoError(t, err)
		assert.NoErrorf(t, ValidateCIMDURL(u), "input %q", in)
	}

	invalid := []string{
		// Section 3: a Client Identifier URL SHOULD NOT contain a query component.
		"https://app.example.com/oauth?foo=bar",
		"http://app.example.com/oauth/client",
		"https://app.example.com",
		"https://app.example.com/",
		"https://app.example.com/a/../b",
		"https://app.example.com/./a",
		"https://app.example.com/oauth#frag",
		"https://user:pass@app.example.com/oauth",
	}
	for _, in := range invalid {
		u, err := url.Parse(in)
		require.NoError(t, err)
		assert.Errorf(t, ValidateCIMDURL(u), "input %q", in)
	}
}

func TestClientMetadataDocument_Validate(t *testing.T) {
	const id = "https://app.example.com/oauth/client"

	// valid returns a minimally conformant document that callers mutate per subtest.
	valid := func() *ClientMetadataDocument {
		return &ClientMetadataDocument{
			ClientID:                id,
			RedirectURIs:            []string{"https://app.example.com/callback"},
			TokenEndpointAuthMethod: "none",
		}
	}

	t.Run("matching client_id passes", func(t *testing.T) {
		require.NoError(t, valid().Validate(id))
	})

	t.Run("client_id mismatch is rejected", func(t *testing.T) {
		doc := valid()
		doc.ClientID = "https://evil.example.com/c"
		require.ErrorIs(t, doc.Validate(id), ErrCIMDClientIDMismatch)
	})

	// An error page served as JSON has no client_id, and must not count as the client giving up its URL
	t.Run("missing client_id is malformed and not a mismatch", func(t *testing.T) {
		doc := valid()
		doc.ClientID = ""
		err := doc.Validate(id)
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrCIMDClientIDMismatch)
	})

	t.Run("explicitly empty grant_types and response_types are rejected", func(t *testing.T) {
		for _, list := range []string{"grant_types", "response_types"} {
			var doc ClientMetadataDocument
			require.NoError(t, json.Unmarshal([]byte(`{"client_id":"`+id+`","redirect_uris":["https://app.example.com/callback"],"`+list+`":[]}`), &doc))
			require.ErrorContains(t, doc.Validate(id), "empty", list)
		}
	})

	t.Run("client secret is rejected", func(t *testing.T) {
		secret := "shh"
		doc := valid()
		doc.ClientSecret = &secret
		require.Error(t, doc.Validate(id))

		exp := int64(0)
		doc2 := valid()
		doc2.ClientSecretExpiresAt = &exp
		require.Error(t, doc2.Validate(id))
	})

	t.Run("symmetric authentication is rejected", func(t *testing.T) {
		for _, method := range []string{"client_secret_basic", "client_secret_post", "client_secret_jwt"} {
			doc := valid()
			doc.TokenEndpointAuthMethod = method
			require.Error(t, doc.Validate(id))

			listed := valid()
			listed.TokenEndpointAuthMethodsSupported = []string{"none", method}
			require.Error(t, listed.Validate(id))
		}
	})

	t.Run("omitted authentication method is not the RFC 7591 default", func(t *testing.T) {
		doc := valid()
		doc.TokenEndpointAuthMethod = ""
		require.NoError(t, doc.Validate(id))
		assert.Equal(t, []string{"none"}, doc.TokenEndpointAuthMethods())
	})

	t.Run("private key material is rejected", func(t *testing.T) {
		doc := valid()
		doc.JWKS = &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: []byte("symmetric-secret")}}}
		require.Error(t, doc.Validate(id))
	})

	t.Run("private key authentication requires keys", func(t *testing.T) {
		doc := valid()
		doc.TokenEndpointAuthMethod = "private_key_jwt"
		require.Error(t, doc.Validate(id))

		listed := valid()
		listed.TokenEndpointAuthMethodsSupported = []string{"none", "private_key_jwt"}
		require.Error(t, listed.Validate(id))
	})

	// Section 4.2 requires registration of redirect URLs for redirect-based grants.
	t.Run("redirect-based grants require redirect_uris", func(t *testing.T) {
		doc := valid()
		doc.RedirectURIs = nil
		require.Error(t, doc.Validate(id), "authorization_code is the RFC 7591 default grant type")

		doc2 := valid()
		doc2.RedirectURIs = nil
		doc2.GrantTypes = []string{"implicit"}
		doc2.ResponseTypes = []string{"token"}
		require.Error(t, doc2.Validate(id))
	})

	t.Run("non-redirect grants do not require redirect_uris", func(t *testing.T) {
		doc := valid()
		doc.RedirectURIs = nil
		doc.GrantTypes = []string{"client_credentials"}
		require.NoError(t, doc.Validate(id))
	})

	t.Run("malformed redirect_uris are rejected", func(t *testing.T) {
		for _, uri := range []string{"/relative/cb", "https://app.example.com/cb#frag", "not a url at all"} {
			doc := valid()
			doc.RedirectURIs = []string{uri}
			require.Errorf(t, doc.Validate(id), "redirect_uri %q", uri)
		}
	})
}

func TestClientMetadataDocument_TokenEndpointAuthMethods(t *testing.T) {
	listed := &ClientMetadataDocument{TokenEndpointAuthMethod: "private_key_jwt", TokenEndpointAuthMethodsSupported: []string{"none", "private_key_jwt"}}
	assert.Equal(t, []string{"none", "private_key_jwt"}, listed.TokenEndpointAuthMethods())

	legacy := &ClientMetadataDocument{TokenEndpointAuthMethod: "private_key_jwt"}
	assert.Equal(t, []string{"private_key_jwt"}, legacy.TokenEndpointAuthMethods())

	// A list that is present but empty declares no method, so the legacy field must not fill in for it
	var empty ClientMetadataDocument
	require.NoError(t, json.Unmarshal([]byte(`{"token_endpoint_auth_method":"none","token_endpoint_auth_methods_supported":[]}`), &empty))
	assert.Empty(t, empty.TokenEndpointAuthMethods())
}

func TestClientMetadataDocument_UnmarshalJSON(t *testing.T) {
	var doc ClientMetadataDocument
	require.NoError(t, json.Unmarshal([]byte(`{
		"client_id":"https://app.example.com/oauth/client",
		"client_name":"Example",
		"custom_metadata":{"enabled":true}
	}`), &doc))

	assert.Equal(t, "Example", doc.ClientName)
	assert.JSONEq(t, `{"enabled":true}`, string(doc.AdditionalMetadata["custom_metadata"]))
}

func TestNewCIMDClient(t *testing.T) {
	const id = "https://app.example.com/oauth/client"
	doc := &ClientMetadataDocument{
		ClientID:                      id,
		RedirectURIs:                  []string{"https://app.example.com/callback"},
		GrantTypes:                    []string{"authorization_code"},
		ResponseTypes:                 []string{"code"},
		Scope:                         "openid profile",
		TokenEndpointAuthMethod:       "private_key_jwt",
		TokenEndpointAuthSigningAlg:   "ES256",
		JWKSURI:                       "https://app.example.com/jwks.json",
		RequestURIs:                   []string{"https://app.example.com/request.jwt"},
		RequestObjectSigningAlgorithm: "ES256",
	}

	client, err := NewCIMDClient(doc)
	require.NoError(t, err)
	assert.Equal(t, id, client.GetID())
	assert.Equal(t, []string{"https://app.example.com/callback"}, client.GetRedirectURIs())
	assert.Equal(t, Arguments{"authorization_code"}, client.GetGrantTypes())
	assert.Equal(t, Arguments{"code"}, client.GetResponseTypes())
	assert.Equal(t, Arguments{"openid", "profile"}, client.GetScopes())
	assert.Equal(t, "private_key_jwt", client.GetTokenEndpointAuthMethod())
	assert.Equal(t, "ES256", client.GetTokenEndpointAuthSigningAlgorithm())
	assert.Equal(t, "https://app.example.com/jwks.json", client.GetJSONWebKeysURI())
	assert.False(t, client.IsPublic())
	assert.Same(t, doc, client.GetClientMetadataDocument())

	defaultedDoc := &ClientMetadataDocument{ClientID: id, RedirectURIs: []string{"https://app.example.com/callback"}, TokenEndpointAuthMethod: "none"}
	defaulted, err := NewCIMDClient(defaultedDoc)
	require.NoError(t, err)
	assert.Equal(t, []string{"authorization_code"}, defaulted.GrantTypes)
	assert.Equal(t, []string{"code"}, defaulted.ResponseTypes)

	t.Run("a declared private_key_jwt is required over none", func(t *testing.T) {
		client, err := NewCIMDClient(&ClientMetadataDocument{
			ClientID:                          id,
			RedirectURIs:                      []string{"https://app.example.com/callback"},
			TokenEndpointAuthMethodsSupported: []string{"none", "private_key_jwt"},
			JWKSURI:                           "https://app.example.com/jwks.json",
		})
		require.NoError(t, err)
		assert.Equal(t, "private_key_jwt", client.GetTokenEndpointAuthMethod())
		assert.False(t, client.IsPublic())
	})

	t.Run("unsupported methods next to none are ignored", func(t *testing.T) {
		client, err := NewCIMDClient(&ClientMetadataDocument{
			ClientID:                          id,
			RedirectURIs:                      []string{"https://app.example.com/callback"},
			TokenEndpointAuthMethod:           "tls_client_auth",
			TokenEndpointAuthMethodsSupported: []string{"tls_client_auth", "none"},
		})
		require.NoError(t, err)
		assert.Equal(t, "none", client.GetTokenEndpointAuthMethod())
		assert.True(t, client.IsPublic())
	})

	t.Run("a document without a supported method is rejected", func(t *testing.T) {
		_, err := NewCIMDClient(&ClientMetadataDocument{
			ClientID:                id,
			RedirectURIs:            []string{"https://app.example.com/callback"},
			TokenEndpointAuthMethod: "tls_client_auth",
		})
		require.Error(t, err)
	})
}

func TestCIMDClient_FetchCIMDReferencedURL(t *testing.T) {
	doc := &ClientMetadataDocument{
		ClientID:                "https://app.example.com/oauth/client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		TokenEndpointAuthMethod: "none",
		RequestURIs:             []string{"https://app.example.com/req.jwt"},
	}
	client, err := NewCIMDClient(doc)
	require.NoError(t, err)

	t.Run("without a guarded client it refuses", func(t *testing.T) {
		_, err := client.FetchCIMDReferencedURL(t.Context(), "https://app.example.com/req.jwt")
		require.Error(t, err)
	})

	t.Run("special-use targets are refused once guarded", func(t *testing.T) {
		guarded, err := NewCIMDClient(doc)
		require.NoError(t, err)
		require.NoError(t, guarded.configureSecureHTTPClient(NewDefaultCIMDFetcher(), nil))

		for _, target := range []string{"https://127.0.0.1/req.jwt", "https://169.254.169.254/latest/meta-data"} {
			_, err := guarded.FetchCIMDReferencedURL(t.Context(), target)
			require.Errorf(t, err, "target %q must not be fetched", target)
		}
	})
}

func TestCIMDClient_RejectsOversizedJWKS(t *testing.T) {
	const jwksURI = "https://keys.example.com/jwks.json"
	doc := &ClientMetadataDocument{
		ClientID:                "https://app.example.com/oauth/client",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKSURI:                 jwksURI,
	}
	client, err := NewCIMDClient(doc)
	require.NoError(t, err)
	fetcher := NewDefaultCIMDFetcher(
		WithCIMDTransport(&cimdMockRoundTripper{responses: map[string]*http.Response{
			jwksURI: cimdMockResponse(http.StatusOK, `{"keys":[],"padding":"`+strings.Repeat("a", DefaultCIMDReferencedURLMaxSize)+`"}`),
		}}),
		WithCIMDAllowPrivateIPs(true),
	)
	resolver := &CIMDResolver{Fetcher: fetcher}
	_, err = resolver.configureClient(client)
	require.NoError(t, err)

	_, err = client.ResolveCIMDJSONWebKeys(t.Context(), false)
	require.Error(t, err)
}

func TestCIMDClient_SharesJWKSFetcherAcrossClients(t *testing.T) {
	fetcher := NewDefaultCIMDFetcher(WithCIMDAllowPrivateIPs(true))
	resolver := &CIMDResolver{Fetcher: fetcher}
	require.Nil(t, resolver.jwksFetcher)

	newClient := func(id string) *CIMDClient {
		client, err := NewCIMDClient(&ClientMetadataDocument{
			ClientID:                id,
			RedirectURIs:            []string{"https://app.example.com/callback"},
			TokenEndpointAuthMethod: "private_key_jwt",
			JWKSURI:                 "https://keys.example.com/jwks.json",
		})
		require.NoError(t, err)
		_, err = resolver.configureClient(client)
		require.NoError(t, err)
		return client
	}

	first := newClient("https://app.example.com/oauth/first")
	second := newClient("https://app.example.com/oauth/second")
	require.NotNil(t, first.jwksFetcher)
	assert.Same(t, first.jwksFetcher, second.jwksFetcher)
	assert.Same(t, first.jwksFetcher, resolver.jwksFetcher)
}

func TestCIMDResponseSizeLimitTransport(t *testing.T) {
	const target = "https://keys.example.com/jwks.json"
	transport := cimdResponseSizeLimitTransport{
		base: &cimdMockRoundTripper{responses: map[string]*http.Response{
			target: cimdMockResponse(http.StatusOK, strings.Repeat("a", 11)),
		}},
		maxSize: 10,
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	require.NoError(t, err)

	_, err = transport.RoundTrip(request)
	require.ErrorContains(t, err, "exceeds maximum size")
}

func TestCIMDResolver_MaxConcurrentDiscoveries(t *testing.T) {
	document := &ClientMetadataDocument{
		ClientID:                "https://app.example.com/oauth/client",
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"https://app.example.com/callback"},
	}

	r := &CIMDResolver{
		Fetcher:                  &stubCIMDFetcher{document: document, ttl: time.Hour},
		MaxConcurrentDiscoveries: 1,
	}

	release, err := r.acquire()
	require.NoError(t, err)

	// With the only slot held, a second discovery is turned away instead of queued behind it
	_, err = r.acquire()
	require.ErrorIs(t, err, ErrCIMDTemporarilyUnavailable)

	release()

	// Once released the slot is reusable.
	release2, err := r.acquire()
	require.NoError(t, err)
	release2()
}
