// Copyright © 2026 Pocket ID
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubCIMDFetcher struct {
	document    *ClientMetadataDocument
	ttl         time.Duration
	cachePolicy *CIMDCachePolicy
	err         error
	calls       int
}

type resolverTestStore struct{}

func (*resolverTestStore) FositeClientManager() ClientManager {
	return resolverTestClientManager{}
}

type resolverTestClientManager struct {
	ClientManager
}

func (resolverTestClientManager) GetClient(context.Context, string) (Client, error) {
	return nil, ErrNotFound
}

func (f *stubCIMDFetcher) Fetch(_ context.Context, _ string) (*ClientMetadataDocument, CIMDCachePolicy, error) {
	f.calls++
	policy := CIMDCachePolicy{TTL: f.ttl, Store: true}
	if f.cachePolicy != nil {
		policy = *f.cachePolicy
	}
	return f.document, policy, f.err
}

type stubCIMDCache struct {
	clients    map[string]CIMDCachedClient
	storeCalls int
	evictCalls int
	lastExpiry time.Time
}

func (c *stubCIMDCache) LoadCIMDClient(_ context.Context, clientID string) (CIMDCachedClient, bool, error) {
	client, found := c.clients[clientID]
	return client, found, nil
}

func (c *stubCIMDCache) StoreCIMDClient(_ context.Context, client Client, _ *ClientMetadataDocument, expiresAt time.Time) (Client, error) {
	c.storeCalls++
	c.lastExpiry = expiresAt
	c.clients[client.GetID()] = CIMDCachedClient{Client: client, ExpiresAt: expiresAt}
	return client, nil
}

func (c *stubCIMDCache) EvictCIMDClient(_ context.Context, clientID string) error {
	c.evictCalls++
	delete(c.clients, clientID)
	return nil
}

func TestCIMDResolver(t *testing.T) {
	const id = "https://app.example.com/oauth/client"
	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	document := &ClientMetadataDocument{
		ClientID:                id,
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"https://app.example.com/callback"},
	}
	notFound := ClientLookupFunc(func(context.Context, string) (Client, error) {
		return nil, ErrNotFound
	})

	t.Run("pre-registered URL client wins", func(t *testing.T) {
		registered := &DefaultClient{ID: id}
		fetcher := &stubCIMDFetcher{document: document, ttl: time.Hour}
		resolver := &CIMDResolver{Fetcher: fetcher, Now: func() time.Time { return now }}

		client, err := resolver.ResolveClient(t.Context(), id, func(context.Context, string) (Client, error) {
			return registered, nil
		})
		require.NoError(t, err)
		assert.Same(t, registered, client)
		assert.Zero(t, fetcher.calls)
	})

	t.Run("pre-registered URL client wins over a fresh cached metadata client", func(t *testing.T) {
		registered := &DefaultClient{ID: id}
		fetcher := &stubCIMDFetcher{document: document, ttl: time.Hour}
		cache := &stubCIMDCache{clients: map[string]CIMDCachedClient{
			id: {Client: &DefaultClient{ID: id}, ExpiresAt: now.Add(time.Hour)},
		}}
		resolver := &CIMDResolver{Fetcher: fetcher, Cache: cache, Now: func() time.Time { return now }}

		client, err := resolver.ResolveClient(t.Context(), id, func(context.Context, string) (Client, error) {
			return registered, nil
		})
		require.NoError(t, err)
		assert.Same(t, registered, client)
		assert.Zero(t, fetcher.calls)
	})

	t.Run("unregistered URL client is discovered and cached", func(t *testing.T) {
		fetcher := &stubCIMDFetcher{document: document, ttl: time.Hour}
		cache := &stubCIMDCache{clients: map[string]CIMDCachedClient{}}
		resolver := &CIMDResolver{Fetcher: fetcher, Cache: cache, Now: func() time.Time { return now }}

		client, err := resolver.ResolveClient(t.Context(), id, notFound)
		require.NoError(t, err)
		assert.Equal(t, id, client.GetID())
		assert.Equal(t, 1, fetcher.calls)
		assert.Equal(t, 1, cache.storeCalls)
		assert.Equal(t, now.Add(time.Hour), cache.clients[id].ExpiresAt)

		_, err = resolver.ResolveClient(t.Context(), id, notFound)
		require.NoError(t, err)
		assert.Equal(t, 1, fetcher.calls)
	})

	t.Run("stale associated client is refreshed", func(t *testing.T) {
		stale := &DefaultClient{ID: id}
		fetcher := &stubCIMDFetcher{document: document, ttl: time.Hour}
		cache := &stubCIMDCache{clients: map[string]CIMDCachedClient{
			id: {Client: stale, ExpiresAt: now.Add(-time.Minute)},
		}}
		resolver := &CIMDResolver{Fetcher: fetcher, Cache: cache, Now: func() time.Time { return now }}

		client, err := resolver.ResolveClient(t.Context(), id, notFound)
		require.NoError(t, err)
		assert.NotSame(t, stale, client)
		assert.Equal(t, 1, fetcher.calls)
		assert.Equal(t, 1, cache.storeCalls)
	})

	t.Run("failed refresh does not return stale metadata", func(t *testing.T) {
		fetcher := &stubCIMDFetcher{err: errors.New("client metadata endpoint is unavailable")}
		cache := &stubCIMDCache{clients: map[string]CIMDCachedClient{
			id: {Client: &DefaultClient{ID: id}, ExpiresAt: now.Add(-time.Minute)},
		}}
		resolver := &CIMDResolver{Fetcher: fetcher, Cache: cache, Now: func() time.Time { return now }}

		_, err := resolver.ResolveClient(t.Context(), id, notFound)
		require.ErrorContains(t, err, "client metadata endpoint is unavailable")
	})

	t.Run("temporarily unavailable document keeps expired metadata in use for the grace period", func(t *testing.T) {
		stale := &DefaultClient{ID: id}
		unavailable := fmt.Errorf("%w: connection refused", ErrCIMDTemporarilyUnavailable)
		resolve := func(expiredFor time.Duration, fetchErr error) (Client, error) {
			resolver := &CIMDResolver{
				Fetcher:            &stubCIMDFetcher{err: fetchErr},
				Cache:              &stubCIMDCache{clients: map[string]CIMDCachedClient{id: {Client: stale, ExpiresAt: now.Add(-expiredFor)}}},
				Now:                func() time.Time { return now },
				StaleIfUnavailable: time.Hour,
			}
			return resolver.ResolveClient(t.Context(), id, notFound)
		}

		client, err := resolve(time.Minute, unavailable)
		require.NoError(t, err)
		assert.Same(t, stale, client)

		_, err = resolve(2*time.Hour, unavailable)
		require.ErrorIs(t, err, ErrCIMDTemporarilyUnavailable)

		// A document that was retrieved and rejected does say something about the client
		_, err = resolve(time.Minute, errors.New("invalid client metadata JSON"))
		require.ErrorContains(t, err, "invalid client metadata JSON")
	})

	t.Run("failed discovery is not repeated within the retry interval", func(t *testing.T) {
		current := now
		fetcher := &stubCIMDFetcher{err: errors.New("invalid client metadata JSON")}
		cache := &stubCIMDCache{clients: map[string]CIMDCachedClient{
			id: {Client: &DefaultClient{ID: id}, ExpiresAt: now.Add(-time.Minute)},
		}}
		resolver := &CIMDResolver{Fetcher: fetcher, Cache: cache, Now: func() time.Time { return current }, RetryAfterFailure: time.Minute}

		for range 2 {
			_, err := resolver.ResolveClient(t.Context(), id, notFound)
			require.ErrorContains(t, err, "invalid client metadata JSON")
		}
		assert.Equal(t, 1, fetcher.calls)

		// A forced refresh is how a fixed document is picked up, so it fetches regardless
		_, err := resolver.RefreshClient(t.Context(), id)
		require.Error(t, err)
		assert.Equal(t, 2, fetcher.calls)

		current = now.Add(2 * time.Minute)
		_, err = resolver.ResolveClient(t.Context(), id, notFound)
		require.Error(t, err)
		assert.Equal(t, 3, fetcher.calls)
	})

	t.Run("policy rejects before fetching", func(t *testing.T) {
		fetcher := &stubCIMDFetcher{document: document, ttl: time.Hour}
		resolver := &CIMDResolver{
			Fetcher: fetcher,
			Policy: CIMDClientPolicyFuncs{Allow: func(context.Context, string) error {
				return errors.New("denied")
			}},
		}

		_, err := resolver.ResolveClient(t.Context(), id, notFound)
		require.ErrorContains(t, err, "denied")
		assert.Zero(t, fetcher.calls)
	})

	t.Run("policy is reapplied to cached metadata clients", func(t *testing.T) {
		fetcher := &stubCIMDFetcher{document: document, ttl: time.Hour}
		cache := &stubCIMDCache{clients: map[string]CIMDCachedClient{
			id: {Client: &DefaultClient{ID: id}, ExpiresAt: now.Add(time.Hour)},
		}}
		resolver := &CIMDResolver{
			Fetcher: fetcher,
			Cache:   cache,
			Policy: CIMDClientPolicyFuncs{Allow: func(context.Context, string) error {
				return errors.New("denied")
			}},
			Now: func() time.Time { return now },
		}

		_, err := resolver.ResolveClient(t.Context(), id, notFound)
		require.ErrorContains(t, err, "denied")
		assert.Zero(t, fetcher.calls)
	})

}

func TestCIMDResolver_RefreshClientRequiresAssociation(t *testing.T) {
	resolver := &CIMDResolver{
		Fetcher: &stubCIMDFetcher{},
		Cache:   &stubCIMDCache{clients: map[string]CIMDCachedClient{}},
	}

	_, err := resolver.RefreshClient(t.Context(), "https://app.example.com/oauth/client")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestCIMDResolver_ConfiguresGuardedJWKSFetching(t *testing.T) {
	const (
		id      = "https://client.example.com/oauth/client"
		jwksURI = "https://keys.example.com/jwks.json"
	)
	documentResponse := cimdMockResponse(http.StatusOK, `{
		"client_id":"https://client.example.com/oauth/client",
		"token_endpoint_auth_method":"private_key_jwt",
		"redirect_uris":["https://client.example.com/callback"],
		"jwks_uri":"https://keys.example.com/jwks.json"
	}`)
	keysResponse := cimdMockResponse(http.StatusOK, `{"keys":[]}`)
	fetcher := NewDefaultCIMDFetcher(
		cimdMockTransport(&cimdMockRoundTripper{responses: map[string]*http.Response{
			id:      documentResponse,
			jwksURI: keysResponse,
		}}),
		WithCIMDAllowPrivateIPs(true),
	)
	resolver := &CIMDResolver{Fetcher: fetcher}

	resolved, err := resolver.ResolveClient(t.Context(), id, func(context.Context, string) (Client, error) {
		return nil, ErrNotFound
	})
	require.NoError(t, err)

	client, ok := resolved.(*CIMDClient)
	require.True(t, ok)
	keys, err := client.ResolveCIMDJSONWebKeys(t.Context(), false)
	require.NoError(t, err)
	assert.Empty(t, keys.Keys)
}

func TestCIMDResolver_NoStoreIsNotPersisted(t *testing.T) {
	const id = "https://app.example.com/oauth/client"
	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	document := &ClientMetadataDocument{
		ClientID:                id,
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"https://app.example.com/callback"},
	}
	notFound := ClientLookupFunc(func(context.Context, string) (Client, error) {
		return nil, ErrNotFound
	})

	cache := &stubCIMDCache{clients: map[string]CIMDCachedClient{}}
	noStore := CIMDCachePolicy{}
	fetcher := &stubCIMDFetcher{document: document, cachePolicy: &noStore}
	r := &CIMDResolver{Fetcher: fetcher, Cache: cache, Now: func() time.Time { return now }}

	client, err := r.ResolveClient(t.Context(), id, notFound)
	require.NoError(t, err)
	require.NotNil(t, client)

	require.Zero(t, cache.storeCalls)
	require.Equal(t, 1, cache.evictCalls)
	require.NotContains(t, cache.clients, id)

	_, err = r.ResolveClient(t.Context(), id, notFound)
	require.NoError(t, err)
	assert.Equal(t, 2, fetcher.calls, "a no-store response must be re-fetched on every use")
}

func TestCIMDResolver_NoCacheIsPersistedExpired(t *testing.T) {
	const id = "https://app.example.com/oauth/client"
	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)
	document := &ClientMetadataDocument{ClientID: id, RedirectURIs: []string{"https://app.example.com/callback"}, TokenEndpointAuthMethod: "none"}
	cache := &stubCIMDCache{clients: map[string]CIMDCachedClient{}}
	r := &CIMDResolver{
		Fetcher: &stubCIMDFetcher{document: document, cachePolicy: &CIMDCachePolicy{Store: true}},
		Cache:   cache,
		Now:     func() time.Time { return now },
	}

	_, err := r.ResolveClient(t.Context(), id, func(context.Context, string) (Client, error) { return nil, ErrNotFound })
	require.NoError(t, err)
	require.Equal(t, 1, cache.storeCalls)
	assert.Equal(t, now, cache.lastExpiry)
}

func TestCIMDResolver_NoStoreRequiresEvictableCache(t *testing.T) {
	const id = "https://app.example.com/oauth/client"
	document := &ClientMetadataDocument{ClientID: id, RedirectURIs: []string{"https://app.example.com/callback"}, TokenEndpointAuthMethod: "none"}
	cache := &stubCIMDCache{clients: map[string]CIMDCachedClient{}}
	noStore := CIMDCachePolicy{}
	r := &CIMDResolver{
		Fetcher: &stubCIMDFetcher{document: document, cachePolicy: &noStore},
		Cache: struct{ CIMDClientCache }{
			CIMDClientCache: cache,
		},
	}

	_, err := r.ResolveClient(t.Context(), id, func(context.Context, string) (Client, error) { return nil, ErrNotFound })
	require.ErrorIs(t, err, errCIMDNoStoreUnsupported)
	require.ErrorContains(t, err, "Cache-Control: no-store")
	assert.Zero(t, cache.storeCalls)
	assert.Zero(t, cache.evictCalls)
}

func TestCIMDResolver_NoStoreFailureHasFriendlyAuthorizeError(t *testing.T) {
	provider := &Fosite{Store: &resolverTestStore{}, Config: &Config{
		ClientResolver: ClientResolverFunc(func(context.Context, string, ClientLookupFunc) (Client, error) {
			return nil, errCIMDNoStoreUnsupported
		}),
	}}
	request := httptest.NewRequest(http.MethodGet, "/authorize?client_id=https%3A%2F%2Fapp.example.com%2Foauth%2Fclient", nil)

	_, err := provider.NewAuthorizeRequest(t.Context(), request)
	require.Error(t, err)
	var oauthErr *RFC6749Error
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, "The client metadata document uses Cache-Control: no-store, but this authorization server requires metadata caching. Allow the document to be cached and try again.", oauthErr.Reason())
}

func TestCIMDResolver_TemporaryFailureIsNotAnInvalidClient(t *testing.T) {
	const id = "https://app.example.com/oauth/client"
	provider := &Fosite{Store: &resolverTestStore{}, Config: &Config{
		ClientResolver: ClientResolverFunc(func(context.Context, string, ClientLookupFunc) (Client, error) {
			return nil, fmt.Errorf("fetch client metadata: %w", ErrCIMDTemporarilyUnavailable)
		}),
	}}

	// The authorization endpoint must not report an unknown client
	_, err := provider.NewAuthorizeRequest(t.Context(), httptest.NewRequest(http.MethodGet, "/authorize?client_id="+url.QueryEscape(id), nil))
	require.ErrorIs(t, err, ErrTemporarilyUnavailable)

	// The token endpoint answers with a 503 so the client keeps its tokens and retries
	form := url.Values{"client_id": {id}}
	_, err = provider.DefaultClientAuthenticationStrategy(t.Context(), httptest.NewRequest(http.MethodPost, "/token", nil), form)
	var oauthErr *RFC6749Error
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, http.StatusServiceUnavailable, oauthErr.CodeField)
}

// blockingCIMDFetcher reports the liveness of the context it is called with, after the caller that
// triggered it has gone away.
type blockingCIMDFetcher struct {
	document *ClientMetadataDocument
	started  chan struct{}
	release  chan struct{}
	ctxErr   chan error
}

func (f *blockingCIMDFetcher) Fetch(ctx context.Context, _ string) (*ClientMetadataDocument, CIMDCachePolicy, error) {
	close(f.started)
	<-f.release
	f.ctxErr <- ctx.Err()
	return f.document, CIMDCachePolicy{TTL: time.Hour, Store: true}, nil
}

func TestCIMDResolver_CancelsWorkWithLeaderContext(t *testing.T) {
	const id = "https://app.example.com/oauth/client"
	document := &ClientMetadataDocument{
		ClientID:                id,
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"https://app.example.com/callback"},
	}
	notFound := ClientLookupFunc(func(context.Context, string) (Client, error) {
		return nil, ErrNotFound
	})

	fetcher := &blockingCIMDFetcher{
		document: document,
		started:  make(chan struct{}),
		release:  make(chan struct{}),
		ctxErr:   make(chan error, 1),
	}
	r := &CIMDResolver{Fetcher: fetcher, Cache: &stubCIMDCache{clients: map[string]CIMDCachedClient{}}}

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	go func() {
		_, _ = r.ResolveClient(leaderCtx, id, notFound)
	}()

	<-fetcher.started
	// The request that triggered discovery disconnects mid-fetch.
	cancelLeader()
	close(fetcher.release)

	select {
	case err := <-fetcher.ctxErr:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("fetch did not complete")
	}
}

type insecureMetadataMaterializer struct{}

func (insecureMetadataMaterializer) MaterializeCIMDClient(_ context.Context, document *ClientMetadataDocument) (Client, error) {
	return &DefaultOpenIDConnectClient{
		DefaultClient: &DefaultClient{ID: document.ClientID},
		RequestURIs:   []string{"https://app.example.com/request.jwt"},
	}, nil
}

func TestCIMDResolver_CustomMaterializerMustSecureRemoteURLs(t *testing.T) {
	const id = "https://app.example.com/oauth/client"
	document := &ClientMetadataDocument{ClientID: id, RedirectURIs: []string{"https://app.example.com/callback"}, TokenEndpointAuthMethod: "none"}
	r := &CIMDResolver{
		Fetcher:      &stubCIMDFetcher{document: document, ttl: time.Hour},
		Materializer: insecureMetadataMaterializer{},
	}

	_, err := r.ResolveClient(t.Context(), id, func(context.Context, string) (Client, error) { return nil, ErrNotFound })
	require.ErrorContains(t, err, "must implement CIMDSecureFetcher")
}

type idMismatchMaterializer struct{}

func (idMismatchMaterializer) MaterializeCIMDClient(context.Context, *ClientMetadataDocument) (Client, error) {
	return &DefaultClient{ID: "https://other.example.com/oauth/client"}, nil
}

func TestCIMDResolver_RejectsMaterializedIDMismatch(t *testing.T) {
	const id = "https://app.example.com/oauth/client"
	document := &ClientMetadataDocument{
		ClientID:                id,
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"https://app.example.com/callback"},
	}
	notFound := ClientLookupFunc(func(context.Context, string) (Client, error) {
		return nil, ErrNotFound
	})

	r := &CIMDResolver{
		Fetcher:      &stubCIMDFetcher{document: document, ttl: time.Hour},
		Cache:        &stubCIMDCache{clients: map[string]CIMDCachedClient{}},
		Materializer: idMismatchMaterializer{},
	}
	_, err := r.ResolveClient(t.Context(), id, notFound)
	require.ErrorContains(t, err, "does not match requested client_id")
}
