// Copyright © 2026 Pocket ID
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// ClientLookupFunc resolves a client from its identifier.
type ClientLookupFunc func(context.Context, string) (Client, error)

// ClientResolver decorates the authorization server's registered-client lookup.
type ClientResolver interface {
	ResolveClient(context.Context, string, ClientLookupFunc) (Client, error)
}

// ClientResolverProvider optionally provides a client resolver without extending Configurator.
type ClientResolverProvider interface {
	GetClientResolver(context.Context) ClientResolver
}

// ClientResolverFunc implements ClientResolver for a function.
type ClientResolverFunc func(context.Context, string, ClientLookupFunc) (Client, error)

// ResolveClient implements ClientResolver for a function.
func (f ClientResolverFunc) ResolveClient(ctx context.Context, clientID string, next ClientLookupFunc) (Client, error) {
	return f(ctx, clientID, next)
}

// resolveClient applies the optional resolver around the configured client store.
func (f *Fosite) resolveClient(ctx context.Context, clientID string) (Client, error) {
	// The store is only consulted when the resolver delegates to it.
	next := ClientLookupFunc(func(ctx context.Context, clientID string) (Client, error) {
		return f.Store.FositeClientManager().GetClient(ctx, clientID)
	})
	if provider, ok := f.Config.(ClientResolverProvider); ok {
		if resolver := provider.GetClientResolver(ctx); resolver != nil {
			return resolver.ResolveClient(ctx, clientID, next)
		}
	}
	return next(ctx, clientID)
}

// clientLookupError maps a failed client lookup to the error the caller is answered with
// A metadata document that is temporarily unreachable says nothing about the client, so the caller is asked to retry instead of being told the client is invalid
func clientLookupError(err error) *RFC6749Error {
	rfcErr := ErrInvalidClient
	if errors.Is(err, ErrCIMDTemporarilyUnavailable) {
		rfcErr = ErrTemporarilyUnavailable.WithHint("The client metadata document could not be retrieved. Try again later.")
	}
	return rfcErr.WithWrap(err).WithDebug(err.Error())
}

// CIMDCachePolicy contains the response cache semantics needed by the resolver.
type CIMDCachePolicy struct {
	TTL   time.Duration
	Store bool
}

// CIMDCachedClient contains a materialized metadata client and its HTTP cache policy.
type CIMDCachedClient struct {
	Client    Client
	ExpiresAt time.Time
}

// CIMDClientCache persists materialized metadata clients while their metadata is fresh.
type CIMDClientCache interface {
	LoadCIMDClient(context.Context, string) (CIMDCachedClient, bool, error)
	StoreCIMDClient(context.Context, Client, *ClientMetadataDocument, time.Time) (Client, error)
}

// CIMDClientCacheEvictor removes a cached metadata client when a response forbids storage.
type CIMDClientCacheEvictor interface {
	EvictCIMDClient(context.Context, string) error
}

var errCIMDNoStoreUnsupported = errors.New("client metadata document uses Cache-Control: no-store, but this authorization server requires metadata caching")

// CIMDClientMaterializer projects a validated metadata document into a provider client.
type CIMDClientMaterializer interface {
	MaterializeCIMDClient(context.Context, *ClientMetadataDocument) (Client, error)
}

// CIMDClientMaterializerFunc implements CIMDClientMaterializer for a function.
type CIMDClientMaterializerFunc func(context.Context, *ClientMetadataDocument) (Client, error)

// MaterializeCIMDClient calls f.
func (f CIMDClientMaterializerFunc) MaterializeCIMDClient(ctx context.Context, document *ClientMetadataDocument) (Client, error) {
	return f(ctx, document)
}

// CIMDClientPolicy applies authorization-server policy before and after discovery.
type CIMDClientPolicy interface {
	AllowCIMDClient(context.Context, string) error
	ValidateCIMDClient(context.Context, *ClientMetadataDocument) error
}

// CIMDClientPolicyFuncs implements CIMDClientPolicy with optional functions.
type CIMDClientPolicyFuncs struct {
	Allow    func(context.Context, string) error
	Validate func(context.Context, *ClientMetadataDocument) error
}

// AllowCIMDClient applies the identifier policy when configured.
func (p CIMDClientPolicyFuncs) AllowCIMDClient(ctx context.Context, clientID string) error {
	if p.Allow == nil {
		return nil
	}
	return p.Allow(ctx, clientID)
}

// ValidateCIMDClient applies the document policy when configured.
func (p CIMDClientPolicyFuncs) ValidateCIMDClient(ctx context.Context, document *ClientMetadataDocument) error {
	if p.Validate == nil {
		return nil
	}
	return p.Validate(ctx, document)
}

// CIMDResolver resolves unregistered Client Identifier URLs while preserving pre-registered-client precedence.
type CIMDResolver struct {
	Fetcher                  CIMDFetcher
	Cache                    CIMDClientCache
	Materializer             CIMDClientMaterializer
	Policy                   CIMDClientPolicy
	Now                      func() time.Time
	MaxConcurrentDiscoveries int
	// StaleIfUnavailable is how long expired metadata stays usable while its document is temporarily unavailable
	StaleIfUnavailable time.Duration
	// RetryAfterFailure is how long a client ID is not fetched again after its discovery failed, during which it is answered with the same error
	RetryAfterFailure time.Duration

	group    singleflight.Group
	initOnce sync.Once
	slots    chan struct{}

	failuresMu sync.Mutex
	failures   map[string]cimdFailure

	jwksOnce    sync.Once
	jwksFetcher JWKSFetcherStrategy
}

// cimdMaxRememberedFailures bounds the memory that failed discoveries of made-up client IDs can take
const cimdMaxRememberedFailures = 1024

type cimdFailure struct {
	err   error
	until time.Time
}

// acquire takes a discovery slot, and fails right away when all are taken
// Waiting instead would let a few slow documents hold up every other discovery, while failing lets a known client fall back to its expired metadata
func (r *CIMDResolver) acquire() (release func(), err error) {
	r.initOnce.Do(func() {
		if r.MaxConcurrentDiscoveries > 0 {
			r.slots = make(chan struct{}, r.MaxConcurrentDiscoveries)
		}
	})
	if r.slots == nil {
		return func() {}, nil
	}
	select {
	case r.slots <- struct{}{}:
		return func() { <-r.slots }, nil
	default:
		return nil, fmt.Errorf("%w: too many discoveries are in progress", ErrCIMDTemporarilyUnavailable)
	}
}

var _ ClientResolver = (*CIMDResolver)(nil)

// ResolveClient returns a fresh cached metadata client, a pre-registered client, or a newly discovered metadata client.
func (r *CIMDResolver) ResolveClient(ctx context.Context, clientID string, next ClientLookupFunc) (Client, error) {
	if next == nil {
		return nil, errors.New("registered client resolver is required")
	}

	client, err := next(ctx, clientID)
	if err == nil {
		return client, nil
	}
	if !errors.Is(err, ErrNotFound) || !LooksLikeCIMDURL(clientID) {
		return nil, err
	}

	cached, found, err := r.load(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if found {
		if err := r.allow(ctx, clientID); err != nil {
			return nil, err
		}
		if r.now().Before(cached.ExpiresAt) {
			return r.configureClient(cached.Client)
		}
		client, err := r.discover(ctx, clientID, next, true)
		// A document that cannot be retrieved says nothing about the client, so its expired metadata stays in use for a while
		if errors.Is(err, ErrCIMDTemporarilyUnavailable) && r.now().Before(cached.ExpiresAt.Add(r.StaleIfUnavailable)) {
			return r.configureClient(cached.Client)
		}
		return client, err
	}

	return r.discover(ctx, clientID, next, false)
}

// RefreshClient re-fetches a previously associated metadata client regardless of its freshness.
func (r *CIMDResolver) RefreshClient(ctx context.Context, clientID string) (Client, error) {
	_, found, err := r.load(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotFound
	}

	// A forced refresh is how a fixed document is picked up, so it must not be answered with a remembered failure
	r.failuresMu.Lock()
	delete(r.failures, clientID)
	r.failuresMu.Unlock()
	return r.discover(ctx, clientID, nil, true)
}

func (r *CIMDResolver) discover(ctx context.Context, clientID string, next ClientLookupFunc, associated bool) (Client, error) {
	result := r.group.DoChan(clientID, func() (any, error) {
		cached, found, err := r.load(ctx, clientID)
		if err != nil {
			return nil, err
		}
		if found && !associated && r.now().Before(cached.ExpiresAt) {
			return r.configureClient(cached.Client)
		}
		if !found && next != nil {
			client, err := next(ctx, clientID)
			if err == nil {
				return client, nil
			}
			if !errors.Is(err, ErrNotFound) {
				return nil, err
			}
		}
		return r.fetchAndMaterialize(ctx, clientID)
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case resolved := <-result:
		if resolved.Err != nil {
			return nil, resolved.Err
		}
		client, ok := resolved.Val.(Client)
		if !ok {
			return nil, errors.New("CIMD resolver returned an invalid client")
		}
		return client, nil
	}
}

// recentFailure returns the error of a discovery that failed within the retry interval
func (r *CIMDResolver) recentFailure(clientID string) error {
	r.failuresMu.Lock()
	defer r.failuresMu.Unlock()

	failure, found := r.failures[clientID]
	if !found {
		return nil
	}
	if !r.now().Before(failure.until) {
		delete(r.failures, clientID)
		return nil
	}
	return failure.err
}

func (r *CIMDResolver) rememberFailure(clientID string, err error) {
	if r.RetryAfterFailure <= 0 {
		return
	}
	r.failuresMu.Lock()
	defer r.failuresMu.Unlock()

	// Forgetting everything when full is enough, because the memory only spares requests and decides nothing
	if len(r.failures) >= cimdMaxRememberedFailures {
		clear(r.failures)
	}
	if r.failures == nil {
		r.failures = map[string]cimdFailure{}
	}
	r.failures[clientID] = cimdFailure{err: err, until: r.now().Add(r.RetryAfterFailure)}
}

func (r *CIMDResolver) fetchAndMaterialize(ctx context.Context, clientID string) (client Client, err error) {
	if r.Fetcher == nil {
		return nil, errors.New("CIMD fetcher is required")
	}
	if _, err := ParseCIMDURL(clientID); err != nil {
		return nil, err
	}
	if err := r.allow(ctx, clientID); err != nil {
		return nil, err
	}

	// A client ID that failed a moment ago is not fetched again, so nobody can make the server request the same document over and over
	if err := r.recentFailure(clientID); err != nil {
		return nil, err
	}

	release, err := r.acquire()
	if err != nil {
		return nil, err
	}
	defer release()

	// A failure is remembered unless the request that asked for the discovery went away, which says nothing about the document
	defer func() {
		if err != nil && ctx.Err() == nil {
			r.rememberFailure(clientID, err)
		}
	}()
	document, cachePolicy, err := r.Fetcher.Fetch(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("fetch client metadata: %w", err)
	}
	if r.Policy != nil {
		if err := r.Policy.ValidateCIMDClient(ctx, document); err != nil {
			return nil, fmt.Errorf("client metadata violates authorization server policy: %w", err)
		}
	}

	client, err = r.materialize(ctx, document)
	if err != nil {
		return nil, fmt.Errorf("materialize client metadata: %w", err)
	}
	if client == nil {
		return nil, errors.New("materialized CIMD client is nil")
	}
	if client.GetID() != clientID {
		return nil, fmt.Errorf("materialized CIMD client ID %q does not match requested client_id %q", client.GetID(), clientID)
	}
	client, err = r.configureClient(client)
	if err != nil {
		return nil, err
	}
	if !cachePolicy.Store {
		if r.Cache == nil {
			return client, nil
		}
		evictor, ok := r.Cache.(CIMDClientCacheEvictor)
		if !ok {
			return nil, errCIMDNoStoreUnsupported
		}
		if err := evictor.EvictCIMDClient(ctx, clientID); err != nil {
			return nil, fmt.Errorf("evict client metadata: %w", err)
		}
		return client, nil
	}
	if r.Cache == nil {
		return client, nil
	}

	stored, err := r.Cache.StoreCIMDClient(ctx, client, document, r.now().Add(cachePolicy.TTL))
	if err != nil {
		return nil, fmt.Errorf("store client metadata: %w", err)
	}
	if stored == nil {
		return nil, errors.New("stored CIMD client is nil")
	}
	return r.configureClient(stored)
}

func (r *CIMDResolver) load(ctx context.Context, clientID string) (CIMDCachedClient, bool, error) {
	if r.Cache == nil {
		return CIMDCachedClient{}, false, nil
	}
	cached, found, err := r.Cache.LoadCIMDClient(ctx, clientID)
	if err != nil {
		return CIMDCachedClient{}, false, fmt.Errorf("load client metadata: %w", err)
	}
	if found && cached.Client == nil {
		return CIMDCachedClient{}, false, errors.New("cached CIMD client is nil")
	}
	return cached, found, nil
}

func (r *CIMDResolver) materialize(ctx context.Context, document *ClientMetadataDocument) (Client, error) {
	if r.Materializer != nil {
		return r.Materializer.MaterializeCIMDClient(ctx, document)
	}
	return NewCIMDClient(document)
}

func (r *CIMDResolver) allow(ctx context.Context, clientID string) error {
	if r.Policy == nil {
		return nil
	}
	if err := r.Policy.AllowCIMDClient(ctx, clientID); err != nil {
		return fmt.Errorf("CIMD client is not allowed: %w", err)
	}
	return nil
}

// configureClient applies any provider-specific configuration to a materialized metadata client.
func (r *CIMDResolver) configureClient(client Client) (Client, error) {
	if metadataClient, ok := client.(*CIMDClient); ok {
		provider, _ := r.Fetcher.(CIMDSecureHTTPClientProvider)
		if err := metadataClient.configureSecureHTTPClient(provider, r.sharedCIMDJWKSFetcher); err != nil {
			return nil, fmt.Errorf("configure CIMD client: %w", err)
		}
		return metadataClient, nil
	}

	oidcClient, ok := client.(OpenIDConnectClient)
	if !ok {
		return client, nil
	}
	if len(oidcClient.GetRequestURIs()) > 0 {
		if _, ok := client.(CIMDSecureFetcher); !ok {
			return nil, errors.New("materialized CIMD client with request_uris must implement CIMDSecureFetcher")
		}
	}
	if oidcClient.GetJSONWebKeysURI() != "" {
		if _, ok := client.(CIMDJWKSResolver); !ok {
			return nil, errors.New("materialized CIMD client with jwks_uri must implement CIMDJWKSResolver")
		}
	}
	return client, nil
}

func (r *CIMDResolver) sharedCIMDJWKSFetcher(httpClient *http.Client) JWKSFetcherStrategy {
	r.jwksOnce.Do(func() {
		r.jwksFetcher = newCIMDJWKSFetcherStrategy(httpClient)
	})
	return r.jwksFetcher
}

func (r *CIMDResolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}
