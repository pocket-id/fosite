// Copyright © 2026 Pocket ID
// SPDX-License-Identifier: Apache-2.0

package rfc8628_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pocket-id/fosite"
	"github.com/pocket-id/fosite/handler/oauth2"
	"github.com/pocket-id/fosite/handler/rfc8628"
	"github.com/pocket-id/fosite/storage"
)

// deviceTokenStorage is the storage the device code token handler needs.
type deviceTokenStorage interface {
	fosite.Transactional
	rfc8628.DeviceAuthStorageProvider
	oauth2.AccessTokenStorageProvider
	oauth2.RefreshTokenStorageProvider
	oauth2.TokenRevocationStorageProvider
}

// usedDeviceCodeStore reports every device code as already used, like a
// storage backend that keeps invalidated device code sessions.
// It also notes how the tokens of a grant are revoked.
type usedDeviceCodeStore struct {
	*storage.MemoryStore
	used  fosite.DeviceRequester
	calls []string
}

func (s *usedDeviceCodeStore) TokenRevocationStorage() oauth2.TokenRevocationStorage {
	return s
}

func (s *usedDeviceCodeStore) Transaction(ctx context.Context, f func(ctx context.Context) error) error {
	s.calls = append(s.calls, "begin")
	err := f(ctx)
	s.calls = append(s.calls, "end")
	return err
}

func (s *usedDeviceCodeStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	s.calls = append(s.calls, "refresh")
	return s.MemoryStore.RevokeRefreshToken(ctx, requestID)
}

func (s *usedDeviceCodeStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	s.calls = append(s.calls, "access")
	return s.MemoryStore.RevokeAccessToken(ctx, requestID)
}

func (s *usedDeviceCodeStore) DeviceAuthStorage() rfc8628.DeviceAuthStorage {
	return s
}

func (s *usedDeviceCodeStore) GetDeviceCodeSession(context.Context, string, fosite.Session) (fosite.DeviceRequester, error) {
	return s.used, fosite.ErrInvalidatedDeviceCode
}

func TestDeviceCodeReuseRevokesTokensOfOriginalGrant(t *testing.T) {
	ctx := context.Background()
	client := &fosite.DefaultClient{ID: "foo", GrantTypes: fosite.Arguments{string(fosite.GrantTypeDeviceCode)}}

	// The first redemption of the device code issued tokens for the original grant
	original := &fosite.DeviceRequest{
		UserCodeState: fosite.UserCodeAccepted,
		Request: fosite.Request{
			ID:          "original-grant",
			Client:      client,
			Session:     &fosite.DefaultSession{},
			RequestedAt: time.Now().UTC(),
		},
	}
	memoryStore := storage.NewMemoryStore()
	store := &usedDeviceCodeStore{MemoryStore: memoryStore, used: original}
	require.NoError(t, memoryStore.CreateAccessTokenSession(ctx, "original-access-token", original))
	require.NoError(t, memoryStore.CreateRefreshTokenSession(ctx, "original-refresh-token", "original-access-token", original))

	h := rfc8628.DeviceCodeTokenEndpointHandler{
		Strategy: &mockDeviceCodeStrategyProvider{
			deviceRateLimitStrategy: &RFC8628HMACSHAStrategy,
			deviceCodeStrategy:      &RFC8628HMACSHAStrategy,
			userCodeStrategy:        &RFC8628HMACSHAStrategy,
			coreStrategy:            hmacshaStrategyOAuth,
		},
		Storage: store,
		Config: &fosite.Config{
			ScopeStrategy:             fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy:  fosite.DefaultAudienceMatchingStrategy,
			DeviceAndUserCodeLifespan: time.Minute,
		},
	}

	// The replayed device code arrives with a new request ID
	code, _, err := RFC8628HMACSHAStrategy.GenerateDeviceCode(ctx)
	require.NoError(t, err)
	replay := func(client fosite.Client) error {
		request := fosite.NewAccessRequest(&fosite.DefaultSession{})
		request.GrantTypes = fosite.Arguments{string(fosite.GrantTypeDeviceCode)}
		request.Client = client
		request.Form = url.Values{"device_code": {code}}
		require.NotEqual(t, original.GetID(), request.GetID())
		return h.HandleTokenEndpointRequest(ctx, request)
	}

	// Another client is refused without ending the grant
	err = replay(&fosite.DefaultClient{ID: "bar", GrantTypes: fosite.Arguments{string(fosite.GrantTypeDeviceCode)}})
	require.ErrorIs(t, err, fosite.ErrInvalidGrant)
	require.Empty(t, store.calls)

	// The client the device code was issued to ends the grant, refresh token first and in one transaction
	err = replay(client)
	require.ErrorIs(t, err, fosite.ErrInvalidGrant)
	require.Equal(t, []string{"begin", "refresh", "access", "end"}, store.calls)

	// Both tokens of the original grant are revoked
	_, err = memoryStore.GetAccessTokenSession(ctx, "original-access-token", nil)
	require.ErrorIs(t, err, fosite.ErrNotFound)
	_, err = memoryStore.GetRefreshTokenSession(ctx, "original-refresh-token", nil)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)
}

// lostRaceDeviceCodeStore reports that a concurrent request already redeemed
// the device code when the token handler invalidates it.
type lostRaceDeviceCodeStore struct {
	*storage.MemoryStore
}

func (s *lostRaceDeviceCodeStore) DeviceAuthStorage() rfc8628.DeviceAuthStorage {
	return s
}

func (s *lostRaceDeviceCodeStore) InvalidateDeviceCodeSession(context.Context, string) error {
	return fosite.ErrInvalidatedDeviceCode
}

func TestDeviceCodeLostRedemptionRaceRevokesGrant(t *testing.T) {
	ctx := context.Background()
	client := &fosite.DefaultClient{ID: "foo", GrantTypes: fosite.Arguments{string(fosite.GrantTypeDeviceCode)}}
	accepted := &fosite.DeviceRequest{
		UserCodeState: fosite.UserCodeAccepted,
		Request: fosite.Request{
			ID:             "grant",
			Client:         client,
			RequestedScope: fosite.Arguments{"foo"},
			GrantedScope:   fosite.Arguments{"foo"},
			Session:        &fosite.DefaultSession{},
			RequestedAt:    time.Now().UTC(),
		},
	}

	for name, newStorage := range map[string]func(*storage.MemoryStore) deviceTokenStorage{
		// The winner committed before this request read the device code session
		"device code already invalidated": func(store *storage.MemoryStore) deviceTokenStorage {
			return &usedDeviceCodeStore{MemoryStore: store, used: accepted}
		},
		// The winner committed while this request was invalidating the device code
		"invalidation lost the race": func(store *storage.MemoryStore) deviceTokenStorage {
			return &lostRaceDeviceCodeStore{MemoryStore: store}
		},
	} {
		t.Run(name, func(t *testing.T) {
			memoryStore := storage.NewMemoryStore()
			code, signature, err := RFC8628HMACSHAStrategy.GenerateDeviceCode(ctx)
			require.NoError(t, err)
			_, userCodeSignature, err := RFC8628HMACSHAStrategy.GenerateUserCode(ctx)
			require.NoError(t, err)
			require.NoError(t, memoryStore.CreateDeviceAuthSession(ctx, signature, userCodeSignature, accepted))

			// The winner's tokens belong to the same grant
			require.NoError(t, memoryStore.CreateAccessTokenSession(ctx, "winner-access-token", accepted))
			require.NoError(t, memoryStore.CreateRefreshTokenSession(ctx, "winner-refresh-token", "winner-access-token", accepted))

			h := rfc8628.DeviceCodeTokenEndpointHandler{
				Strategy: &mockDeviceCodeStrategyProvider{
					deviceRateLimitStrategy: &RFC8628HMACSHAStrategy,
					deviceCodeStrategy:      &RFC8628HMACSHAStrategy,
					userCodeStrategy:        &RFC8628HMACSHAStrategy,
					coreStrategy:            hmacshaStrategyOAuth,
				},
				Storage: newStorage(memoryStore),
				Config: &fosite.Config{
					ScopeStrategy:            fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
					AccessTokenLifespan:      time.Minute,
				},
			}

			// This request passed HandleTokenEndpointRequest, which gave it the ID of the grant
			request := fosite.NewAccessRequest(&fosite.DefaultSession{})
			request.ID = accepted.ID
			request.GrantTypes = fosite.Arguments{string(fosite.GrantTypeDeviceCode)}
			request.Client = client
			request.Form = url.Values{"device_code": {code}}

			err = h.PopulateTokenEndpointResponse(ctx, request, fosite.NewAccessResponse())
			require.ErrorIs(t, err, fosite.ErrInvalidGrant)
			require.Equal(t, http.StatusBadRequest, fosite.ErrorToRFC6749Error(err).CodeField)
			_, err = memoryStore.GetAccessTokenSession(ctx, "winner-access-token", nil)
			require.ErrorIs(t, err, fosite.ErrNotFound)
			_, err = memoryStore.GetRefreshTokenSession(ctx, "winner-refresh-token", nil)
			require.ErrorIs(t, err, fosite.ErrInactiveToken)
		})
	}
}
