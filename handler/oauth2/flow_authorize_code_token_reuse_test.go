// Copyright © 2026 Pocket ID
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pocket-id/fosite"
	"github.com/pocket-id/fosite/compose"
	"github.com/pocket-id/fosite/handler/oauth2"
	"github.com/pocket-id/fosite/storage"
)

// authorizeCodeTokenStorage is the storage the authorization code token handler needs
type authorizeCodeTokenStorage interface {
	fosite.Transactional
	oauth2.AuthorizeCodeStorageProvider
	oauth2.AccessTokenStorageProvider
	oauth2.RefreshTokenStorageProvider
	oauth2.TokenRevocationStorageProvider
}

// usedAuthorizeCodeStore reports every authorization code as already used, like a storage backend that keeps invalidated code sessions
// It also notes how the tokens of a grant are revoked
type usedAuthorizeCodeStore struct {
	*storage.MemoryStore
	used  fosite.Requester
	calls []string
}

func (s *usedAuthorizeCodeStore) AuthorizeCodeStorage() oauth2.AuthorizeCodeStorage {
	return s
}

func (s *usedAuthorizeCodeStore) GetAuthorizeCodeSession(context.Context, string, string, fosite.Session) (fosite.Requester, error) {
	return s.used, fosite.ErrInvalidatedAuthorizeCode
}

func (s *usedAuthorizeCodeStore) TokenRevocationStorage() oauth2.TokenRevocationStorage {
	return s
}

func (s *usedAuthorizeCodeStore) Transaction(ctx context.Context, f func(ctx context.Context) error) error {
	s.calls = append(s.calls, "begin")
	err := f(ctx)
	s.calls = append(s.calls, "end")
	return err
}

func (s *usedAuthorizeCodeStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	s.calls = append(s.calls, "refresh")
	return s.MemoryStore.RevokeRefreshToken(ctx, requestID)
}

func (s *usedAuthorizeCodeStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	s.calls = append(s.calls, "access")
	return s.MemoryStore.RevokeAccessToken(ctx, requestID)
}

// lostRaceAuthorizeCodeStore reports that another request redeemed the code when the token handler invalidates it
type lostRaceAuthorizeCodeStore struct {
	*storage.MemoryStore
}

func (s *lostRaceAuthorizeCodeStore) AuthorizeCodeStorage() oauth2.AuthorizeCodeStorage {
	return s
}

func (s *lostRaceAuthorizeCodeStore) InvalidateAuthorizeCodeSession(context.Context, string, string) error {
	return fosite.ErrInvalidatedAuthorizeCode
}

func TestAuthorizeCodeReuseRevokesGrantOnlyForItsOwner(t *testing.T) {
	ctx := context.Background()
	owner := &fosite.DefaultClient{ID: "foo", GrantTypes: fosite.Arguments{"authorization_code"}}

	// The first redemption of the code issued tokens for the grant
	original := &fosite.Request{ID: "original-grant", Client: owner, Session: &fosite.DefaultSession{}, RequestedAt: time.Now().UTC()}
	store := &usedAuthorizeCodeStore{MemoryStore: storage.NewMemoryStore(), used: original}
	require.NoError(t, store.CreateAccessTokenSession(ctx, "original-access-token", original))
	require.NoError(t, store.CreateRefreshTokenSession(ctx, "original-refresh-token", "original-access-token", original))

	h := oauth2.AuthorizeExplicitGrantHandler{
		Storage:  store,
		Strategy: &compose.CommonStrategyProvider{CoreStrategy: hmacshaStrategy},
		Config:   &fosite.Config{},
	}
	code, _, err := hmacshaStrategy.GenerateAuthorizeCode(ctx, nil)
	require.NoError(t, err)
	replay := func(client fosite.Client, code string) error {
		request := fosite.NewAccessRequest(&fosite.DefaultSession{})
		request.GrantTypes = fosite.Arguments{"authorization_code"}
		request.Client = client
		request.Form = url.Values{"code": {code}}
		return h.HandleTokenEndpointRequest(ctx, request)
	}

	// Another client and a caller who only knows the signature of the code are refused without ending the grant
	err = replay(&fosite.DefaultClient{ID: "bar", GrantTypes: fosite.Arguments{"authorization_code"}}, code)
	require.ErrorIs(t, err, fosite.ErrInvalidGrant)
	key, signature, _ := strings.Cut(code, ".")
	err = replay(owner, strings.Repeat("A", len(key))+"."+signature)
	require.ErrorIs(t, err, fosite.ErrInvalidGrant)
	require.Empty(t, store.calls)

	// The client the code was issued to ends the grant, refresh token first and in one transaction
	err = replay(owner, code)
	require.ErrorIs(t, err, fosite.ErrInvalidGrant)
	require.Equal(t, []string{"begin", "refresh", "access", "end"}, store.calls)
	_, err = store.GetAccessTokenSession(ctx, "original-access-token", nil)
	require.ErrorIs(t, err, fosite.ErrNotFound)
	_, err = store.GetRefreshTokenSession(ctx, "original-refresh-token", nil)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)
}

func TestAuthorizeCodeLostRedemptionRaceRevokesGrant(t *testing.T) {
	ctx := context.Background()
	client := &fosite.DefaultClient{ID: "foo", GrantTypes: fosite.Arguments{"authorization_code"}}
	grant := &fosite.Request{ID: "grant", Client: client, Session: &fosite.DefaultSession{}, RequestedAt: time.Now().UTC()}

	for name, newStorage := range map[string]func(*storage.MemoryStore) authorizeCodeTokenStorage{
		// The winner committed before this request read the code again
		"code already invalidated": func(store *storage.MemoryStore) authorizeCodeTokenStorage {
			return &usedAuthorizeCodeStore{MemoryStore: store, used: grant}
		},
		// The winner committed while this request was invalidating the code
		"invalidation lost the race": func(store *storage.MemoryStore) authorizeCodeTokenStorage {
			return &lostRaceAuthorizeCodeStore{MemoryStore: store}
		},
	} {
		t.Run(name, func(t *testing.T) {
			// The winner's tokens belong to the same grant
			store := storage.NewMemoryStore()
			code, signature, err := hmacshaStrategy.GenerateAuthorizeCode(ctx, nil)
			require.NoError(t, err)
			require.NoError(t, store.CreateAuthorizeCodeSession(ctx, signature, grant))
			require.NoError(t, store.CreateAccessTokenSession(ctx, "winner-access-token", grant))
			require.NoError(t, store.CreateRefreshTokenSession(ctx, "winner-refresh-token", "winner-access-token", grant))

			h := oauth2.AuthorizeExplicitGrantHandler{
				Storage:  newStorage(store),
				Strategy: &compose.CommonStrategyProvider{CoreStrategy: hmacshaStrategy},
				Config:   &fosite.Config{},
			}

			// This request passed HandleTokenEndpointRequest, which gave it the ID of the grant
			request := fosite.NewAccessRequest(&fosite.DefaultSession{})
			request.ID = grant.ID
			request.GrantTypes = fosite.Arguments{"authorization_code"}
			request.Client = client
			request.Form = url.Values{"code": {code}}

			err = h.PopulateTokenEndpointResponse(ctx, request, fosite.NewAccessResponse())
			require.ErrorIs(t, err, fosite.ErrInvalidGrant)
			_, err = store.GetAccessTokenSession(ctx, "winner-access-token", nil)
			require.ErrorIs(t, err, fosite.ErrNotFound)
			_, err = store.GetRefreshTokenSession(ctx, "winner-refresh-token", nil)
			require.ErrorIs(t, err, fosite.ErrInactiveToken)
		})
	}
}
