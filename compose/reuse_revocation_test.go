// Copyright © 2026 Pocket ID
// SPDX-License-Identifier: Apache-2.0

package compose_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pocket-id/fosite"
	"github.com/pocket-id/fosite/compose"
	"github.com/pocket-id/fosite/handler/oauth2"
	"github.com/pocket-id/fosite/storage"
)

// reuseEnv runs the token endpoint of an authorization code and refresh token provider over the in-memory store.
type reuseEnv struct {
	provider fosite.OAuth2Provider
	store    *storage.MemoryStore
	strategy oauth2.CoreStrategy
}

func newReuseEnv(t *testing.T, wrap func(*storage.MemoryStore) fosite.Storage) *reuseEnv {
	t.Helper()

	config := &fosite.Config{
		GlobalSecret:          []byte("some-super-cool-secret-that-nobody-knows"),
		AccessTokenLifespan:   time.Hour,
		AuthorizeCodeLifespan: 10 * time.Minute,
		ScopeStrategy:         fosite.HierarchicScopeStrategy,
	}
	store := storage.NewMemoryStore()
	store.Clients["client"] = &fosite.DefaultClient{
		ID: "client", Public: true, Scopes: []string{"offline"},
		GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, RedirectURIs: []string{"https://cb"},
	}
	strategy := compose.NewOAuth2HMACStrategy(config)
	var s fosite.Storage = store
	if wrap != nil {
		s = wrap(store)
	}
	return &reuseEnv{
		provider: compose.Compose(config, s, &compose.CommonStrategyProvider{CoreStrategy: strategy},
			compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2RefreshTokenGrantFactory, compose.OAuth2PKCEFactory),
		store:    store,
		strategy: strategy,
	}
}

func (e *reuseEnv) issueCode(t *testing.T) string {
	t.Helper()

	code, signature, err := e.strategy.GenerateAuthorizeCode(context.Background(), nil)
	require.NoError(t, err)
	request := fosite.NewAuthorizeRequest()
	request.ID = "grant"
	request.Client = e.store.Clients["client"]
	request.RequestedAt = time.Now()
	request.GrantedScope = fosite.Arguments{"offline"}
	request.Session = &fosite.DefaultSession{ExpiresAt: map[fosite.TokenType]time.Time{fosite.AuthorizeCode: time.Now().Add(10 * time.Minute)}}
	request.Form = url.Values{"redirect_uri": {"https://cb"}}
	require.NoError(t, e.store.CreateAuthorizeCodeSession(context.Background(), signature, request))
	return code
}

// redeem runs the token endpoint and returns the RFC 6749 error code ("" on success) and the response.
func (e *reuseEnv) redeem(t *testing.T, form url.Values) (string, fosite.AccessResponder) {
	t.Helper()

	form.Set("client_id", "client")
	r := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request, err := e.provider.NewAccessRequest(context.Background(), r, &fosite.DefaultSession{})
	if err != nil {
		return fosite.ErrorToRFC6749Error(err).ErrorField, nil
	}
	response, err := e.provider.NewAccessResponse(context.Background(), request)
	if err != nil {
		return fosite.ErrorToRFC6749Error(err).ErrorField, nil
	}
	return "", response
}

func (e *reuseEnv) mustRedeem(t *testing.T, form url.Values) fosite.AccessResponder {
	t.Helper()

	code, response := e.redeem(t, form)
	require.Empty(t, code)
	return response
}

func (e *reuseEnv) accessTokenIsActive(response fosite.AccessResponder) bool {
	ctx := context.Background()
	_, err := e.store.GetAccessTokenSession(ctx, e.strategy.AccessTokenSignature(ctx, response.GetAccessToken()), nil)
	return err == nil
}

func codeForm(code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://cb"}}
}

func refreshForm(token string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}
}

// refreshRevokeFailsStore cannot revoke refresh tokens. Without real transactions nothing rolls back what the
// reuse handling did before the failure, so it has to revoke what it still can.
type refreshRevokeFailsStore struct{ *storage.MemoryStore }

func (s refreshRevokeFailsStore) TokenRevocationStorage() oauth2.TokenRevocationStorage {
	return refreshRevokeFails{s.MemoryStore}
}

type refreshRevokeFails struct{ *storage.MemoryStore }

func (refreshRevokeFails) RevokeRefreshToken(context.Context, string) error {
	return errors.New("storage unavailable")
}

func TestAuthorizationCodeReuseRevokesWhatItCanWhenOneRevocationFails(t *testing.T) {
	e := newReuseEnv(t, func(m *storage.MemoryStore) fosite.Storage { return refreshRevokeFailsStore{m} })
	code := e.issueCode(t)
	response := e.mustRedeem(t, codeForm(code))
	require.True(t, e.accessTokenIsActive(response))

	errCode, _ := e.redeem(t, codeForm(code))
	assert.Equal(t, "invalid_grant", errCode)
	assert.False(t, e.accessTokenIsActive(response), "the access token is revoked although the refresh token could not be")
}

func TestRefreshTokenReuseRevokesWhatItCanWhenOneRevocationFails(t *testing.T) {
	e := newReuseEnv(t, func(m *storage.MemoryStore) fosite.Storage { return refreshRevokeFailsStore{m} })
	first := e.mustRedeem(t, codeForm(e.issueCode(t)))
	used, _ := first.GetExtra("refresh_token").(string)
	rotated := e.mustRedeem(t, refreshForm(used))
	require.True(t, e.accessTokenIsActive(rotated))

	errCode, _ := e.redeem(t, refreshForm(used))
	assert.NotEmpty(t, errCode)
	assert.False(t, e.accessTokenIsActive(rotated), "the access token is revoked although the refresh token could not be")
}

// incompleteInvalidatedCodeStore answers an invalidated code with a request that has no client and no session.
type incompleteInvalidatedCodeStore struct{ *storage.MemoryStore }

func (s incompleteInvalidatedCodeStore) AuthorizeCodeStorage() oauth2.AuthorizeCodeStorage {
	return incompleteInvalidatedCode{s.MemoryStore}
}

type incompleteInvalidatedCode struct{ oauth2.AuthorizeCodeStorage }

func (incompleteInvalidatedCode) GetAuthorizeCodeSession(context.Context, string, string, fosite.Session) (fosite.Requester, error) {
	return &fosite.Request{ID: "grant"}, fosite.ErrInvalidatedAuthorizeCode
}

func TestInvalidatedCodeWithoutAClientOrASessionIsAServerError(t *testing.T) {
	e := newReuseEnv(t, func(m *storage.MemoryStore) fosite.Storage { return incompleteInvalidatedCodeStore{m} })

	var errCode string
	require.NotPanics(t, func() { errCode, _ = e.redeem(t, codeForm(e.issueCode(t))) })
	assert.Equal(t, "server_error", errCode)
}
