// Copyright © 2026 Pocket ID
// SPDX-License-Identifier: Apache-2.0

package compose_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pocket-id/fosite"
	"github.com/pocket-id/fosite/compose"
	"github.com/pocket-id/fosite/storage"
)

// The PKCE handler consumes the PKCE session when the token response is populated, which has to happen after the
// authorization code handler has invalidated the code. Composed before it, a request that fails would leave the code
// redeemable and the PKCE session gone, so the next request would not need the verifier: the handler refuses instead.
func TestPKCEComposedBeforeTheAuthorizeCodeHandlerCannotBeDowngraded(t *testing.T) {
	for _, tc := range []struct {
		name      string
		factories []compose.Factory
	}{
		{name: "after the authorize code handler", factories: []compose.Factory{compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2PKCEFactory}},
		{name: "before the authorize code handler", factories: []compose.Factory{compose.OAuth2PKCEFactory, compose.OAuth2AuthorizeExplicitFactory}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			config := &fosite.Config{
				GlobalSecret:          []byte("some-super-cool-secret-that-nobody-knows"),
				AccessTokenLifespan:   time.Hour,
				AuthorizeCodeLifespan: 10 * time.Minute,
				ScopeStrategy:         fosite.HierarchicScopeStrategy,
			}
			store := storage.NewMemoryStore()
			store.Clients["client"] = &fosite.DefaultClient{
				ID: "client", Public: true, Scopes: []string{"read"},
				GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}, RedirectURIs: []string{"https://cb"},
			}
			strategy := compose.NewOAuth2HMACStrategy(config)
			provider := compose.Compose(config, store, &compose.CommonStrategyProvider{CoreStrategy: strategy}, tc.factories...)

			code, signature, err := strategy.GenerateAuthorizeCode(ctx, nil)
			require.NoError(t, err)
			verifier := strings.Repeat("v", 50)
			sum := sha256.Sum256([]byte(verifier))
			authorize := fosite.NewAuthorizeRequest()
			authorize.ID = "grant"
			authorize.Client = store.Clients["client"]
			authorize.RequestedAt = time.Now()
			authorize.GrantedScope = fosite.Arguments{"read"}
			authorize.Session = &fosite.DefaultSession{ExpiresAt: map[fosite.TokenType]time.Time{fosite.AuthorizeCode: time.Now().Add(10 * time.Minute)}}
			authorize.Form = url.Values{"redirect_uri": {"https://cb"}}
			require.NoError(t, store.CreateAuthorizeCodeSession(ctx, signature, authorize))
			challenge := fosite.NewAuthorizeRequest()
			challenge.Client = authorize.Client
			challenge.Session = &fosite.DefaultSession{}
			challenge.Form = url.Values{"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
			require.NoError(t, store.CreatePKCERequestSession(ctx, signature, challenge))

			redeem := func(verifier string) error {
				form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://cb"}, "client_id": {"client"}}
				if verifier != "" {
					form.Set("code_verifier", verifier)
				}
				r := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				request, err := provider.NewAccessRequest(ctx, r, &fosite.DefaultSession{})
				if err != nil {
					return err
				}
				_, err = provider.NewAccessResponse(ctx, request)
				return err
			}

			// Nobody can redeem the code without the verifier, whatever happened to the requests before.
			assert.Error(t, redeem(""))
			assert.Error(t, redeem(""))
			if strings.HasPrefix(tc.name, "after") {
				assert.NoError(t, redeem(verifier))
			} else {
				// The misordered composition refuses the request instead of silently consuming the session.
				assert.ErrorIs(t, redeem(verifier), fosite.ErrServerError)
				_, err := store.GetPKCERequestSession(ctx, "code", signature, nil)
				assert.NoError(t, err)
			}
		})
	}
}
