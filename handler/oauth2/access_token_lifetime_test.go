// Copyright © 2026 Pocket ID
// SPDX-License-Identifier: Apache-2.0

package oauth2_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-jose/go-jose/v4"
	gojwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/pocket-id/fosite"
	"github.com/pocket-id/fosite/compose"
	"github.com/pocket-id/fosite/handler/oauth2"
	"github.com/pocket-id/fosite/storage"
	"github.com/pocket-id/fosite/token/jwt"
	"github.com/stretchr/testify/require"
)

func TestJWTAccessTokenLifetime(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, grant := range []string{"authorization_code", "refresh_token", string(fosite.GrantTypeDeviceCode), string(fosite.GrantTypeJWTBearer)} {
		for _, phase := range []time.Duration{0, 499 * time.Millisecond, 500 * time.Millisecond, 999 * time.Millisecond} {
			t.Run(fmt.Sprintf("%s/%s", grant, phase), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					time.Sleep(phase)
					now := time.Now().UTC()
					ctx := context.Background()
					config := &fosite.Config{
						GlobalSecret: []byte(strings.Repeat("s", 32)), AccessTokenLifespan: 15 * time.Minute,
						RefreshTokenLifespan: time.Hour, AuthorizeCodeLifespan: time.Minute,
						AccessTokenIssuer: "https://issuer.example", RefreshTokenScopes: []string{"offline_access"},
						DeviceAndUserCodeLifespan: time.Minute, TokenURL: "https://issuer.example/token",
						ScopeStrategy: fosite.HierarchicScopeStrategy, GrantTypeJWTBearerMaxDuration: time.Hour,
					}
					core := compose.NewOAuth2HMACStrategy(config)
					access := compose.NewOAuth2RFC9068JWTStrategy(func(context.Context) (interface{}, error) { return key, nil }, config)
					strategies := &compose.CommonStrategyProvider{CoreStrategy: core, AccessTokenStrat: access, DeviceStrategy: compose.NewDeviceStrategy(config)}
					store := storage.NewMemoryStore()
					client := &fosite.DefaultClient{
						ID: "public-client", Public: true, GrantTypes: fosite.Arguments{grant},
						Scopes: fosite.Arguments{"offline_access", "read"}, Audience: fosite.Arguments{"https://resource.example"},
					}
					session := &oauth2.JWTSession{Subject: "user", JWTClaims: &jwt.JWTClaims{Subject: "user"}}
					session.SetExpiresAt(fosite.AuthorizeCode, now.Add(time.Minute))
					session.SetExpiresAt(fosite.RefreshToken, now.Add(time.Hour))
					session.SetExpiresAt(fosite.DeviceCode, now.Add(time.Minute))
					original := &fosite.Request{
						ID: "grant", Client: client, Session: session, Form: url.Values{}, RequestedAt: now,
						RequestedScope: fosite.Arguments{"offline_access", "read"}, GrantedScope: fosite.Arguments{"offline_access", "read"},
						RequestedAudience: fosite.Arguments{"https://resource.example"}, GrantedAudience: fosite.Arguments{"https://resource.example"},
					}
					request := fosite.NewAccessRequest(&oauth2.JWTSession{})
					request.Client = client
					request.GrantTypes = fosite.Arguments{grant}
					var handler fosite.TokenEndpointHandler
					switch grant {
					case "authorization_code":
						token, signature, err := core.GenerateAuthorizeCode(ctx, original)
						require.NoError(t, err)
						require.NoError(t, store.CreateAuthorizeCodeSession(ctx, signature, original))
						request.Form.Set("code", token)
						handler = &oauth2.AuthorizeExplicitGrantHandler{Config: config, Storage: store, Strategy: strategies}
					case "refresh_token":
						token, signature, err := core.GenerateRefreshToken(ctx, original)
						require.NoError(t, err)
						require.NoError(t, store.CreateRefreshTokenSession(ctx, signature, "", original))
						request.Form.Set("refresh_token", token)
						handler = &oauth2.RefreshTokenGrantHandler{Config: config, Storage: store, Strategy: strategies}
					case string(fosite.GrantTypeDeviceCode):
						deviceCode, deviceSignature, err := strategies.DeviceStrategy.GenerateDeviceCode(ctx)
						require.NoError(t, err)
						_, userSignature, err := strategies.DeviceStrategy.GenerateUserCode(ctx)
						require.NoError(t, err)
						device := &fosite.DeviceRequest{Request: *original, UserCodeState: fosite.UserCodeAccepted}
						require.NoError(t, store.CreateDeviceAuthSession(ctx, deviceSignature, userSignature, device))
						request.Form.Set("device_code", deviceCode)
						handler = compose.RFC8628DeviceAuthorizationTokenFactory(config, store, strategies).(fosite.TokenEndpointHandler)
					case string(fosite.GrantTypeJWTBearer):
						store.IssuerPublicKeys["https://assertion.example"] = storage.IssuerPublicKeys{
							Issuer: "https://assertion.example",
							KeysBySub: map[string]storage.SubjectPublicKeys{"user": {Subject: "user", Keys: map[string]storage.PublicKeyScopes{
								"assertion-key": {Key: &jose.JSONWebKey{Key: key.Public(), KeyID: "assertion-key", Algorithm: string(jose.RS256), Use: "sig"}, Scopes: []string{"read"}},
							}}},
						}
						signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "assertion-key"}}, (&jose.SignerOptions{}).WithType("JWT"))
						require.NoError(t, err)
						assertion, err := gojwt.Signed(signer).Claims(gojwt.Claims{
							Issuer: "https://assertion.example", Subject: "user", ID: "assertion", Audience: gojwt.Audience{config.TokenURL},
							IssuedAt: gojwt.NewNumericDate(now), Expiry: gojwt.NewNumericDate(now.Add(time.Minute)),
						}).Serialize()
						require.NoError(t, err)
						request.Form.Set("assertion", assertion)
						request.RequestedScope = fosite.Arguments{"read"}
						request.GrantAudience("https://resource.example")
						request.Session = &oauth2.JWTSession{JWTClaims: &jwt.JWTClaims{Subject: "user"}}
						handler = compose.RFC7523AssertionGrantFactory(config, store, strategies).(fosite.TokenEndpointHandler)
					}
					require.NoError(t, handler.HandleTokenEndpointRequest(ctx, request))
					response := fosite.NewAccessResponse()
					require.NoError(t, handler.PopulateTokenEndpointResponse(ctx, request, response))
					payload, err := base64.RawURLEncoding.DecodeString(strings.Split(response.GetAccessToken(), ".")[1])
					require.NoError(t, err)
					var claims map[string]interface{}
					require.NoError(t, json.Unmarshal(payload, &claims))
					iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
					require.Equal(t, now.Unix(), iat)
					require.Equal(t, int64(900), exp-iat, "JWT rounding must not exceed the configured access-token lifespan")
					require.False(t, request.GetSession().GetExpiresAt(fosite.AccessToken).After(now.Add(15*time.Minute)))
				})
			})
		}
	}
}
