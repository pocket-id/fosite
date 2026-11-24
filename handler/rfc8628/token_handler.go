// Copyright © 2025 Ory Corp
// Modified by contributors to the Pocket ID fork.
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"github.com/ory/x/errorsx"
	"github.com/pocket-id/fosite/handler/oauth2"

	"github.com/pocket-id/fosite"
)

var _ fosite.TokenEndpointHandler = (*DeviceCodeTokenEndpointHandler)(nil)

// DeviceCodeTokenEndpointHandler is a token response handler for
// - the Authorize code grant using the explicit grant type as defined in https://tools.ietf.org/html/rfc6749#section-4.1
// - the Device Authorization Grant as defined in https://www.rfc-editor.org/rfc/rfc8628
type DeviceCodeTokenEndpointHandler struct {
	Storage interface {
		fosite.Transactional
		DeviceAuthStorageProvider
		oauth2.AccessTokenStorageProvider
		oauth2.RefreshTokenStorageProvider
		oauth2.TokenRevocationStorageProvider
	}
	Strategy interface {
		DeviceRateLimitStrategyProvider
		DeviceCodeStrategyProvider
		UserCodeStrategyProvider
		oauth2.AccessTokenStrategyProvider
		oauth2.RefreshTokenStrategyProvider
	}
	Config interface {
		fosite.AccessTokenLifespanProvider
		fosite.RefreshTokenLifespanProvider
		fosite.RefreshTokenScopesProvider
	}
}

func (c *DeviceCodeTokenEndpointHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return false
}

func (c *DeviceCodeTokenEndpointHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(string(fosite.GrantTypeDeviceCode))
}

func (v DeviceCodeTokenEndpointHandler) CanHandleRequest(requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(string(fosite.GrantTypeDeviceCode))
}

func (c *DeviceCodeTokenEndpointHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	code, signature, err := c.deviceCode(ctx, requester)
	if err != nil {
		return err
	}

	ar, err := c.session(ctx, requester, signature)
	if err != nil {
		// Another request redeemed the device code after this one passed HandleTokenEndpointRequest, which is a second use like any other
		if errors.Is(err, fosite.ErrInvalidatedDeviceCode) {
			return c.revokeTokens(ctx, requester.GetID())
		}
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if err := c.Strategy.DeviceCodeStrategy().ValidateDeviceCode(ctx, ar, code); err != nil {
		return errorsx.WithStack(err)
	}

	for _, scope := range ar.GetGrantedScopes() {
		requester.GrantScope(scope)
	}

	for _, audience := range ar.GetGrantedAudience() {
		requester.GrantAudience(audience)
	}

	accessToken, accessTokenSignature, err := c.Strategy.AccessTokenStrategy().GenerateAccessToken(ctx, requester)
	if err != nil {
		return errors.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	var refreshToken, refreshTokenSignature string
	if c.canIssueRefreshToken(ctx, requester) {
		refreshToken, refreshTokenSignature, err = c.Strategy.RefreshTokenStrategy().GenerateRefreshToken(ctx, requester)
		if err != nil {
			return errors.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	err = c.Storage.Transaction(ctx, func(ctx context.Context) error {
		if err := c.Storage.DeviceAuthStorage().InvalidateDeviceCodeSession(ctx, signature); err != nil {
			return err
		}
		if err := c.Storage.AccessTokenStorage().CreateAccessTokenSession(ctx, accessTokenSignature, requester.Sanitize([]string{})); err != nil {
			return err
		}
		if refreshTokenSignature != "" {
			if err := c.Storage.RefreshTokenStorage().CreateRefreshTokenSession(ctx, refreshTokenSignature, accessTokenSignature, requester.Sanitize([]string{})); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		// The storage reports a device code that another request redeemed in the meantime, which is a second use like any other
		// The tokens are revoked here, after the transaction of this request was rolled back
		if errors.Is(err, fosite.ErrInvalidatedDeviceCode) {
			return c.revokeTokens(ctx, requester.GetID())
		}

		// A storage call inside the transaction may return a deliberate
		// client-facing grant error (e.g. invalid_grant when a device code was
		// already used). Preserve its status instead of masking it as a
		// server error, so a losing concurrent redemption returns 400
		// invalid_grant rather than 500.
		if errors.Is(err, fosite.ErrInvalidGrant) {
			return errorsx.WithStack(err)
		}
		return errors.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	lifeSpan := fosite.GetEffectiveLifespan(requester.GetClient(), c.getGrantType(requester), fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	responder.SetAccessToken(accessToken)
	responder.SetTokenType("bearer")
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, lifeSpan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	if refreshToken != "" {
		responder.SetExtra("refresh_token", refreshToken)
	}

	return nil
}

func (c *DeviceCodeTokenEndpointHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(errorsx.WithStack(fosite.ErrUnknownRequest))
	}

	var err error
	if err = c.validateGrantTypes(requester); err != nil {
		return err
	}

	var code, signature string
	if code, signature, err = c.deviceCode(ctx, requester); err != nil {
		return err
	}

	if err = c.validateCode(ctx, requester, code); err != nil {
		return errorsx.WithStack(err)
	}

	ar, err := c.session(ctx, requester, signature)
	reused := ar != nil && errors.Is(err, fosite.ErrInvalidatedDeviceCode)
	if err != nil && !reused {
		return err
	}

	if err = c.Strategy.DeviceCodeStrategy().ValidateDeviceCode(ctx, ar, code); err != nil {
		return errorsx.WithStack(err)
	}

	// Override scopes
	requester.SetRequestedScopes(ar.GetRequestedScopes())

	// Override audiences
	requester.SetRequestedAudience(ar.GetRequestedAudience())

	// The authorization server MUST ensure that
	// the authorization code was issued to the authenticated confidential client,
	// or if the client is public, ensure that the code was issued to "client_id" in the request
	if ar.GetClient().GetID() != requester.GetClient().GetID() {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the one from the authorize request."))
	}

	// A device code that is used twice ends the grant it was issued for, whose ID is the stored request's and not the one of this request
	// The checks above come first, so this takes the genuine code and the client it was issued to
	if reused {
		return c.revokeTokens(ctx, ar.GetID())
	}

	// Checking of POST client_id skipped, because
	// if the client type is confidential or the client was issued client credentials (or assigned other authentication requirements),
	// the client MUST authenticate with the authorization server as described in Section 3.2.1.
	requester.SetSession(ar.GetSession())
	requester.SetID(ar.GetID())

	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), c.getGrantType(requester), fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	requester.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	rtLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), c.getGrantType(requester), fosite.RefreshToken, c.Config.GetRefreshTokenLifespan(ctx))
	if rtLifespan > -1 {
		requester.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(rtLifespan).Round(time.Second))
	}

	return nil
}

func (c *DeviceCodeTokenEndpointHandler) canIssueRefreshToken(ctx context.Context, requester fosite.Requester) bool {
	scopes := c.Config.GetRefreshTokenScopes(ctx)

	// Require one of the refresh token scopes, if set.
	if len(scopes) > 0 && !requester.GetGrantedScopes().HasOneOf(scopes...) {
		return false
	}

	// Do not issue a refresh token to clients that cannot use the refresh token grant type.
	if !requester.GetClient().GetGrantTypes().Has("refresh_token") {
		return false
	}

	return true
}

// revokeTokens revokes the tokens of the grant whose device code was used twice, and returns the error that answers the request
// The refresh token goes first and both go in one transaction, so a refresh that runs at the same time can't leave a token behind
func (c *DeviceCodeTokenEndpointHandler) revokeTokens(ctx context.Context, reqId string) error {
	invalid := fosite.ErrInvalidGrant.WithHint("The device code has already been used.")
	err := c.Storage.Transaction(ctx, func(ctx context.Context) error {
		if err := c.Storage.TokenRevocationStorage().RevokeRefreshToken(ctx, reqId); err != nil && !errors.Is(err, fosite.ErrNotFound) {
			return err
		}
		if err := c.Storage.TokenRevocationStorage().RevokeAccessToken(ctx, reqId); err != nil && !errors.Is(err, fosite.ErrNotFound) {
			return err
		}
		return nil
	})
	if err != nil {
		invalid = invalid.WithHint("The device code has already been used. Additionally, an error occurred during the revocation of its tokens.").WithDebug(err.Error())
	}
	return errorsx.WithStack(invalid)
}

func (c DeviceCodeTokenEndpointHandler) deviceCode(ctx context.Context, requester fosite.AccessRequester) (code string, signature string, err error) {
	code = requester.GetRequestForm().Get("device_code")

	signature, err = c.Strategy.DeviceCodeStrategy().DeviceCodeSignature(ctx, code)
	if err != nil {
		return "", "", errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return
}

func (c DeviceCodeTokenEndpointHandler) validateCode(ctx context.Context, requester fosite.Requester, code string) error {
	shouldRateLimit, err := c.Strategy.DeviceRateLimitStrategy().ShouldRateLimit(ctx, code)
	if err != nil {
		return err
	}
	if shouldRateLimit {
		return errorsx.WithStack(fosite.ErrSlowDown)
	}
	return nil
}

func (s DeviceCodeTokenEndpointHandler) session(ctx context.Context, requester fosite.AccessRequester, codeSignature string) (fosite.DeviceRequester, error) {
	req, err := s.Storage.DeviceAuthStorage().GetDeviceCodeSession(ctx, codeSignature, requester.GetSession())

	if err != nil && errors.Is(err, fosite.ErrInvalidatedDeviceCode) {
		if req != nil {
			return req, err
		}

		return req, fosite.ErrServerError.
			WithHint("Misconfigured code lead to an error that prohibited the OAuth 2.0 Framework from processing this request.").
			WithDebug("\"GetDeviceCodeSession\" must return a value for \"fosite.Requester\" when returning \"ErrInvalidatedDeviceCode\".")
	}

	if err != nil && errors.Is(err, fosite.ErrNotFound) {
		return nil, errorsx.WithStack(fosite.ErrInvalidGrant.WithWrap(err).WithDebug(err.Error()))
	}

	if err != nil {
		return nil, errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	state := req.GetUserCodeState()

	if state == fosite.UserCodeUnused {
		return nil, fosite.ErrAuthorizationPending
	}
	if state == fosite.UserCodeRejected {
		return nil, fosite.ErrAccessDenied
	}

	return req, err
}

func (v DeviceCodeTokenEndpointHandler) validateGrantTypes(requester fosite.AccessRequester) error {
	if !requester.GetClient().GetGrantTypes().Has(string(fosite.GrantTypeDeviceCode)) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:device_code\"."))
	}

	return nil
}

func (v DeviceCodeTokenEndpointHandler) getGrantType(requester fosite.AccessRequester) fosite.GrantType {
	return fosite.GrantTypeDeviceCode
}

func getExpiresIn(r fosite.Requester, key fosite.TokenType, defaultLifespan time.Duration, now time.Time) time.Duration {
	if r.GetSession().GetExpiresAt(key).IsZero() {
		return defaultLifespan
	}
	return time.Duration(r.GetSession().GetExpiresAt(key).UnixNano() - now.UnixNano())
}
