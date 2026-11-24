// Copyright © 2025 Ory Corp
// Modified by contributors to the Pocket ID fork.
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"github.com/ory/x/errorsx"
	"github.com/pocket-id/fosite"

	"github.com/pkg/errors"
)

// HandleTokenEndpointRequest implements
// * https://tools.ietf.org/html/rfc6749#section-4.1.3 (everything)
func (c *AuthorizeExplicitGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(errorsx.WithStack(fosite.ErrUnknownRequest))
	}

	if !request.GetClient().GetGrantTypes().Has("authorization_code") {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"authorization_code\"."))
	}

	code := request.GetRequestForm().Get("code")
	signature := c.Strategy.AuthorizeCodeStrategy().AuthorizeCodeSignature(ctx, code)
	authorizeRequest, err := c.Storage.AuthorizeCodeStorage().GetAuthorizeCodeSession(ctx, code, signature, request.GetSession())
	reused := errors.Is(err, fosite.ErrInvalidatedAuthorizeCode)
	if reused && authorizeRequest == nil {
		return fosite.ErrServerError.
			WithHint("Misconfigured code lead to an error that prohibited the OAuth 2.0 Framework from processing this request.").
			WithDebug("GetAuthorizeCodeSession must return a value for \"fosite.Requester\" when returning \"ErrInvalidatedAuthorizeCode\".")
	} else if err != nil && errors.Is(err, fosite.ErrNotFound) {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithWrap(err).WithDebug(err.Error()))
	} else if err != nil && !reused {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// The authorization server MUST verify that the authorization code is valid
	// The stored request carries the session the code was issued with, which holds its expiry
	if err := c.Strategy.AuthorizeCodeStrategy().ValidateAuthorizeCode(ctx, authorizeRequest, code); err != nil {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithWrap(err).WithDebug(err.Error()))
	}

	// Override scopes
	request.SetRequestedScopes(authorizeRequest.GetRequestedScopes())

	// Override audiences
	request.SetRequestedAudience(authorizeRequest.GetRequestedAudience())

	// The authorization server MUST ensure that the authorization code was issued to the authenticated
	// confidential client, or if the client is public, ensure that the
	// code was issued to "client_id" in the request,
	if authorizeRequest.GetClient().GetID() != request.GetClient().GetID() {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the one from the authorize request."))
	}

	// A code that is used twice ends the grant it was issued for
	// The checks above come first, so this takes the genuine code and the client it was issued to
	if reused {
		return c.reusedCode(ctx, authorizeRequest.GetID())
	}

	// ensure that the "redirect_uri" parameter is present if the
	// "redirect_uri" parameter was included in the initial authorization
	// request as described in Section 4.1.1, and if included ensure that
	// their values are identical.
	forcedRedirectURI := authorizeRequest.GetRequestForm().Get("redirect_uri")
	if forcedRedirectURI != "" && forcedRedirectURI != request.GetRequestForm().Get("redirect_uri") {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The \"redirect_uri\" from this request does not match the one from the authorize request."))
	}

	// Checking of POST client_id skipped, because:
	// If the client type is confidential or the client was issued client
	// credentials (or assigned other authentication requirements), the
	// client MUST authenticate with the authorization server as described
	// in Section 3.2.1.
	request.SetSession(authorizeRequest.GetSession())
	request.SetID(authorizeRequest.GetID())

	atLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	request.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	rtLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.RefreshToken, c.Config.GetRefreshTokenLifespan(ctx))
	if rtLifespan > -1 {
		request.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(rtLifespan).Round(time.Second))
	}

	return nil
}

// reusedCode revokes the tokens of the grant whose code was used twice, and returns the error that answers the request
// The refresh token goes first and both go in one transaction, so a refresh that runs at the same time can't leave a token behind
func (c *AuthorizeExplicitGrantHandler) reusedCode(ctx context.Context, requestID string) error {
	invalid := fosite.ErrInvalidGrant.WithHint("The authorization code has already been used.")
	err := c.Storage.Transaction(ctx, func(ctx context.Context) error {
		if err := c.Storage.TokenRevocationStorage().RevokeRefreshToken(ctx, requestID); err != nil && !errors.Is(err, fosite.ErrNotFound) {
			return err
		}
		if err := c.Storage.TokenRevocationStorage().RevokeAccessToken(ctx, requestID); err != nil && !errors.Is(err, fosite.ErrNotFound) {
			return err
		}
		return nil
	})
	if err != nil {
		invalid = invalid.WithHint("The authorization code has already been used. Additionally, an error occurred during the revocation of its tokens.").WithDebug(err.Error())
	}
	return errorsx.WithStack(invalid)
}

func canIssueRefreshToken(ctx context.Context, c *AuthorizeExplicitGrantHandler, request fosite.Requester) bool {
	scope := c.Config.GetRefreshTokenScopes(ctx)
	// Require one of the refresh token scopes, if set.
	if len(scope) > 0 && !request.GetGrantedScopes().HasOneOf(scope...) {
		return false
	}
	// Do not issue a refresh token to clients that cannot use the refresh token grant type.
	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return false
	}
	return true
}

func (c *AuthorizeExplicitGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	code := requester.GetRequestForm().Get("code")
	signature := c.Strategy.AuthorizeCodeStrategy().AuthorizeCodeSignature(ctx, code)
	authorizeRequest, err := c.Storage.AuthorizeCodeStorage().GetAuthorizeCodeSession(ctx, code, signature, requester.GetSession())
	if err != nil {
		// Another request redeemed the code after this one passed HandleTokenEndpointRequest, which is a second use like any other
		if errors.Is(err, fosite.ErrInvalidatedAuthorizeCode) {
			return c.reusedCode(ctx, requester.GetID())
		}
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if err := c.Strategy.AuthorizeCodeStrategy().ValidateAuthorizeCode(ctx, requester, code); err != nil {
		// This needs to happen after store retrieval for the session to be hydrated properly
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithWrap(err).WithDebug(err.Error()))
	}

	for _, scope := range authorizeRequest.GetGrantedScopes() {
		requester.GrantScope(scope)
	}

	for _, audience := range authorizeRequest.GetGrantedAudience() {
		requester.GrantAudience(audience)
	}

	access, accessSignature, err := c.Strategy.AccessTokenStrategy().GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	var refresh, refreshSignature string
	if canIssueRefreshToken(ctx, c, authorizeRequest) {
		refresh, refreshSignature, err = c.Strategy.RefreshTokenStrategy().GenerateRefreshToken(ctx, requester)
		if err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	err = c.Storage.Transaction(ctx, func(ctx context.Context) error {
		if err := c.Storage.AuthorizeCodeStorage().InvalidateAuthorizeCodeSession(ctx, code, signature); err != nil {
			return err
		}
		if err := c.Storage.AccessTokenStorage().CreateAccessTokenSession(ctx, accessSignature, requester.Sanitize([]string{})); err != nil {
			return err
		}
		if refreshSignature != "" {
			if err := c.Storage.RefreshTokenStorage().CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, requester.Sanitize([]string{})); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		// The storage reports a code that another request redeemed in the meantime, which is a second use like any other
		// The tokens are revoked here, after the transaction of this request was rolled back
		if errors.Is(err, fosite.ErrInvalidatedAuthorizeCode) {
			return c.reusedCode(ctx, requester.GetID())
		}

		// A storage call inside the transaction may return a deliberate
		// client-facing grant error (e.g. invalid_grant when a code was
		// already used). Preserve its status instead of masking it as a
		// server error, so a losing concurrent redemption returns 400
		// invalid_grant rather than 500.
		if errors.Is(err, fosite.ErrInvalidGrant) {
			return errorsx.WithStack(err)
		}
		return errors.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	responder.SetAccessToken(access)
	responder.SetTokenType("bearer")
	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, atLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	if refresh != "" {
		responder.SetExtra("refresh_token", refresh)
	}

	return nil
}

func (c *AuthorizeExplicitGrantHandler) CanSkipClientAuth(_ context.Context, _ fosite.AccessRequester) bool {
	return false
}

func (c *AuthorizeExplicitGrantHandler) CanHandleTokenEndpointRequest(_ context.Context, requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "authorization_code"
	return requester.GetGrantTypes().ExactOne("authorization_code")
}
