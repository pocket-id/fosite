// Copyright © 2025 Ory Corp
// Modified by contributors to the Pocket ID fork.
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/ory/x/errorsx"
	"github.com/ory/x/otelx"
	"github.com/pocket-id/fosite/i18n"
	"github.com/pocket-id/fosite/token/jwt"
)

func wrapSigningKeyFailure(outer *RFC6749Error, inner error) *RFC6749Error {
	outer = outer.WithWrap(inner).WithDebug(inner.Error())
	if e := new(RFC6749Error); errors.As(inner, &e) {
		return outer.WithHintf("%s %s", outer.Reason(), e.Reason())
	}
	return outer
}

// requestObjectClaimValue converts a request object claim into its request parameter representation.
// JSON strings, numbers and booleans map to their literal value; structured values such as the OpenID
// Connect "claims" parameter are re-serialized as JSON, matching the OAuth 2.0 query syntax.
func requestObjectClaimValue(v interface{}) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case bool:
		return strconv.FormatBool(t), nil
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), nil
	case json.Number:
		return t.String(), nil
	default:
		value, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(value), nil
	}
}

func (f *Fosite) authorizeRequestParametersFromOpenIDConnectRequest(ctx context.Context, request *AuthorizeRequest, isPARRequest bool) (err error) {
	ctx, span := trace.SpanFromContext(ctx).TracerProvider().Tracer("github.com/pocket-id/fosite").Start(ctx, "Fosite.authorizeRequestParametersFromOpenIDConnectRequest",
		trace.WithAttributes(attribute.Bool("is_par_request", isPARRequest)))
	defer otelx.End(span, &err)

	var scope Arguments = RemoveEmpty(strings.Split(request.Form.Get("scope"), " "))

	// Even if a scope parameter is present in the Request Object value, a scope parameter MUST always be passed using
	// the OAuth 2.0 request syntax containing the openid scope value to indicate to the underlying OAuth 2.0 logic that this is an OpenID Connect request.
	// Source: http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
	if !scope.Has("openid") {
		return nil
	}

	if len(request.Form.Get("request")+request.Form.Get("request_uri")) == 0 {
		return nil
	} else if len(request.Form.Get("request")) > 0 && len(request.Form.Get("request_uri")) > 0 {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("OpenID Connect parameters 'request' and 'request_uri' were both given, but you can use at most one."))
	}

	// Unsigned ("none") request objects carry the same trust as plain query parameters and therefore do not
	// need any client keys, so they are accepted from every client.
	oidcClient, isOIDCClient := request.Client.(OpenIDConnectClient)
	if !isOIDCClient && len(request.Form.Get("request_uri")) > 0 {
		return errorsx.WithStack(ErrRequestURINotSupported.WithHint("OpenID Connect 'request_uri' context was given, but the OAuth 2.0 Client does not implement advanced OpenID Connect capabilities."))
	}

	assertion := request.Form.Get("request")
	if location := request.Form.Get("request_uri"); len(location) > 0 {
		if !slices.Contains(oidcClient.GetRequestURIs(), location) {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf("Request URI '%s' is not whitelisted by the OAuth 2.0 Client.", location))
		}

		// A request_uri taken from a Client ID Metadata Document is attacker-authored, so it must be
		// dereferenced through the SSRF-guarded CIMD transport rather than the authorization
		// server's general HTTP client (section 8.6 covers "any URLs contained within a Client ID
		// Metadata Document").
		var response *http.Response
		var err error
		secure, isCIMDClient := oidcClient.(CIMDSecureFetcher)
		if isCIMDClient {
			response, err = secure.FetchCIMDReferencedURL(ctx, location)
		} else {
			var req *retryablehttp.Request
			req, err = retryablehttp.NewRequestWithContext(ctx, "GET", location, nil)
			if err != nil {
				return errorsx.WithStack(ErrInvalidRequestURI.WithHintf("Unable to fetch OpenID Connect request parameters from 'request_uri' because: %s.", err.Error()).WithWrap(err).WithDebug(err.Error()))
			}
			response, err = f.Config.GetHTTPClient(ctx).Do(req)
		}
		if err != nil {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf("Unable to fetch OpenID Connect request parameters from 'request_uri' because: %s.", err.Error()).WithWrap(err).WithDebug(err.Error()))
		}
		defer func(Body io.ReadCloser) { _ = Body.Close() }(response.Body)
		response.Body = io.NopCloser(io.LimitReader(response.Body, 10*1024*1024)) // limit to 10MiB

		if response.StatusCode != http.StatusOK {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf("Unable to fetch OpenID Connect request parameters from 'request_uri' because status code '%d' was expected, but got '%d'.", http.StatusOK, response.StatusCode))
		}

		bodyReader := io.Reader(response.Body)
		if isCIMDClient {
			bodyReader = io.LimitReader(response.Body, DefaultCIMDReferencedURLMaxSize+1)
		}
		body, err := io.ReadAll(bodyReader)
		if err != nil {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHintf("Unable to fetch OpenID Connect request parameters from 'request_uri' because body parsing failed with: %s.", err).WithWrap(err).WithDebug(err.Error()))
		}
		if isCIMDClient && len(body) > DefaultCIMDReferencedURLMaxSize {
			return errorsx.WithStack(ErrInvalidRequestURI.WithHint("Unable to fetch OpenID Connect request parameters from 'request_uri' because the response exceeds the maximum size."))
		}

		assertion = string(body)
	}

	supportedAlgs := f.Config.GetSupportedRequestObjectSigningAlgorithms(ctx)
	token, err := jwt.ParseWithClaims(assertion, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
		alg := fmt.Sprintf("%s", t.Header["alg"])

		// request_object_signing_alg - OPTIONAL.
		//  JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects sent to the OP. All Request Objects from this Client MUST be rejected,
		// 	if not signed with this algorithm. Request Objects are described in Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core]. This algorithm MUST
		//	be used both when the Request Object is passed by value (using the request parameter) and when it is passed by reference (using the request_uri parameter).
		//	Servers SHOULD support RS256. The value none MAY be used. The default, if omitted, is that any algorithm supported by the OP and the RP MAY be used.
		if isOIDCClient && oidcClient.GetRequestObjectSigningAlgorithm() != "" && oidcClient.GetRequestObjectSigningAlgorithm() != alg {
			return nil, errorsx.WithStack(ErrInvalidRequestObject.WithHintf("The request object uses signing algorithm '%s', but the requested OAuth 2.0 Client enforces signing algorithm '%s'.", alg, oidcClient.GetRequestObjectSigningAlgorithm()))
		}

		if len(supportedAlgs) > 0 && !slices.Contains(supportedAlgs, alg) {
			return nil, errorsx.WithStack(ErrInvalidRequestObject.WithHintf("The request object uses signing algorithm '%s', but the authorization server only supports %v.", alg, supportedAlgs))
		}

		if t.Method == jwt.SigningMethodNone {
			return jwt.UnsafeAllowNoneSignatureType, nil
		}

		if !isOIDCClient {
			return nil, errorsx.WithStack(ErrInvalidRequestObject.WithHintf("The request object is signed with algorithm '%s', but the OAuth 2.0 Client does not implement advanced OpenID Connect capabilities needed to verify signed request objects.", alg))
		}

		if oidcClient.GetJSONWebKeys() == nil && len(oidcClient.GetJSONWebKeysURI()) == 0 {
			return nil, errorsx.WithStack(ErrInvalidRequestObject.WithHintf("The request object is signed with algorithm '%s', but the OAuth 2.0 Client does not have any JSON Web Keys registered.", alg))
		}

		switch t.Method {
		case jose.RS256, jose.RS384, jose.RS512:
			key, err := f.findClientPublicJWK(ctx, oidcClient, t, true)
			if err != nil {
				return nil, wrapSigningKeyFailure(
					ErrInvalidRequestObject.WithHint("Unable to retrieve RSA signing key from OAuth 2.0 Client."), err)
			}
			return key, nil
		case jose.ES256, jose.ES384, jose.ES512:
			key, err := f.findClientPublicJWK(ctx, oidcClient, t, false)
			if err != nil {
				return nil, wrapSigningKeyFailure(
					ErrInvalidRequestObject.WithHint("Unable to retrieve ECDSA signing key from OAuth 2.0 Client."), err)
			}
			return key, nil
		case jose.PS256, jose.PS384, jose.PS512:
			key, err := f.findClientPublicJWK(ctx, oidcClient, t, true)
			if err != nil {
				return nil, wrapSigningKeyFailure(
					ErrInvalidRequestObject.WithHint("Unable to retrieve RSA signing key from OAuth 2.0 Client."), err)
			}
			return key, nil
		default:
			return nil, errorsx.WithStack(ErrInvalidRequestObject.WithHintf("This request object uses unsupported signing algorithm '%s'.", t.Header["alg"]))
		}
	})
	if err != nil {
		var e *jwt.ValidationError
		if !errors.As(err, &e) {
			return err
		}
		if e.Inner != nil {
			// Do not re-process already enhanced errors: keyfunc failures carry RFC 6749 errors.
			if rfcErr := new(RFC6749Error); errors.As(e.Inner, &rfcErr) {
				return e.Inner
			}
			// Claim validation failures (e.g. an elapsed "exp" or future "nbf"/"iat") surface as bare
			// errors and would otherwise be rendered as an unrecognizable server error.
			return errorsx.WithStack(ErrInvalidRequestObject.WithHint("Unable to verify the request object because its claims could not be validated, check if the expiry time is set correctly.").WithWrap(e.Inner).WithDebug(e.Inner.Error()))
		}
		return errorsx.WithStack(ErrInvalidRequestObject.WithHint("Unable to verify the request object's signature.").WithWrap(err).WithDebug(err.Error()))
	} else if err := token.Claims.Valid(); err != nil {
		return errorsx.WithStack(ErrInvalidRequestObject.WithHint("Unable to verify the request object because its claims could not be validated, check if the expiry time is set correctly.").WithWrap(err).WithDebug(err.Error()))
	}

	claims := token.Claims
	// Reject the request if the "request_uri" authorization request
	// parameter is provided.
	if requestURI, _ := claims["request_uri"].(string); isPARRequest && requestURI != "" {
		return errorsx.WithStack(ErrInvalidRequestObject.WithHint("Pushed Authorization Requests can not contain the 'request_uri' parameter."))
	}

	// OpenID Connect Core 1.0 section 6.1 requires the client_id claim, when present in the request
	// object, to be identical to the client_id request parameter the client was resolved from. A
	// non-string claim can never match a client ID and must not slip past into the merged form.
	if rawClientID, hasClientID := claims["client_id"]; hasClientID {
		clientID, isString := rawClientID.(string)
		if !isString || (request.Client != nil && clientID != request.Client.GetID()) {
			return errorsx.WithStack(ErrInvalidRequestObject.WithHint("The request object contains a 'client_id' claim that does not match the 'client_id' request parameter."))
		}
	}

	for k, v := range claims {
		// Request objects must not nest further request objects (OpenID Connect Core 1.0 section 6.1),
		// so these claims are never mapped back to the parameters they would shadow.
		if k == "request" || k == "request_uri" {
			continue
		}
		value, err := requestObjectClaimValue(v)
		if err != nil {
			return errorsx.WithStack(ErrInvalidRequestObject.WithHintf("The request object claim '%s' could not be interpreted as a request parameter.", k).WithWrap(err).WithDebug(err.Error()))
		}
		request.Form.Set(k, value)
	}

	// A scope claim in the request object supersedes the outer scope parameter entirely instead of
	// being unioned with it: request object values take precedence (OpenID Connect Core 1.0 section
	// 6.1) and RFC 9101 section 6.3 requires using only the request object's value when both are set.
	request.State = request.Form.Get("state")
	return nil
}

func (f *Fosite) validateAuthorizeRedirectURI(ctx context.Context, request *AuthorizeRequest) (err error) {
	ctx, span := trace.SpanFromContext(ctx).TracerProvider().Tracer("github.com/pocket-id/fosite").Start(ctx, "Fosite.validateAuthorizeRedirectURI")
	_ = ctx
	defer otelx.End(span, &err)

	// Fetch redirect URI from request
	rawRedirURI := request.Form.Get("redirect_uri")

	// This ensures that the 'redirect_uri' parameter is present for OpenID Connect 1.0 authorization requests as per:
	//
	// Authorization Code Flow - https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	// Implicit Flow - https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest
	// Hybrid Flow - https://openid.net/specs/openid-connect-core-1_0.html#HybridAuthRequest
	//
	// Note: as per the Hybrid Flow documentation the Hybrid Flow has the same requirements as the Authorization Code Flow.
	if len(rawRedirURI) == 0 && request.GetRequestedScopes().Has("openid") {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("The 'redirect_uri' parameter is required when using OpenID Connect 1.0."))
	}

	// Validate redirect uri
	redirectURI, err := request.matchRedirectURI(rawRedirURI)
	if err != nil {
		return err
	} else if !IsValidRedirectURI(redirectURI) {
		return errorsx.WithStack(ErrInvalidRequest.WithHintf("The redirect URI '%s' contains an illegal character (for example #) or is otherwise invalid.", redirectURI))
	}
	request.RedirectURI = redirectURI
	return nil
}

func (f *Fosite) parseAuthorizeScope(_ *http.Request, request *AuthorizeRequest) error {
	request.SetRequestedScopes(RemoveEmpty(strings.Split(request.Form.Get("scope"), " ")))

	return nil
}

var defaultAuthorizePromptValues = []string{"login", "none", "consent", "select_account"}

func (f *Fosite) validateAuthorizePrompt(ctx context.Context, request *AuthorizeRequest) error {
	if !request.GetRequestedScopes().Has("openid") {
		return nil
	}

	requiredPrompt := RemoveEmpty(strings.Split(request.GetRequestForm().Get("prompt"), " "))
	if len(requiredPrompt) == 0 {
		return nil
	}

	availablePrompts := f.Config.GetAllowedPrompts(ctx)
	if len(availablePrompts) == 0 {
		availablePrompts = defaultAuthorizePromptValues
	}

	for _, prompt := range requiredPrompt {
		if !slices.Contains(availablePrompts, prompt) {
			return errorsx.WithStack(ErrInvalidRequest.WithHintf("Used unknown value '%s' for prompt parameter", requiredPrompt))
		}
	}

	if slices.Contains(requiredPrompt, "none") && len(requiredPrompt) > 1 {
		return errorsx.WithStack(ErrInvalidRequest.WithHint("Parameter 'prompt' was set to 'none', but contains other values as well which is not allowed."))
	}

	return nil
}

func (f *Fosite) validateAuthorizeScope(ctx context.Context, _ *http.Request, request *AuthorizeRequest) error {
	for _, permission := range request.GetRequestedScopes() {
		if !f.Config.GetScopeStrategy(ctx)(request.Client.GetScopes(), permission) {
			return errorsx.WithStack(ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", permission))
		}
	}

	return nil
}

func (f *Fosite) validateResponseTypes(r *http.Request, request *AuthorizeRequest) error {
	// https://tools.ietf.org/html/rfc6749#section-3.1.1
	// Extension response types MAY contain a space-delimited (%x20) list of
	// values, where the order of values does not matter (e.g., response
	// type "a b" is the same as "b a").  The meaning of such composite
	// response types is defined by their respective specifications.
	responseTypes := RemoveEmpty(strings.Split(r.Form.Get("response_type"), " "))
	if len(responseTypes) == 0 {
		return errorsx.WithStack(ErrUnsupportedResponseType.WithHint("`The request is missing the 'response_type' parameter."))
	}

	var found bool
	for _, t := range request.GetClient().GetResponseTypes() {
		if Arguments(responseTypes).Matches(RemoveEmpty(strings.Split(t, " "))...) {
			found = true
			break
		}
	}

	if !found {
		return errorsx.WithStack(ErrUnsupportedResponseType.WithHintf("The client is not allowed to request response_type '%s'.", r.Form.Get("response_type")))
	}

	request.ResponseTypes = responseTypes
	return nil
}

func (f *Fosite) ParseResponseMode(ctx context.Context, r *http.Request, request *AuthorizeRequest) error {
	switch responseMode := r.Form.Get("response_mode"); responseMode {
	case string(ResponseModeDefault):
		request.ResponseMode = ResponseModeDefault
	case string(ResponseModeFragment):
		request.ResponseMode = ResponseModeFragment
	case string(ResponseModeQuery):
		request.ResponseMode = ResponseModeQuery
	case string(ResponseModeFormPost):
		request.ResponseMode = ResponseModeFormPost
	default:
		rm := ResponseModeType(responseMode)
		if f.ResponseModeHandler(ctx).ResponseModes().Has(rm) {
			request.ResponseMode = rm
			break
		}
		return errorsx.WithStack(ErrUnsupportedResponseMode.WithHintf("Request with unsupported response_mode \"%s\".", responseMode))
	}

	return nil
}

func (f *Fosite) validateResponseMode(r *http.Request, request *AuthorizeRequest) error {
	if request.ResponseMode == ResponseModeDefault {
		return nil
	}

	responseModeClient, ok := request.GetClient().(ResponseModeClient)
	if !ok {
		return errorsx.WithStack(ErrUnsupportedResponseMode.WithHintf("The request has response_mode \"%s\". set but registered OAuth 2.0 client doesn't support response_mode", r.Form.Get("response_mode")))
	}

	var found bool
	for _, t := range responseModeClient.GetResponseModes() {
		if request.ResponseMode == t {
			found = true
			break
		}
	}

	if !found {
		return errorsx.WithStack(ErrUnsupportedResponseMode.WithHintf("The client is not allowed to request response_mode '%s'.", r.Form.Get("response_mode")))
	}

	return nil
}

func (f *Fosite) authorizeRequestFromPAR(ctx context.Context, r *http.Request, request *AuthorizeRequest) (bool, error) {
	configProvider, ok := f.Config.(PushedAuthorizeRequestConfigProvider)
	if !ok {
		// If the config provider is not implemented, PAR cannot be used.
		return false, nil
	}

	requestURI := r.Form.Get("request_uri")
	if requestURI == "" || !strings.HasPrefix(requestURI, configProvider.GetPushedAuthorizeRequestURIPrefix(ctx)) {
		// nothing to do here
		return false, nil
	}

	clientID := r.Form.Get("client_id")

	storage, ok := f.Store.(PARStorageProvider)
	if !ok {
		return false, errorsx.WithStack(ErrServerError.WithHint(ErrorPARNotSupported).WithDebug(DebugPARStorageInvalid))
	}

	// hydrate the requester
	var parRequest AuthorizeRequester
	var err error
	if parRequest, err = storage.PARStorage().GetPARSession(ctx, requestURI); err != nil {
		return false, errorsx.WithStack(ErrInvalidRequestURI.WithHint("Invalid PAR session").WithWrap(err).WithDebug(err.Error()))
	}

	// hydrate the request object
	request.Merge(parRequest)
	request.RedirectURI = parRequest.GetRedirectURI()
	request.ResponseTypes = parRequest.GetResponseTypes()
	request.State = parRequest.GetState()
	request.ResponseMode = parRequest.GetResponseMode()

	if err := storage.PARStorage().DeletePARSession(ctx, requestURI); err != nil {
		return false, errorsx.WithStack(ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// validate the clients match
	if clientID != request.GetClient().GetID() {
		return false, errorsx.WithStack(ErrInvalidRequest.WithHint("The 'client_id' must match the one sent in the pushed authorization request."))
	}

	return true, nil
}

func (f *Fosite) prepareAuthorizeRequestForErrorRedirect(ctx context.Context, r *http.Request, request *AuthorizeRequest) {
	if request.GetClient() == nil || request.GetRedirectURI() != nil {
		return
	}

	if err := f.ParseResponseMode(ctx, r, request); err != nil {
		request.ResponseMode = ResponseModeDefault
	}

	if err := f.validateAuthorizeRedirectURI(ctx, request); err != nil {
		return
	}

	if request.GetResponseMode() == ResponseModeDefault {
		responseTypes := RemoveEmpty(strings.Split(request.Form.Get("response_type"), " "))
		if Arguments(responseTypes).ExactOne("code") {
			request.SetDefaultResponseMode(ResponseModeQuery)
		} else {
			request.SetDefaultResponseMode(ResponseModeFragment)
		}
	}
}

func (f *Fosite) NewAuthorizeRequest(ctx context.Context, r *http.Request) (_ AuthorizeRequester, err error) {
	ctx, span := trace.SpanFromContext(ctx).TracerProvider().Tracer("github.com/pocket-id/fosite").Start(ctx, "Fosite.NewAuthorizeRequest",
		trace.WithAttributes(attribute.Bool("is_par_request", false)))
	defer otelx.End(span, &err)

	return f.newAuthorizeRequest(ctx, r, false)
}

func (f *Fosite) newAuthorizeRequest(ctx context.Context, r *http.Request, isPARRequest bool) (AuthorizeRequester, error) {
	request := NewAuthorizeRequest()
	request.RedirectURIMatcher = f.Config.GetRedirectURIMatcher(ctx)
	request.Request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), r)

	ctx = context.WithValue(ctx, RequestContextKey, r)
	ctx = context.WithValue(ctx, AuthorizeRequestContextKey, request)

	if err := r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebug(err.Error()))
	}
	request.Form = r.Form

	// Save state to the request to be returned in error conditions (https://github.com/ory/hydra/issues/1642)
	request.State = request.Form.Get("state")

	// Check if this is a continuation from a pushed authorization request
	if !isPARRequest {
		if isPAR, err := f.authorizeRequestFromPAR(ctx, r, request); err != nil {
			return request, err
		} else if isPAR {
			// No need to continue
			return request, nil
		} else if configProvider, ok := f.Config.(PushedAuthorizeRequestConfigProvider); ok && configProvider.EnforcePushedAuthorize(ctx) {
			return request, errorsx.WithStack(ErrInvalidRequest.WithHint("Pushed Authorization Requests are enforced but no such request was sent."))
		}
	}

	client, err := f.resolveClient(ctx, request.GetRequestForm().Get("client_id"))
	if err != nil {
		if errors.Is(err, ErrCIMDTemporarilyUnavailable) {
			return request, errorsx.WithStack(clientLookupError(err))
		}
		hint := "The requested OAuth 2.0 Client does not exist."
		if errors.Is(err, errCIMDNoStoreUnsupported) {
			hint = "The client metadata document uses Cache-Control: no-store, but this authorization server requires metadata caching. Allow the document to be cached and try again."
		}
		return request, errorsx.WithStack(ErrInvalidClient.WithHint(hint).WithWrap(err).WithDebug(err.Error()))
	}
	request.Client = client

	// Now that the base fields (state and client) are populated, we extract all the information
	// from the request object or request object uri, if one is set.
	//
	// All other parse methods should come afterwards so that we ensure that the data is taken
	// from the request_object if set.
	if err := f.authorizeRequestParametersFromOpenIDConnectRequest(ctx, request, isPARRequest); err != nil {
		f.prepareAuthorizeRequestForErrorRedirect(ctx, r, request)
		return request, err
	}

	// The request context is now fully available and we can start processing the individual
	// fields.
	if err := f.ParseResponseMode(ctx, r, request); err != nil {
		return request, err
	}

	if err = f.parseAuthorizeScope(r, request); err != nil {
		return request, err
	}

	// Unknown scopes are dropped before the redirect URI validation so that its OpenID Connect
	// redirect_uri requirement and the later prompt validation only consider scopes the request
	// can actually be granted. Dropping cannot fail, so error redirectability is unaffected.
	if f.Config.GetIgnoreUnknownScopes(ctx) {
		scopes, _ := FilterRequestedScopes(f.Config.GetScopeStrategy(ctx), request.Client, request.GetRequestedScopes(), true)
		request.SetRequestedScopes(scopes)
	}

	if err = f.validateAuthorizeRedirectURI(ctx, request); err != nil {
		return request, err
	}

	if err = f.validateAuthorizeScope(ctx, r, request); err != nil {
		return request, err
	}

	if _, err = ValidateResourceIndicator(request.GetRequestForm()); err != nil {
		return request, err
	}

	if len(request.Form.Get("registration")) > 0 {
		return request, errorsx.WithStack(ErrRegistrationNotSupported)
	}

	if err = f.validateResponseTypes(r, request); err != nil {
		return request, err
	}

	if err = f.validateResponseMode(r, request); err != nil {
		return request, err
	}

	// A fallback handler to set the default response mode in cases where we can not reach the Authorize Handlers
	// but still need the e.g. correct error response mode.
	if request.GetResponseMode() == ResponseModeDefault {
		if request.ResponseTypes.ExactOne("code") {
			request.SetDefaultResponseMode(ResponseModeQuery)
		} else {
			// If the response type is not `code` it is an implicit/hybrid (fragment) response mode.
			request.SetDefaultResponseMode(ResponseModeFragment)
		}
	}

	if err = f.validateAuthorizePrompt(ctx, request); err != nil {
		return request, err
	}

	// rfc6819 4.4.1.8.  Threat: CSRF Attack against redirect-uri
	// The "state" parameter should be used to link the authorization
	// request with the redirect URI used to deliver the access token (Section 5.3.5).
	//
	// https://tools.ietf.org/html/rfc6819#section-4.4.1.8
	// The "state" parameter should not	be guessable
	if len(request.State) < f.GetMinParameterEntropy(ctx) {
		// We're assuming that using less then, by default, 8 characters for the state can not be considered "unguessable"
		return request, errorsx.WithStack(ErrInvalidState.WithHintf("Request parameter 'state' must be at least be %d characters long to ensure sufficient entropy.", f.GetMinParameterEntropy(ctx)))
	}

	return request, nil
}
