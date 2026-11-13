// Copyright © 2026 Pocket ID
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/go-jose/go-jose/v4"
	"github.com/hashicorp/go-retryablehttp"
)

// ErrCIMDTemporarilyUnavailable marks a metadata document that could not be retrieved for a reason that may pass, such as a network error or a timeout
// Such a failure says nothing about the client, so trust in it and its cached metadata should survive
var ErrCIMDTemporarilyUnavailable = errors.New("client metadata document is temporarily unavailable")

// ErrCIMDClientIDMismatch marks a retrieved document whose client_id is not the URL it was fetched from
var ErrCIMDClientIDMismatch = errors.New("client_id does not match the client metadata document URL")

// ErrCIMDFetchRefused marks a request for a metadata document that was refused because of where it would go
// A transport that guards destinations itself returns an error matching it, so the refusal is not taken for a host that is temporarily unreachable
var ErrCIMDFetchRefused = errors.New("request for the client metadata document was refused")

// LooksLikeCIMDURL reports whether clientID is a candidate Client Identifier URL.
//
// A URL-shaped identifier is not necessarily backed by a Client ID Metadata
// Document. Callers must give pre-registered clients precedence before attempting
// metadata discovery.
func LooksLikeCIMDURL(clientID string) bool {
	u, err := url.Parse(clientID)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "https") && u.Hostname() != ""
}

// ParseCIMDURL parses and validates a Client Identifier URL.
func ParseCIMDURL(clientID string) (*url.URL, error) {
	u, err := url.Parse(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client_id URL: %w", err)
	}
	if err := ValidateCIMDURL(u); err != nil {
		return nil, err
	}
	if strings.Contains(clientID, "#") {
		return nil, errors.New("client_id URL must not contain a fragment")
	}
	return u, nil
}

// ValidateCIMDURL enforces the Client Identifier URL requirements from draft-ietf-oauth-client-id-metadata-document-03 section 3.
func ValidateCIMDURL(u *url.URL) error {
	if u == nil {
		return errors.New("client_id URL is required")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return errors.New("client_id URL must use the https scheme")
	}
	if u.Hostname() == "" {
		return errors.New("client_id URL must have a host")
	}
	if u.User != nil {
		return errors.New("client_id URL must not contain userinfo")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return errors.New("client_id URL must not contain a fragment")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return errors.New("client_id URL must not contain a query component")
	}
	if u.Path == "" || u.Path == "/" {
		return errors.New("client_id URL must contain a path component other than /")
	}
	for seg := range strings.SplitSeq(u.Path, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("client_id URL must not contain %q path segments", seg)
		}
	}
	return nil
}

// ClientMetadataDocument contains registered OAuth client metadata published at a Client Identifier URL.
//
// AdditionalMetadata preserves registered extensions and future metadata members
// that this version of Fosite does not interpret.
type ClientMetadataDocument struct {
	ClientID                          string                     `json:"client_id"`
	RedirectURIs                      []string                   `json:"redirect_uris"`
	TokenEndpointAuthMethod           string                     `json:"token_endpoint_auth_method"`
	TokenEndpointAuthMethodsSupported []string                   `json:"token_endpoint_auth_methods_supported"`
	GrantTypes                        []string                   `json:"grant_types"`
	ResponseTypes                     []string                   `json:"response_types"`
	ClientName                        string                     `json:"client_name"`
	ClientURI                         string                     `json:"client_uri"`
	LogoURI                           string                     `json:"logo_uri"`
	Scope                             string                     `json:"scope"`
	Contacts                          []string                   `json:"contacts"`
	TOSURI                            string                     `json:"tos_uri"`
	PolicyURI                         string                     `json:"policy_uri"`
	JWKSURI                           string                     `json:"jwks_uri"`
	JWKS                              *jose.JSONWebKeySet        `json:"jwks"`
	SoftwareID                        string                     `json:"software_id"`
	SoftwareVersion                   string                     `json:"software_version"`
	SoftwareStatement                 string                     `json:"software_statement"`
	RequestURIs                       []string                   `json:"request_uris"`
	RequestObjectSigningAlgorithm     string                     `json:"request_object_signing_alg"`
	TokenEndpointAuthSigningAlg       string                     `json:"token_endpoint_auth_signing_alg"`
	PostLogoutRedirectURIs            []string                   `json:"post_logout_redirect_uris"`
	AdditionalMetadata                map[string]json.RawMessage `json:"-"`

	// Presence of these values is forbidden by the CIMD credential restrictions.
	ClientSecret          *string `json:"client_secret"`
	ClientSecretExpiresAt *int64  `json:"client_secret_expires_at"`
}

// UnmarshalJSON decodes known metadata and retains unrecognized members for provider policy and change detection.
func (d *ClientMetadataDocument) UnmarshalJSON(data []byte) error {
	type documentAlias ClientMetadataDocument

	var decoded documentAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	var additional map[string]json.RawMessage
	if err := json.Unmarshal(data, &additional); err != nil {
		return err
	}
	for _, key := range clientMetadataDocumentKnownFields {
		delete(additional, key)
	}
	if len(additional) == 0 {
		additional = nil
	}

	*d = ClientMetadataDocument(decoded)
	d.AdditionalMetadata = additional
	return nil
}

var clientMetadataDocumentKnownFields = []string{
	"client_id",
	"redirect_uris",
	"token_endpoint_auth_method",
	"token_endpoint_auth_methods_supported",
	"grant_types",
	"response_types",
	"client_name",
	"client_uri",
	"logo_uri",
	"scope",
	"contacts",
	"tos_uri",
	"policy_uri",
	"jwks_uri",
	"jwks",
	"software_id",
	"software_version",
	"software_statement",
	"request_uris",
	"request_object_signing_alg",
	"token_endpoint_auth_signing_alg",
	"post_logout_redirect_uris",
	"client_secret",
	"client_secret_expires_at",
}

// TokenEndpointAuthMethods returns the token endpoint authentication methods the client declares, of which the authorization server picks one it supports
// The token_endpoint_auth_methods_supported list replaces the legacy token_endpoint_auth_method, and a document with neither declares "none" instead of the RFC 7591 default
func (d *ClientMetadataDocument) TokenEndpointAuthMethods() []string {
	if d.TokenEndpointAuthMethodsSupported != nil {
		return d.TokenEndpointAuthMethodsSupported
	}
	if d.TokenEndpointAuthMethod != "" {
		return []string{d.TokenEndpointAuthMethod}
	}
	return []string{"none"}
}

// Validate checks the protocol-level CIMD invariants against the URL used to retrieve the document.
func (d *ClientMetadataDocument) Validate(clientID string) error {
	if d == nil {
		return errors.New("client metadata document is required")
	}
	if _, err := ParseCIMDURL(clientID); err != nil {
		return fmt.Errorf("invalid client_id in metadata document: %w", err)
	}
	// A document without a client_id is malformed, which unlike a mismatch says nothing about who controls the URL
	if d.ClientID == "" {
		return errors.New("client metadata document must contain a client_id")
	}
	if d.ClientID != clientID {
		return fmt.Errorf("%w: the document at %q declares %q", ErrCIMDClientIDMismatch, clientID, d.ClientID)
	}

	// An omitted list takes its RFC 7591 default, but an explicitly empty one declares nothing the server could support
	if (d.GrantTypes != nil && len(d.GrantTypes) == 0) || (d.ResponseTypes != nil && len(d.ResponseTypes) == 0) {
		return errors.New("client metadata document must not contain an empty grant_types or response_types")
	}
	if d.ClientSecret != nil || d.ClientSecretExpiresAt != nil {
		return errors.New("client metadata document must not contain a client secret")
	}
	// A document cannot establish a shared secret, so neither field may name a symmetric method
	for _, method := range append([]string{d.TokenEndpointAuthMethod}, d.TokenEndpointAuthMethodsSupported...) {
		switch method {
		case "client_secret_basic", "client_secret_post", "client_secret_jwt":
			return fmt.Errorf("client metadata document must not use symmetric authentication method %q", method)
		}
	}
	if d.JWKS != nil && d.JWKSURI != "" {
		return errors.New("client metadata document must not contain both jwks and jwks_uri")
	}
	if d.JWKS != nil {
		for i := range d.JWKS.Keys {
			if !d.JWKS.Keys[i].IsPublic() {
				return errors.New("client metadata document must not contain private key material")
			}
		}
	}
	if slices.Contains(d.TokenEndpointAuthMethods(), "private_key_jwt") && d.JWKS == nil && d.JWKSURI == "" {
		return errors.New("private_key_jwt requires jwks or jwks_uri")
	}
	return d.validateRedirectURIs()
}

// validateRedirectURIs enforces the registration requirement of section 4.2 and RFC 7591 section 5.
//
// Rejecting malformed entries here attributes the error to the document, rather than surfacing it
// much later as an unrelated "redirect_uri is not registered" failure in the authorize flow.
func (d *ClientMetadataDocument) validateRedirectURIs() error {
	// RFC 7591 section 2 defaults an omitted grant_types to authorization_code.
	grantTypes := d.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}
	needsRedirect := slices.Contains(grantTypes, "authorization_code") || slices.Contains(grantTypes, "implicit")
	if needsRedirect && len(d.RedirectURIs) == 0 {
		return errors.New("client metadata document must contain redirect_uris for redirect-based grant types")
	}

	for _, raw := range d.RedirectURIs {
		u, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("client metadata document has an invalid redirect_uris entry %q: %w", raw, err)
		}
		if !u.IsAbs() {
			return fmt.Errorf("redirect_uris entry %q must be an absolute URI", raw)
		}
		if u.Fragment != "" || u.RawFragment != "" || strings.Contains(raw, "#") {
			return fmt.Errorf("redirect_uris entry %q must not contain a fragment", raw)
		}
	}

	return nil
}

// CIMDClient is the standard Fosite projection of a Client ID Metadata Document.
type CIMDClient struct {
	*DefaultOpenIDConnectClient
	Document *ClientMetadataDocument

	// mu guards the lazily installed fetch fields below. A cache that hands the same *CIMDClient
	// to concurrent resolutions would otherwise race on first use.
	mu          sync.Mutex
	jwksFetcher JWKSFetcherStrategy
	validateURL func(context.Context, string) error
	httpClient  *http.Client
}

// CIMDSecureFetcher is implemented by clients whose document-supplied URLs must be dereferenced
// through the SSRF-guarded transport rather than the authorization server's general HTTP client.
type CIMDSecureFetcher interface {
	FetchCIMDReferencedURL(ctx context.Context, rawURL string) (*http.Response, error)
}

// CIMDJWKSResolver resolves keys referenced by a metadata client through its guarded fetcher.
type CIMDJWKSResolver interface {
	ResolveCIMDJSONWebKeys(context.Context, bool) (*jose.JSONWebKeySet, error)
}

// NewCIMDClient projects protocol-defined client metadata into Fosite's standard client interfaces.
//
// Authorization-server policy may wrap or transform the returned client to
// restrict grants, scopes, audiences, or other locally controlled behavior.
func NewCIMDClient(doc *ClientMetadataDocument) (*CIMDClient, error) {
	if doc == nil {
		return nil, errors.New("client metadata document is required")
	}
	if err := doc.Validate(doc.ClientID); err != nil {
		return nil, err
	}

	// A client that declares private_key_jwt must authenticate with it, and every other client has to be usable as a public one
	methods := doc.TokenEndpointAuthMethods()
	authMethod := "none"
	if slices.Contains(methods, "private_key_jwt") {
		authMethod = "private_key_jwt"
	} else if !slices.Contains(methods, "none") {
		return nil, fmt.Errorf("client metadata document declares no supported token endpoint authentication method: %q", methods)
	}

	grantTypes := append([]string(nil), doc.GrantTypes...)
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}
	responseTypes := append([]string(nil), doc.ResponseTypes...)
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	return &CIMDClient{
		DefaultOpenIDConnectClient: &DefaultOpenIDConnectClient{
			DefaultClient: &DefaultClient{
				ID:            doc.ClientID,
				RedirectURIs:  append([]string(nil), doc.RedirectURIs...),
				GrantTypes:    grantTypes,
				ResponseTypes: responseTypes,
				Scopes:        strings.Fields(doc.Scope),
				Public:        authMethod == "none",
			},
			JSONWebKeysURI:                    doc.JWKSURI,
			JSONWebKeys:                       doc.JWKS,
			TokenEndpointAuthMethod:           authMethod,
			RequestURIs:                       append([]string(nil), doc.RequestURIs...),
			RequestObjectSigningAlgorithm:     doc.RequestObjectSigningAlgorithm,
			TokenEndpointAuthSigningAlgorithm: doc.TokenEndpointAuthSigningAlg,
		},
		Document: doc,
	}, nil
}

// GetClientMetadataDocument returns the metadata used to materialize the client.
func (c *CIMDClient) GetClientMetadataDocument() *ClientMetadataDocument {
	return c.Document
}

// ResolveCIMDJSONWebKeys resolves the client's remote keys through the SSRF-guarded CIMD transport.
func (c *CIMDClient) ResolveCIMDJSONWebKeys(ctx context.Context, ignoreCache bool) (*jose.JSONWebKeySet, error) {
	if c.JSONWebKeysURI == "" {
		return nil, errors.New("CIMD client has no jwks_uri")
	}
	c.mu.Lock()
	fetcher, validateURL := c.jwksFetcher, c.validateURL
	c.mu.Unlock()

	if fetcher == nil || validateURL == nil {
		return nil, errors.New("CIMD client has no secure jwks_uri fetcher")
	}
	if err := validateURL(ctx, c.JSONWebKeysURI); err != nil {
		return nil, fmt.Errorf("jwks_uri is not safe to fetch: %w", err)
	}
	return fetcher.Resolve(ctx, c.JSONWebKeysURI, ignoreCache)
}

// configureSecureHTTPClient installs a guarded HTTP client and JWKS fetcher if the client references external URLs.
func (c *CIMDClient) configureSecureHTTPClient(provider CIMDSecureHTTPClientProvider, sharedJWKSFetcher func(*http.Client) JWKSFetcherStrategy) error {
	needsKeys := c.JSONWebKeysURI != ""
	needsFetch := len(c.RequestURIs) > 0
	if !needsKeys && !needsFetch {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// If the client already has a secure fetcher and HTTP client, no further configuration is needed.
	if c.validateURL != nil && c.httpClient != nil && (!needsKeys || c.jwksFetcher != nil) {
		return nil
	}
	if provider == nil {
		return errors.New("CIMD client referencing external URLs requires a secure HTTP client")
	}
	httpClient := provider.CIMDHTTPClient()
	if httpClient == nil {
		return errors.New("CIMD secure HTTP client is nil")
	}
	c.validateURL = provider.ValidateFetchURL
	c.httpClient = httpClient

	if needsKeys {
		if sharedJWKSFetcher == nil {
			return errors.New("CIMD client referencing jwks_uri requires a shared JWKS fetcher")
		}
		c.jwksFetcher = sharedJWKSFetcher(httpClient)
	}
	return nil
}

func newCIMDJWKSFetcherStrategy(httpClient *http.Client) JWKSFetcherStrategy {
	limitedHTTPClient := *httpClient
	base := limitedHTTPClient.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	limitedHTTPClient.Transport = cimdResponseSizeLimitTransport{base: base, maxSize: DefaultCIMDReferencedURLMaxSize}
	retryClient := retryablehttp.NewClient()
	retryClient.HTTPClient = &limitedHTTPClient
	retryClient.Logger = nil
	return NewDefaultJWKSFetcherStrategy(JWKSFetcherWithHTTPClient(retryClient))
}

type cimdResponseSizeLimitTransport struct {
	base    http.RoundTripper
	maxSize int64
}

func (t cimdResponseSizeLimitTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, t.maxSize+1))
	closeErr := response.Body.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(body)) > t.maxSize {
		return nil, errors.New("CIMD referenced response exceeds maximum size")
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}

// FetchCIMDReferencedURL dereferences a URL taken from the client's metadata document through the
// SSRF-guarded transport, after re-validating it against the special-use ranges.
func (c *CIMDClient) FetchCIMDReferencedURL(ctx context.Context, rawURL string) (*http.Response, error) {
	c.mu.Lock()
	httpClient, validateURL := c.httpClient, c.validateURL
	c.mu.Unlock()

	if httpClient == nil || validateURL == nil {
		return nil, errors.New("CIMD client has no guarded HTTP client")
	}
	if err := validateURL(ctx, rawURL); err != nil {
		return nil, fmt.Errorf("URL referenced by the client metadata document is not safe to fetch: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return httpClient.Do(req)
}
