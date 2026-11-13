// Copyright © 2026 Pocket ID
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Default limits for fetching Client ID Metadata Documents. They follow the
// recommendations in draft-ietf-oauth-client-id-metadata-document.
const (
	DefaultCIMDMaxSize              = 5 * 1024 // 5 KiB (draft recommendation)
	DefaultCIMDFetchTimeout         = 15 * time.Second
	DefaultCIMDMaxCacheTTL          = 24 * time.Hour
	DefaultCIMDCacheTTL             = 1 * time.Hour
	DefaultCIMDReferencedURLMaxSize = 1 * 1024 * 1024
)

// specialUseIPNets contains special-purpose ranges that net.IP does not reject
// through its built-in private, loopback, link-local, or unspecified checks.
var specialUseIPNets = parseCIMDSpecialUseRanges([]string{
	"0.0.0.0/8",
	"100.64.0.0/10",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.31.196.0/24",
	"192.52.193.0/24",
	"192.88.99.0/24",
	"192.175.48.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"64:ff9b::/96",
	"64:ff9b:1::/48",
	"100::/64",
	"100:0:0:1::/64",
	"2001::/23",
	"2001:db8::/32",
	"2002::/16",
	"2620:4f:8000::/48",
	"3fff::/20",
	"5f00::/16",
	"ff00::/8",
})

// Refusals by the fetcher's own rules, which stay terminal while every other failure to reach a document may pass
var (
	errCIMDRedirect     = errors.New("redirects are not allowed when fetching client metadata")
	errCIMDSpecialUseIP = errors.New("special-use IP addresses are not allowed")
)

// CIMDFetcher retrieves and validates the Client ID Metadata Document located
// at a client_id URL.
type CIMDFetcher interface {
	// Fetch retrieves the metadata document at clientID (an https URL), validates
	// it, and returns a parsed document along with the response's cache policy.
	Fetch(ctx context.Context, clientID string) (doc *ClientMetadataDocument, cachePolicy CIMDCachePolicy, err error)
}

// CIMDSecureHTTPClientProvider exposes the guarded client for fetching URLs referenced by a metadata document.
type CIMDSecureHTTPClientProvider interface {
	ValidateFetchURL(context.Context, string) error
	CIMDHTTPClient() *http.Client
}

// DefaultCIMDFetcher is the default CIMDFetcher. It blocks requests to private
// IP addresses (SSRF), refuses redirects, caps the response body size, and
// requires a 200 response.
type DefaultCIMDFetcher struct {
	client        *http.Client
	baseTransport http.RoundTripper
	decorate      func(http.RoundTripper) http.RoundTripper
	userAgent     string

	maxSize    int64
	timeout    time.Duration
	minTTL     time.Duration
	maxTTL     time.Duration
	defaultTTL time.Duration

	allowPrivateIPs    bool
	resolver           *net.Resolver
	extraPrivateRanges []*net.IPNet
}

// CIMDFetcherOption configures a DefaultCIMDFetcher.
type CIMDFetcherOption func(*DefaultCIMDFetcher)

// WithCIMDTransport sets the base transport used by the fetcher.
//
// A custom non-*http.Transport is a trusted escape hatch for tests and controlled integrations because Fosite cannot install its dial-time SSRF guard around it.
func WithCIMDTransport(rt http.RoundTripper) CIMDFetcherOption {
	return func(f *DefaultCIMDFetcher) { f.baseTransport = rt }
}

// WithCIMDTransportDecorator wraps the guarded transport without hiding its dialer from the fetcher.
//
// This is the preferred option for tracing, metrics, and other middleware, and decorators must call the supplied transport rather than replace it.
func WithCIMDTransportDecorator(decorate func(http.RoundTripper) http.RoundTripper) CIMDFetcherOption {
	return func(f *DefaultCIMDFetcher) { f.decorate = decorate }
}

// WithCIMDUserAgent sets the User-Agent header sent when fetching.
func WithCIMDUserAgent(ua string) CIMDFetcherOption {
	return func(f *DefaultCIMDFetcher) { f.userAgent = ua }
}

// WithCIMDMaxSize sets the maximum accepted response size in bytes, applied to the body and to the
// response headers separately.
func WithCIMDMaxSize(n int64) CIMDFetcherOption {
	return func(f *DefaultCIMDFetcher) { f.maxSize = n }
}

// WithCIMDCacheTTLBounds sets the maximum and default cache lifetimes without extending an explicit origin lifetime.
func WithCIMDCacheTTLBounds(maxTTL, defaultTTL time.Duration) CIMDFetcherOption {
	return func(f *DefaultCIMDFetcher) {
		f.maxTTL, f.defaultTTL = maxTTL, defaultTTL
	}
}

// WithCIMDMinCacheTTL sets a lifetime every document is cached for, whatever its response headers say
// This bounds how often a client can make the server fetch its document, and lets a cache that cannot evict accept documents served with no-store
func WithCIMDMinCacheTTL(minTTL time.Duration) CIMDFetcherOption {
	return func(f *DefaultCIMDFetcher) { f.minTTL = minTTL }
}

// WithCIMDAllowPrivateIPs disables SSRF protection, allowing documents to be
// fetched from private, loopback, or link-local addresses.
func WithCIMDAllowPrivateIPs(allow bool) CIMDFetcherOption {
	return func(f *DefaultCIMDFetcher) { f.allowPrivateIPs = allow }
}

// WithCIMDResolver sets the resolver used for resolution-time SSRF checks.
func WithCIMDResolver(r *net.Resolver) CIMDFetcherOption {
	return func(f *DefaultCIMDFetcher) { f.resolver = r }
}

// WithCIMDExtraPrivateRanges adds CIDR ranges that are treated as private.
func WithCIMDExtraPrivateRanges(ranges []*net.IPNet) CIMDFetcherOption {
	return func(f *DefaultCIMDFetcher) { f.extraPrivateRanges = ranges }
}

// NewDefaultCIMDFetcher returns a DefaultCIMDFetcher configured with the given
// options and package defaults.
func NewDefaultCIMDFetcher(opts ...CIMDFetcherOption) *DefaultCIMDFetcher {
	f := &DefaultCIMDFetcher{
		userAgent:  "fosite/oidc-client-metadata-fetcher",
		maxSize:    DefaultCIMDMaxSize,
		timeout:    DefaultCIMDFetchTimeout,
		maxTTL:     DefaultCIMDMaxCacheTTL,
		defaultTTL: DefaultCIMDCacheTTL,
		resolver:   net.DefaultResolver,
	}
	for _, o := range opts {
		o(f)
	}
	f.client = f.buildHTTPClient()
	return f
}

var _ CIMDFetcher = (*DefaultCIMDFetcher)(nil)
var _ CIMDSecureHTTPClientProvider = (*DefaultCIMDFetcher)(nil)

// buildHTTPClient constructs the HTTP client used for fetching.
func (f *DefaultCIMDFetcher) buildHTTPClient() *http.Client {
	c := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errCIMDRedirect
		},
	}

	switch tr := f.baseTransport.(type) {
	case nil:
		defaultTransport, _ := http.DefaultTransport.(*http.Transport)
		c.Transport = f.guardTransport(defaultTransport)
	case *http.Transport:
		c.Transport = f.guardTransport(tr)
	default:
		c.Transport = tr
	}

	if f.decorate != nil {
		if decorated := f.decorate(c.Transport); decorated != nil {
			c.Transport = decorated
		}
	}
	return c
}

// guardTransport clones tr and, unless private IPs are allowed, installs a
// connect-time SSRF check via the dialer's Control hook.
func (f *DefaultCIMDFetcher) guardTransport(tr *http.Transport) http.RoundTripper {
	if tr == nil {
		tr = &http.Transport{}
	} else {
		tr = tr.Clone()
	}

	// Limit the size of the response headers to prevent memory exhaustion attacks.
	tr.MaxResponseHeaderBytes = f.maxSize * 8
	tr.ResponseHeaderTimeout = f.timeout

	if f.allowPrivateIPs {
		return tr
	}

	// A proxy would hide the final destination from the guarded dialer and bypass its IP checks.
	tr.Proxy = nil
	// Custom TLS dialers bypass DialContext, so the guarded transport must perform the TLS handshake itself.
	tr.DialTLS = nil
	tr.DialTLSContext = nil

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("could not parse dialed address %q", address)
			}
			if f.isSpecialUseIP(ip) {
				return errCIMDSpecialUseIP
			}
			return nil
		},
	}
	tr.DialContext = dialer.DialContext
	return tr
}

func (f *DefaultCIMDFetcher) Fetch(ctx context.Context, clientID string) (*ClientMetadataDocument, CIMDCachePolicy, error) {
	u, err := ParseCIMDURL(clientID)
	if err != nil {
		return nil, CIMDCachePolicy{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	if err := f.validateResolvedURL(ctx, u); err != nil {
		return nil, CIMDCachePolicy{}, cimdUnreachableError(ctx, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, CIMDCachePolicy{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", f.userAgent)

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, CIMDCachePolicy{}, cimdUnreachableError(ctx, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("unexpected status %d fetching client metadata", resp.StatusCode)
		// A server error or a rate limit says nothing about the document itself
		if resp.StatusCode >= http.StatusInternalServerError || resp.StatusCode == http.StatusTooManyRequests {
			err = fmt.Errorf("%w: %w", ErrCIMDTemporarilyUnavailable, err)
		}
		return nil, CIMDCachePolicy{}, err
	}
	if err := validateCIMDContentType(resp.Header.Get("Content-Type")); err != nil {
		return nil, CIMDCachePolicy{}, err
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxSize+1))
	if err != nil {
		return nil, CIMDCachePolicy{}, cimdUnreachableError(ctx, err)
	}
	if int64(len(body)) > f.maxSize {
		return nil, CIMDCachePolicy{}, errors.New("client metadata document exceeds maximum size")
	}

	var doc ClientMetadataDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, CIMDCachePolicy{}, fmt.Errorf("invalid client metadata JSON: %w", err)
	}
	if err := doc.Validate(clientID); err != nil {
		return nil, CIMDCachePolicy{}, err
	}

	return &doc, f.parseCachePolicy(resp.Header, time.Now()), nil
}

// cimdUnreachableError marks a failure to retrieve the document as temporary, unless the fetcher itself refused the request
func cimdUnreachableError(ctx context.Context, err error) error {
	if errors.Is(err, errCIMDRedirect) || errors.Is(err, errCIMDSpecialUseIP) || errors.Is(err, ErrCIMDFetchRefused) {
		return err
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return fmt.Errorf("%w: %w", ErrCIMDTemporarilyUnavailable, err)
}

// parseCachePolicy derives a bounded freshness lifetime and whether the response may be stored.
func (f *DefaultCIMDFetcher) parseCachePolicy(header http.Header, now time.Time) CIMDCachePolicy {
	directives := parseCIMDCacheControl(header.Values("Cache-Control"))
	if _, noStore := directives["no-store"]; noStore {
		return CIMDCachePolicy{TTL: f.minTTL, Store: f.minTTL > 0}
	}

	policy := CIMDCachePolicy{TTL: f.minTTL, Store: true}
	if _, noCache := directives["no-cache"]; noCache {
		return policy
	}

	freshness := f.defaultTTL
	if seconds, ok := cacheDirectiveSeconds(directives, "s-maxage"); ok {
		freshness = boundedCacheDuration(seconds, f.maxTTL)
	} else if seconds, ok := cacheDirectiveSeconds(directives, "max-age"); ok {
		freshness = boundedCacheDuration(seconds, f.maxTTL)
	} else if expires := header.Get("Expires"); expires != "" {
		// RFC 9111 section 5.3 reads an Expires value that is not a date, such as 0, as already expired
		freshness = 0
		if expiresAt, err := http.ParseTime(expires); err == nil {
			date := now
			if parsedDate, err := http.ParseTime(header.Get("Date")); err == nil {
				date = parsedDate
			}
			freshness = expiresAt.Sub(date)
		}
	}
	if freshness > f.maxTTL {
		freshness = f.maxTTL
	}
	if freshness < 0 {
		freshness = 0
	}

	currentAge := time.Duration(0)
	if seconds, err := strconv.ParseInt(strings.TrimSpace(header.Get("Age")), 10, 64); err == nil && seconds > 0 {
		currentAge = boundedCacheDuration(seconds, f.maxTTL)
	}
	if date, err := http.ParseTime(header.Get("Date")); err == nil && now.After(date) && now.Sub(date) > currentAge {
		currentAge = now.Sub(date)
	}
	policy.TTL = max(f.minTTL, freshness-currentAge)
	return policy
}

func parseCIMDCacheControl(values []string) map[string]string {
	directives := make(map[string]string)
	for _, value := range values {
		for part := range strings.SplitSeq(value, ",") {
			name, directiveValue, hasValue := strings.Cut(strings.TrimSpace(part), "=")
			name = strings.ToLower(name)
			if name == "" {
				continue
			}
			if hasValue {
				directiveValue = strings.Trim(strings.TrimSpace(directiveValue), `"`)
			}
			directives[name] = directiveValue
		}
	}
	return directives
}

func cacheDirectiveSeconds(directives map[string]string, name string) (int64, bool) {
	value, ok := directives[name]
	if !ok {
		return 0, false
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	return seconds, err == nil && seconds >= 0
}

func boundedCacheDuration(seconds int64, limit time.Duration) time.Duration {
	if limit <= 0 || seconds >= int64(limit/time.Second) {
		return max(0, limit)
	}
	return time.Duration(seconds) * time.Second
}

// ValidateFetchURL checks whether an HTTP URL referenced by a metadata document is safe to fetch.
func (f *DefaultCIMDFetcher) ValidateFetchURL(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid metadata URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return errors.New("metadata URL must use the https scheme")
	}
	if u.Hostname() == "" {
		return errors.New("metadata URL must have a host")
	}
	if u.User != nil {
		return errors.New("metadata URL must not contain userinfo")
	}
	return f.validateResolvedURL(ctx, u)
}

// CIMDHTTPClient returns a copy of the guarded HTTP client for fetching referenced metadata URLs.
func (f *DefaultCIMDFetcher) CIMDHTTPClient() *http.Client {
	client := *f.client
	client.Timeout = f.timeout
	return &client
}

// validateResolvedURL rejects every special-use address returned for the URL host.
func (f *DefaultCIMDFetcher) validateResolvedURL(ctx context.Context, u *url.URL) error {
	if f.allowPrivateIPs {
		return nil
	}
	special, err := f.isSpecialUseURL(ctx, u)
	if err != nil {
		return err
	}
	if special {
		return errCIMDSpecialUseIP
	}
	return nil
}

// validateCIMDContentType accepts the standard JSON media type and structured JSON suffixes.
func validateCIMDContentType(value string) error {
	if value == "" {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return fmt.Errorf("invalid client metadata content type: %w", err)
	}
	if mediaType != "application/json" && !(strings.HasPrefix(mediaType, "application/") && strings.HasSuffix(mediaType, "+json")) {
		return fmt.Errorf("client metadata response has unsupported content type %q", mediaType)
	}
	return nil
}

// isSpecialUseURL resolves the host of u and reports if any address is special-use.
func (f *DefaultCIMDFetcher) isSpecialUseURL(ctx context.Context, u *url.URL) (bool, error) {
	ips, err := f.resolver.LookupIPAddr(ctx, u.Hostname())
	if err != nil {
		return false, fmt.Errorf("cannot resolve hostname: %w", err)
	}
	if len(ips) == 0 {
		return false, errors.New("cannot resolve hostname")
	}
	for _, addr := range ips {
		if f.isSpecialUseIP(addr.IP) {
			return true, nil
		}
	}
	return false, nil
}

// isSpecialUseIP reports whether ip is unusable as a public CIMD fetch destination.
func (f *DefaultCIMDFetcher) isSpecialUseIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, r := range specialUseIPNets {
		if r.Contains(ip) {
			return true
		}
	}
	for _, r := range f.extraPrivateRanges {
		if r != nil && r.Contains(ip) {
			return true
		}
	}
	return false
}

func parseCIMDSpecialUseRanges(cidrs []string) []*net.IPNet {
	ranges := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		ranges = append(ranges, ipNet)
	}
	return ranges
}
