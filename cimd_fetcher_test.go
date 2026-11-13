// Copyright © 2026 Pocket ID
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cimdMockRoundTripper serves canned responses keyed by request URL.
type cimdMockRoundTripper struct {
	responses map[string]*http.Response
}

func (m *cimdMockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if resp, ok := m.responses[req.URL.String()]; ok {
		return resp, nil
	}
	return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("not found")), Header: make(http.Header)}, nil
}

type failingRoundTripper struct{ err error }

func (f failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, f.err
}

func cimdMockResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func cimdMockTransport(rt http.RoundTripper) CIMDFetcherOption {
	return WithCIMDTransport(rt)
}

func newTestFetcher(responses map[string]*http.Response) *DefaultCIMDFetcher {
	return NewDefaultCIMDFetcher(
		cimdMockTransport(&cimdMockRoundTripper{responses: responses}),
	)
}

func TestDefaultCIMDFetcher_Fetch(t *testing.T) {
	const id = "https://8.8.8.8/oauth/client"
	body := `{"client_id":"https://8.8.8.8/oauth/client","client_name":"App","redirect_uris":["https://app/cb"],"token_endpoint_auth_method":"none"}`

	t.Run("fetches and parses", func(t *testing.T) {
		resp := cimdMockResponse(http.StatusOK, body)
		resp.Header.Set("Cache-Control", "max-age=600")
		f := newTestFetcher(map[string]*http.Response{id: resp})
		doc, cachePolicy, err := f.Fetch(t.Context(), id)
		require.NoError(t, err)
		assert.Equal(t, id, doc.ClientID)
		assert.Equal(t, "App", doc.ClientName)
		assert.Equal(t, CIMDCachePolicy{TTL: 10 * time.Minute, Store: true}, cachePolicy)
	})

	t.Run("non-200 is an error", func(t *testing.T) {
		f := newTestFetcher(map[string]*http.Response{id: cimdMockResponse(http.StatusNotFound, "nope")})
		_, _, err := f.Fetch(t.Context(), id)
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrCIMDTemporarilyUnavailable)
	})

	t.Run("server errors and rate limits are temporary", func(t *testing.T) {
		for _, status := range []int{http.StatusServiceUnavailable, http.StatusTooManyRequests} {
			f := newTestFetcher(map[string]*http.Response{id: cimdMockResponse(status, "nope")})
			_, _, err := f.Fetch(t.Context(), id)
			require.ErrorIs(t, err, ErrCIMDTemporarilyUnavailable)
		}
	})

	t.Run("network failure is temporary", func(t *testing.T) {
		f := NewDefaultCIMDFetcher(cimdMockTransport(failingRoundTripper{errRoundTrip}))
		_, _, err := f.Fetch(t.Context(), id)
		require.ErrorIs(t, err, ErrCIMDTemporarilyUnavailable)
		require.ErrorIs(t, err, errRoundTrip)
	})

	t.Run("destination refused by the transport is not temporary", func(t *testing.T) {
		f := NewDefaultCIMDFetcher(cimdMockTransport(failingRoundTripper{fmt.Errorf("%w: blocked address", ErrCIMDFetchRefused)}))
		_, _, err := f.Fetch(t.Context(), id)
		require.ErrorIs(t, err, ErrCIMDFetchRefused)
		require.NotErrorIs(t, err, ErrCIMDTemporarilyUnavailable)
	})

	t.Run("oversize body is rejected", func(t *testing.T) {
		big := `{"client_id":"https://8.8.8.8/oauth/client","padding":"` + strings.Repeat("a", 6*1024) + `"}`
		f := newTestFetcher(map[string]*http.Response{id: cimdMockResponse(http.StatusOK, big)})
		_, _, err := f.Fetch(t.Context(), id)
		require.Error(t, err)
	})

	t.Run("non-JSON body is rejected", func(t *testing.T) {
		f := newTestFetcher(map[string]*http.Response{id: cimdMockResponse(http.StatusOK, "<html>not json</html>")})
		_, _, err := f.Fetch(t.Context(), id)
		require.Error(t, err)
	})

	t.Run("redirects are not followed", func(t *testing.T) {
		redir := cimdMockResponse(http.StatusFound, "")
		redir.Header.Set("Location", "https://8.8.8.8/elsewhere")
		f := newTestFetcher(map[string]*http.Response{id: redir})
		_, _, err := f.Fetch(t.Context(), id)
		require.ErrorIs(t, err, errCIMDRedirect)
		require.NotErrorIs(t, err, ErrCIMDTemporarilyUnavailable)
	})

	t.Run("client_id mismatch is rejected", func(t *testing.T) {
		mismatch := `{"client_id":"https://evil.example.com/c","token_endpoint_auth_method":"none"}`
		f := newTestFetcher(map[string]*http.Response{id: cimdMockResponse(http.StatusOK, mismatch)})
		_, _, err := f.Fetch(t.Context(), id)
		require.ErrorIs(t, err, ErrCIMDClientIDMismatch)
	})

	t.Run("invalid client_id URL is rejected before fetching", func(t *testing.T) {
		f := newTestFetcher(nil)
		_, _, err := f.Fetch(t.Context(), "https://app.example.com#fragment")
		require.Error(t, err)
	})

	t.Run("private url is rejected", func(t *testing.T) {
		f := NewDefaultCIMDFetcher()
		_, _, err := f.Fetch(t.Context(), "https://127.0.0.1/oauth/client")
		require.ErrorIs(t, err, errCIMDSpecialUseIP)
		require.NotErrorIs(t, err, ErrCIMDTemporarilyUnavailable)
	})

	t.Run("non-JSON content type is rejected", func(t *testing.T) {
		resp := cimdMockResponse(http.StatusOK, body)
		resp.Header.Set("Content-Type", "text/html")
		f := newTestFetcher(map[string]*http.Response{id: resp})
		_, _, err := f.Fetch(t.Context(), id)
		require.Error(t, err)
	})
}

func TestDefaultCIMDFetcher_ParseCachePolicy(t *testing.T) {
	f := NewDefaultCIMDFetcher()
	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		header   http.Header
		expected CIMDCachePolicy
	}{
		{name: "default", header: http.Header{}, expected: CIMDCachePolicy{TTL: DefaultCIMDCacheTTL, Store: true}},
		{name: "no store", header: http.Header{"Cache-Control": {"no-store"}}, expected: CIMDCachePolicy{}},
		{name: "no cache", header: http.Header{"Cache-Control": {"max-age=600, no-cache"}}, expected: CIMDCachePolicy{Store: true}},
		{name: "must revalidate", header: http.Header{"Cache-Control": {"max-age=600, must-revalidate"}}, expected: CIMDCachePolicy{TTL: 10 * time.Minute, Store: true}},
		{name: "proxy revalidate", header: http.Header{"Cache-Control": {"max-age=600, proxy-revalidate"}}, expected: CIMDCachePolicy{TTL: 10 * time.Minute, Store: true}},
		{name: "zero max age", header: http.Header{"Cache-Control": {"max-age=0"}}, expected: CIMDCachePolicy{Store: true}},
		{name: "max age", header: http.Header{"Cache-Control": {"max-age=600"}}, expected: CIMDCachePolicy{TTL: 10 * time.Minute, Store: true}},
		{name: "quoted max age", header: http.Header{"Cache-Control": {`MAX-AGE="600"`}}, expected: CIMDCachePolicy{TTL: 10 * time.Minute, Store: true}},
		{name: "short max age is not extended", header: http.Header{"Cache-Control": {"max-age=1"}}, expected: CIMDCachePolicy{TTL: time.Second, Store: true}},
		{name: "bounded max age", header: http.Header{"Cache-Control": {"max-age=999999"}}, expected: CIMDCachePolicy{TTL: DefaultCIMDMaxCacheTTL, Store: true}},
		{name: "overflowing max age is bounded", header: http.Header{"Cache-Control": {"max-age=9223372036854775807"}}, expected: CIMDCachePolicy{TTL: DefaultCIMDMaxCacheTTL, Store: true}},
		{name: "age reduces freshness", header: http.Header{"Cache-Control": {"max-age=600"}, "Age": {"120"}}, expected: CIMDCachePolicy{TTL: 8 * time.Minute, Store: true}},
		{name: "overflowing age expires entry", header: http.Header{"Cache-Control": {"max-age=600"}, "Age": {"9223372036854775807"}}, expected: CIMDCachePolicy{Store: true}},
		{name: "s maxage wins", header: http.Header{"Cache-Control": {"max-age=600, s-maxage=120"}}, expected: CIMDCachePolicy{TTL: 2 * time.Minute, Store: true}},
		{name: "expires", header: http.Header{"Date": {now.Format(http.TimeFormat)}, "Expires": {now.Add(15 * time.Minute).Format(http.TimeFormat)}}, expected: CIMDCachePolicy{TTL: 15 * time.Minute, Store: true}},
		{name: "invalid expires is already expired", header: http.Header{"Expires": {"0"}}, expected: CIMDCachePolicy{Store: true}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, f.parseCachePolicy(tc.header, now))
		})
	}
}

func TestDefaultCIMDFetcher_MinCacheTTL(t *testing.T) {
	f := NewDefaultCIMDFetcher(WithCIMDMinCacheTTL(time.Minute))
	now := time.Date(2026, time.July, 29, 12, 0, 0, 0, time.UTC)

	// Every header that asks for less than the minimum is stored for the minimum, including the ones that forbid storing
	for _, cacheControl := range []string{"no-store", "no-cache", "max-age=0", "max-age=1"} {
		assert.Equal(t, CIMDCachePolicy{TTL: time.Minute, Store: true}, f.parseCachePolicy(http.Header{"Cache-Control": {cacheControl}}, now), cacheControl)
	}
	assert.Equal(t, CIMDCachePolicy{TTL: 10 * time.Minute, Store: true}, f.parseCachePolicy(http.Header{"Cache-Control": {"max-age=600"}}, now))
}

func TestDefaultCIMDFetcher_IsPrivateIP(t *testing.T) {
	f := NewDefaultCIMDFetcher(
		WithCIMDExtraPrivateRanges([]*net.IPNet{
			{IP: net.ParseIP("fd00::"), Mask: net.CIDRMask(8, 128)},
		}),
	)
	private := []string{
		"127.0.0.1",
		"10.0.0.1",
		"192.168.1.1",
		"172.16.0.1",
		"169.254.1.1",
		"100.64.0.1",
		"192.0.2.1",
		"198.18.0.1",
		"::1",
		"fe80::1",
		"fd00::1",
		"100:0:0:1::1",
		"3fff::1",
		"5f00::1",
		"0.0.0.0",
	}
	for _, s := range private {
		assert.Truef(t, f.isSpecialUseIP(net.ParseIP(s)), "expected %s special-use", s)
	}
	public := []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"}
	for _, s := range public {
		assert.Falsef(t, f.isSpecialUseIP(net.ParseIP(s)), "expected %s public", s)
	}
}

func TestDefaultCIMDFetcher_AllowPrivateIPs(t *testing.T) {
	const id = "https://127.0.0.1/oauth/client"
	body := `{"client_id":"https://127.0.0.1/oauth/client","token_endpoint_auth_method":"none","redirect_uris":["https://127.0.0.1/cb"]}`
	f := NewDefaultCIMDFetcher(
		cimdMockTransport(&cimdMockRoundTripper{responses: map[string]*http.Response{id: cimdMockResponse(http.StatusOK, body)}}),
		WithCIMDAllowPrivateIPs(true),
	)
	doc, _, err := f.Fetch(t.Context(), id)
	require.NoError(t, err)
	assert.Equal(t, id, doc.ClientID)
}

func TestDefaultCIMDFetcher_BoundsResponseHeaders(t *testing.T) {
	f := NewDefaultCIMDFetcher(WithCIMDMaxSize(1234))
	tr, ok := f.client.Transport.(*http.Transport)
	require.True(t, ok)
	// The size and timeout limits cover headers too, where net/http would otherwise allow 10 MiB
	assert.Equal(t, int64(1234*8), tr.MaxResponseHeaderBytes)
	assert.Equal(t, DefaultCIMDFetchTimeout, tr.ResponseHeaderTimeout)
	assert.Nil(t, tr.Proxy)
}

func TestDefaultCIMDFetcher_CustomTransportCannotBypassGuardedDialer(t *testing.T) {
	custom := &http.Transport{
		DialTLS: func(_, _ string) (net.Conn, error) {
			return nil, errors.New("must not be called")
		},
		DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, errors.New("must not be called")
		},
	}
	f := NewDefaultCIMDFetcher(WithCIMDTransport(custom))
	guarded, ok := f.client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Nil(t, guarded.DialTLS)
	assert.Nil(t, guarded.DialTLSContext)
	assert.NotNil(t, guarded.DialContext)
}
