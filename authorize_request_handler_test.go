// Copyright © 2025 Ory Corp
// Modified by contributors to the Pocket ID fork.
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"

	. "github.com/pocket-id/fosite"
	. "github.com/pocket-id/fosite/internal"
)

// Should pass
//
//   - https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#Terminology
//     The OAuth 2.0 specification allows for registration of space-separated response_type parameter values.
//     If a Response Type contains one of more space characters (%20), it is compared as a space-delimited list of
//     values in which the order of values does not matter.
func TestNewAuthorizeRequest(t *testing.T) {
	var store *MockStorage
	var clientManager *MockClientManager

	redir, _ := url.Parse("https://foo.bar/cb")
	specialCharRedir, _ := url.Parse("web+application://callback")
	for k, c := range []struct {
		desc          string
		conf          *Fosite
		r             *http.Request
		query         url.Values
		expectedError error
		mock          func()
		expect        *AuthorizeRequest
	}{
		/* empty request */
		{
			desc:          "empty request fails",
			conf:          &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			r:             &http.Request{},
			expectedError: ErrInvalidClient,
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		/* invalid redirect uri */
		{
			desc:          "invalid redirect uri fails",
			conf:          &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query:         url.Values{"redirect_uri": []string{"invalid"}},
			expectedError: ErrInvalidClient,
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		/* invalid client */
		{
			desc:          "invalid client fails",
			conf:          &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query:         url.Values{"redirect_uri": []string{"https://foo.bar/cb"}},
			expectedError: ErrInvalidClient,
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		/* redirect client mismatch */
		{
			desc: "client and request redirects mismatch",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"client_id": []string{"1234"},
			},
			expectedError: ErrInvalidRequest,
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"invalid"}, Scopes: []string{}}, nil)
			},
		},
		/* redirect client mismatch */
		{
			desc: "client and request redirects mismatch",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri": []string{""},
				"client_id":    []string{"1234"},
			},
			expectedError: ErrInvalidRequest,
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"invalid"}, Scopes: []string{}}, nil)
			},
		},
		/* redirect client mismatch */
		{
			desc: "client and request redirects mismatch",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri": []string{"https://foo.bar/cb"},
				"client_id":    []string{"1234"},
			},
			expectedError: ErrInvalidRequest,
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"invalid"}, Scopes: []string{}}, nil)
			},
		},
		/* no state */
		{
			desc: "no state",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  []string{"https://foo.bar/cb"},
				"client_id":     []string{"1234"},
				"response_type": []string{"code"},
			},
			expectedError: ErrInvalidState,
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{}}, nil)
			},
		},
		/* short state */
		{
			desc: "short state",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code"},
				"state":         {"short"},
			},
			expectedError: ErrInvalidState,
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{}}, nil)
			},
		},
		/* fails because scope not given */
		{
			desc: "should fail because client does not have scope baz",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code token"},
				"state":         {"strong-state"},
				"scope":         {"foo bar baz"},
			},
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"}}, nil)
			},
			expectedError: ErrInvalidScope,
		},
		/* audience parameter is ignored, even when not whitelisted for the client */
		{
			desc: "audience parameter is ignored",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code token"},
				"state":         {"strong-state"},
				"scope":         {"foo bar"},
				"audience":      {"https://cloud.ory.sh/api https://www.ory.com/api"},
			},
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ResponseTypes: []string{"code token"},
					RedirectURIs:  []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"},
					Audience: []string{"https://cloud.ory.sh/api"},
				}, nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{"code", "token"},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultClient{
						ResponseTypes: []string{"code token"}, RedirectURIs: []string{"https://foo.bar/cb"},
						Scopes:   []string{"foo", "bar"},
						Audience: []string{"https://cloud.ory.sh/api"},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{},
				},
			},
		},
		/* success case */
		{
			desc: "should pass",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code token"},
				"state":         {"strong-state"},
				"scope":         {"foo bar"},
				"audience":      {"https://cloud.ory.sh/api https://www.ory.com/api"},
			},
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ResponseTypes: []string{"code token"},
					RedirectURIs:  []string{"https://foo.bar/cb"},
					Scopes:        []string{"foo", "bar"},
					Audience:      []string{"https://cloud.ory.sh/api", "https://www.ory.com/api"},
				}, nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{"code", "token"},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultClient{
						ResponseTypes: []string{"code token"}, RedirectURIs: []string{"https://foo.bar/cb"},
						Scopes:   []string{"foo", "bar"},
						Audience: []string{"https://cloud.ory.sh/api", "https://www.ory.com/api"},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{},
				},
			},
		},
		/* invalid OIDC prompt parameter */
		{
			desc: "should fail because prompt none cannot be combined with login",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code"},
				"state":         {"strong-state"},
				"scope":         {"openid"},
				"prompt":        {"none login"},
			},
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"openid"}, ResponseTypes: []string{"code"}}, nil)
			},
			expectedError: ErrInvalidRequest,
		},
		/* invalid OIDC prompt parameter */
		{
			desc: "should fail because prompt none cannot be combined with consent",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code"},
				"state":         {"strong-state"},
				"scope":         {"openid"},
				"prompt":        {"none consent"},
			},
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"openid"}, ResponseTypes: []string{"code"}}, nil)
			},
			expectedError: ErrInvalidRequest,
		},
		/* invalid OIDC prompt parameter */
		{
			desc: "should fail because prompt none cannot be combined with select_account",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code"},
				"state":         {"strong-state"},
				"scope":         {"openid"},
				"prompt":        {"none select_account"},
			},
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"openid"}, ResponseTypes: []string{"code"}}, nil)
			},
			expectedError: ErrInvalidRequest,
		},
		/* invalid OIDC prompt parameter */
		{
			desc: "should fail because prompt value is unknown",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code"},
				"state":         {"strong-state"},
				"scope":         {"openid"},
				"prompt":        {"unknown"},
			},
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"openid"}, ResponseTypes: []string{"code"}}, nil)
			},
			expectedError: ErrInvalidRequest,
		},
		/* repeated audience parameter */
		{
			desc: "repeated audience parameter is ignored",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code token"},
				"state":         {"strong-state"},
				"scope":         {"foo bar"},
				"audience":      {"https://cloud.ory.sh/api", "https://www.ory.com/api"},
			},
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ResponseTypes: []string{"code token"},
					RedirectURIs:  []string{"https://foo.bar/cb"},
					Scopes:        []string{"foo", "bar"},
					Audience:      []string{"https://cloud.ory.sh/api", "https://www.ory.com/api"},
				}, nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{"code", "token"},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultClient{
						ResponseTypes: []string{"code token"}, RedirectURIs: []string{"https://foo.bar/cb"},
						Scopes:   []string{"foo", "bar"},
						Audience: []string{"https://cloud.ory.sh/api", "https://www.ory.com/api"},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{},
				},
			},
		},
		/* repeated audience parameter with tricky values */
		{
			desc: "repeated audience parameter with tricky values is ignored",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: ExactAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code token"},
				"state":         {"strong-state"},
				"scope":         {"foo bar"},
				"audience":      {"test value", ""},
			},
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ResponseTypes: []string{"code token"},
					RedirectURIs:  []string{"https://foo.bar/cb"},
					Scopes:        []string{"foo", "bar"},
					Audience:      []string{"test value"},
				}, nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{"code", "token"},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultClient{
						ResponseTypes: []string{"code token"}, RedirectURIs: []string{"https://foo.bar/cb"},
						Scopes:   []string{"foo", "bar"},
						Audience: []string{"test value"},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{},
				},
			},
		},
		/* redirect_uri with special character in protocol*/
		{
			desc: "redirect_uri with special character",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  {"web+application://callback"},
				"client_id":     {"1234"},
				"response_type": {"code token"},
				"state":         {"strong-state"},
				"scope":         {"foo bar"},
				"audience":      {"https://cloud.ory.sh/api https://www.ory.com/api"},
			},
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ResponseTypes: []string{"code token"},
					RedirectURIs:  []string{"web+application://callback"},
					Scopes:        []string{"foo", "bar"},
					Audience:      []string{"https://cloud.ory.sh/api", "https://www.ory.com/api"},
				}, nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   specialCharRedir,
				ResponseTypes: []string{"code", "token"},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultClient{
						ResponseTypes: []string{"code token"}, RedirectURIs: []string{"web+application://callback"},
						Scopes:   []string{"foo", "bar"},
						Audience: []string{"https://cloud.ory.sh/api", "https://www.ory.com/api"},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{},
				},
			},
		},
		/* audience with double spaces between values */
		{
			desc: "audience with double spaces between values is ignored",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code token"},
				"state":         {"strong-state"},
				"scope":         {"foo bar"},
				"audience":      {"https://cloud.ory.sh/api  https://www.ory.com/api"},
			},
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					ResponseTypes: []string{"code token"},
					RedirectURIs:  []string{"https://foo.bar/cb"},
					Scopes:        []string{"foo", "bar"},
					Audience:      []string{"https://cloud.ory.sh/api", "https://www.ory.com/api"},
				}, nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{"code", "token"},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultClient{
						ResponseTypes: []string{"code token"}, RedirectURIs: []string{"https://foo.bar/cb"},
						Scopes:   []string{"foo", "bar"},
						Audience: []string{"https://cloud.ory.sh/api", "https://www.ory.com/api"},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{},
				},
			},
		},
		/* fails because unknown response_mode*/
		{
			desc: "should fail because unknown response_mode",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code token"},
				"state":         {"strong-state"},
				"scope":         {"foo bar"},
				"response_mode": {"unknown"},
			},
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"}, ResponseTypes: []string{"code token"}}, nil)
			},
			expectedError: ErrUnsupportedResponseMode,
		},
		/* fails because response_mode is requested but the OAuth 2.0 client doesn't support response mode */
		{
			desc: "should fail because response_mode is requested but the OAuth 2.0 client doesn't support response mode",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code token"},
				"state":         {"strong-state"},
				"scope":         {"foo bar"},
				"response_mode": {"form_post"},
			},
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"foo", "bar"}, ResponseTypes: []string{"code token"}}, nil)
			},
			expectedError: ErrUnsupportedResponseMode,
		},
		/* fails because requested response mode is not allowed */
		{
			desc: "should fail because requested response mode is not allowed",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code token"},
				"state":         {"strong-state"},
				"scope":         {"foo bar"},
				"response_mode": {"form_post"},
			},
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultResponseModeClient{
					DefaultClient: &DefaultClient{
						RedirectURIs:  []string{"https://foo.bar/cb"},
						Scopes:        []string{"foo", "bar"},
						ResponseTypes: []string{"code token"},
					},
					ResponseModes: []ResponseModeType{ResponseModeQuery},
				}, nil)
			},
			expectedError: ErrUnsupportedResponseMode,
		},
		/* success with response mode */
		{
			desc: "success with response mode",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code token"},
				"state":         {"strong-state"},
				"scope":         {"foo bar"},
				"response_mode": {"form_post"},
				"audience":      {"https://cloud.ory.sh/api https://www.ory.com/api"},
			},
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultResponseModeClient{
					DefaultClient: &DefaultClient{
						RedirectURIs:  []string{"https://foo.bar/cb"},
						Scopes:        []string{"foo", "bar"},
						ResponseTypes: []string{"code token"},
						Audience:      []string{"https://cloud.ory.sh/api", "https://www.ory.com/api"},
					},
					ResponseModes: []ResponseModeType{ResponseModeFormPost},
				}, nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{"code", "token"},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultResponseModeClient{
						DefaultClient: &DefaultClient{
							RedirectURIs:  []string{"https://foo.bar/cb"},
							Scopes:        []string{"foo", "bar"},
							ResponseTypes: []string{"code token"},
							Audience:      []string{"https://cloud.ory.sh/api", "https://www.ory.com/api"},
						},
						ResponseModes: []ResponseModeType{ResponseModeFormPost},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{},
				},
			},
		},
		/* determine correct response mode if default */
		{
			desc: "success with response mode",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code"},
				"state":         {"strong-state"},
				"scope":         {"foo bar"},
				"audience":      {"https://cloud.ory.sh/api https://www.ory.com/api"},
			},
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultResponseModeClient{
					DefaultClient: &DefaultClient{
						RedirectURIs:  []string{"https://foo.bar/cb"},
						Scopes:        []string{"foo", "bar"},
						ResponseTypes: []string{"code"},
						Audience:      []string{"https://cloud.ory.sh/api", "https://www.ory.com/api"},
					},
					ResponseModes: []ResponseModeType{ResponseModeQuery},
				}, nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{"code"},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultResponseModeClient{
						DefaultClient: &DefaultClient{
							RedirectURIs:  []string{"https://foo.bar/cb"},
							Scopes:        []string{"foo", "bar"},
							ResponseTypes: []string{"code"},
							Audience:      []string{"https://cloud.ory.sh/api", "https://www.ory.com/api"},
						},
						ResponseModes: []ResponseModeType{ResponseModeQuery},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{},
				},
			},
		},
		/* determine correct response mode if default */
		{
			desc: "success with response mode",
			conf: &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}},
			query: url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code token"},
				"state":         {"strong-state"},
				"scope":         {"foo bar"},
				"audience":      {"https://cloud.ory.sh/api https://www.ory.com/api"},
			},
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultResponseModeClient{
					DefaultClient: &DefaultClient{
						RedirectURIs:  []string{"https://foo.bar/cb"},
						Scopes:        []string{"foo", "bar"},
						ResponseTypes: []string{"code token"},
						Audience:      []string{"https://cloud.ory.sh/api", "https://www.ory.com/api"},
					},
					ResponseModes: []ResponseModeType{ResponseModeFragment},
				}, nil)
			},
			expect: &AuthorizeRequest{
				RedirectURI:   redir,
				ResponseTypes: []string{"code", "token"},
				State:         "strong-state",
				Request: Request{
					Client: &DefaultResponseModeClient{
						DefaultClient: &DefaultClient{
							RedirectURIs:  []string{"https://foo.bar/cb"},
							Scopes:        []string{"foo", "bar"},
							ResponseTypes: []string{"code token"},
							Audience:      []string{"https://cloud.ory.sh/api", "https://www.ory.com/api"},
						},
						ResponseModes: []ResponseModeType{ResponseModeFragment},
					},
					RequestedScope:    []string{"foo", "bar"},
					RequestedAudience: []string{},
				},
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store = NewMockStorage(ctrl)
			clientManager = NewMockClientManager(ctrl)
			t.Cleanup(ctrl.Finish)

			c.mock()
			if c.r == nil {
				c.r = &http.Request{Header: http.Header{}}
				if c.query != nil {
					c.r.URL = &url.URL{RawQuery: c.query.Encode()}
				}
			}

			c.conf.Store = store
			ar, err := c.conf.NewAuthorizeRequest(context.Background(), c.r)
			if c.expectedError != nil {
				assert.EqualError(t, err, c.expectedError.Error())
				// https://github.com/ory/hydra/issues/1642
				AssertObjectKeysEqual(t, &AuthorizeRequest{State: c.query.Get("state")}, ar, "State")
			} else {
				require.NoError(t, err)
				AssertObjectKeysEqual(t, c.expect, ar, "ResponseTypes", "RequestedAudience", "RequestedScope", "Client", "RedirectURI", "State")
				assert.NotNil(t, ar.GetRequestedAt())
			}
		})
	}
}

func TestNewAuthorizeRequestInvalidPromptCanRedirectAuthorizeError(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := NewMockStorage(ctrl)
	clientManager := NewMockClientManager(ctrl)
	defer ctrl.Finish()

	conf := &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}}
	query := url.Values{
		"redirect_uri":  {"https://foo.bar/cb"},
		"client_id":     {"1234"},
		"response_type": {"code"},
		"state":         {"strong-state"},
		"scope":         {"openid"},
		"prompt":        {"none consent"},
	}
	req := &http.Request{Header: http.Header{}, URL: &url.URL{RawQuery: query.Encode()}}

	store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
	clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"openid"}, ResponseTypes: []string{"code"}}, nil)

	ar, err := conf.NewAuthorizeRequest(context.Background(), req)
	require.EqualError(t, err, ErrInvalidRequest.Error())
	require.True(t, ar.IsRedirectURIValid())

	rw := httptest.NewRecorder()
	conf.WriteAuthorizeError(context.Background(), rw, ar, err)

	require.Equal(t, http.StatusSeeOther, rw.Code)
	location, err := url.Parse(rw.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "https://foo.bar/cb", location.Scheme+"://"+location.Host+location.Path)
	assert.Equal(t, "invalid_request", location.Query().Get("error"))
	assert.Equal(t, "strong-state", location.Query().Get("state"))
}

func TestNewAuthorizeRequestUsesRedirectURIMatcher(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := NewMockStorage(ctrl)
	clientManager := NewMockClientManager(ctrl)
	defer ctrl.Finish()

	conf := &Fosite{
		Store: store,
		Config: &Config{
			ScopeStrategy:            ExactScopeStrategy,
			AudienceMatchingStrategy: DefaultAudienceMatchingStrategy,
			RedirectURIMatcher: func(rawurl string, client Client) (*url.URL, error) {
				if rawurl == "https://tenant.example.com/callback" && len(client.GetRedirectURIs()) == 1 && client.GetRedirectURIs()[0] == "https://*.example.com/callback" {
					return url.Parse(rawurl)
				}
				return nil, ErrInvalidRequest
			},
		},
	}
	query := url.Values{
		"redirect_uri":  {"https://tenant.example.com/callback"},
		"client_id":     {"1234"},
		"response_type": {"code"},
		"state":         {"strong-state"},
	}
	req := &http.Request{Header: http.Header{}, URL: &url.URL{RawQuery: query.Encode()}}

	store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
	clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
		RedirectURIs:  []string{"https://*.example.com/callback"},
		ResponseTypes: []string{"code"},
	}, nil)

	ar, err := conf.NewAuthorizeRequest(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "https://tenant.example.com/callback", ar.GetRedirectURI().String())
	require.True(t, ar.IsRedirectURIValid())
}

func TestNewAuthorizeRequestRejectsWildcardLikeRedirectByDefault(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := NewMockStorage(ctrl)
	clientManager := NewMockClientManager(ctrl)
	defer ctrl.Finish()

	conf := &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}}
	query := url.Values{
		"redirect_uri":  {"https://tenant.example.com/callback"},
		"client_id":     {"1234"},
		"response_type": {"code"},
		"state":         {"strong-state"},
	}
	req := &http.Request{Header: http.Header{}, URL: &url.URL{RawQuery: query.Encode()}}

	store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
	clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
		RedirectURIs:  []string{"https://*.example.com/callback"},
		ResponseTypes: []string{"code"},
	}, nil)

	ar, err := conf.NewAuthorizeRequest(context.Background(), req)
	require.EqualError(t, err, ErrInvalidRequest.Error())
	require.False(t, ar.IsRedirectURIValid())
}

func TestNewAuthorizeRequestUnsupportedRequestObjectCanRedirectAuthorizeError(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := NewMockStorage(ctrl)
	clientManager := NewMockClientManager(ctrl)
	defer ctrl.Finish()

	conf := &Fosite{Store: store, Config: &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy, SupportedRequestObjectSigningAlgorithms: []string{"RS256"}}}
	query := url.Values{
		"redirect_uri":  {"https://foo.bar/cb"},
		"client_id":     {"1234"},
		"response_type": {"code"},
		"state":         {"strong-state"},
		"scope":         {"openid"},
		"request":       {"eyJhbGciOiJub25lIn0.eyJpc3MiOiIxMjM0In0."},
	}
	req := &http.Request{Header: http.Header{}, URL: &url.URL{RawQuery: query.Encode()}}

	store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
	clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{RedirectURIs: []string{"https://foo.bar/cb"}, Scopes: []string{"openid"}, ResponseTypes: []string{"code"}}, nil)

	ar, err := conf.NewAuthorizeRequest(context.Background(), req)
	require.EqualError(t, err, ErrInvalidRequestObject.Error())
	require.True(t, ar.IsRedirectURIValid())

	rw := httptest.NewRecorder()
	conf.WriteAuthorizeError(context.Background(), rw, ar, err)

	require.Equal(t, http.StatusSeeOther, rw.Code)
	location, err := url.Parse(rw.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "https://foo.bar/cb", location.Scheme+"://"+location.Host+location.Path)
	assert.Equal(t, "invalid_request_object", location.Query().Get("error"))
	assert.Equal(t, "strong-state", location.Query().Get("state"))
}

func TestNewAuthorizeRequestIgnoresUnknownScopes(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := NewMockStorage(ctrl)
	clientManager := NewMockClientManager(ctrl)
	defer ctrl.Finish()

	conf := &Fosite{
		Store: store,
		Config: &Config{
			ScopeStrategy:            ExactScopeStrategy,
			AudienceMatchingStrategy: DefaultAudienceMatchingStrategy,
			IgnoreUnknownScopes:      true,
		},
	}
	query := url.Values{
		"redirect_uri":  {"https://foo.bar/cb"},
		"client_id":     {"1234"},
		"response_type": {"code"},
		"state":         {"strong-state"},
		"scope":         {"openid profile phone"},
	}
	req := &http.Request{Header: http.Header{}, URL: &url.URL{RawQuery: query.Encode()}}

	store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
	clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
		RedirectURIs:  []string{"https://foo.bar/cb"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "profile", "email"},
	}, nil)

	ar, err := conf.NewAuthorizeRequest(context.Background(), req)
	require.NoError(t, err)
	// The unknown "phone" scope is dropped instead of failing the request.
	require.Equal(t, Arguments{"openid", "profile"}, ar.GetRequestedScopes())
}

func TestNewAuthorizeRequestIgnoredOpenIDScopeDoesNotRequireRedirectURI(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := NewMockStorage(ctrl)
	clientManager := NewMockClientManager(ctrl)
	defer ctrl.Finish()

	conf := &Fosite{
		Store: store,
		Config: &Config{
			ScopeStrategy:            ExactScopeStrategy,
			AudienceMatchingStrategy: DefaultAudienceMatchingStrategy,
			IgnoreUnknownScopes:      true,
		},
	}
	// No redirect_uri parameter: allowed for plain OAuth 2.0 requests when the client has
	// exactly one registered redirect URI, but required for OpenID Connect requests. The
	// client is not registered for "openid", so the scope is dropped before that check.
	query := url.Values{
		"client_id":     {"1234"},
		"response_type": {"code"},
		"state":         {"strong-state"},
		"scope":         {"openid email"},
	}
	req := &http.Request{Header: http.Header{}, URL: &url.URL{RawQuery: query.Encode()}}

	store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
	clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
		RedirectURIs:  []string{"https://foo.bar/cb"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"email"},
	}, nil)

	ar, err := conf.NewAuthorizeRequest(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, Arguments{"email"}, ar.GetRequestedScopes())
}

func TestNewAuthorizeRequestMultipleResources(t *testing.T) {
	for _, tc := range []struct {
		description   string
		allowMultiple bool
		resources     []string
		expectErr     error
	}{
		{description: "a single resource is accepted by default", resources: []string{"https://api.example.com"}},
		{description: "repeated resources are rejected by default", resources: []string{"https://api.example.com", "https://other.example.com"}, expectErr: ErrInvalidTarget},
		{description: "a single resource is accepted when repeated ones are allowed", allowMultiple: true, resources: []string{"https://api.example.com"}},
		{description: "repeated resources are accepted when allowed", allowMultiple: true, resources: []string{"https://api.example.com", "https://other.example.com"}},
		{description: "every repeated resource is validated", allowMultiple: true, resources: []string{"https://api.example.com", "https://other.example.com#fragment"}, expectErr: ErrInvalidTarget},
	} {
		t.Run(tc.description, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := NewMockStorage(ctrl)
			clientManager := NewMockClientManager(ctrl)
			defer ctrl.Finish()

			conf := &Fosite{
				Store: store,
				Config: &Config{
					ScopeStrategy:                   ExactScopeStrategy,
					AudienceMatchingStrategy:        DefaultAudienceMatchingStrategy,
					AllowMultipleResourceIndicators: tc.allowMultiple,
				},
			}
			query := url.Values{
				"redirect_uri":  {"https://foo.bar/cb"},
				"client_id":     {"1234"},
				"response_type": {"code"},
				"state":         {"strong-state"},
				"resource":      tc.resources,
			}
			req := &http.Request{Header: http.Header{}, URL: &url.URL{RawQuery: query.Encode()}}

			store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
			clientManager.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
				RedirectURIs:  []string{"https://foo.bar/cb"},
				ResponseTypes: []string{"code"},
			}, nil)

			ar, err := conf.NewAuthorizeRequest(context.Background(), req)
			if tc.expectErr != nil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tc.expectErr))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.resources, GetResourceIndicators(ar.GetRequestForm()))
		})
	}
}
