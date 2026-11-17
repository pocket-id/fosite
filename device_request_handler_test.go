// Copyright © 2025 Ory Corp
// Modified by contributors to the Pocket ID fork.
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"

	. "github.com/pocket-id/fosite"
	"github.com/pocket-id/fosite/internal"
)

func TestNewDeviceRequestWithPublicClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)
	clientManager := internal.NewMockClientManager(ctrl)
	deviceClient := &DefaultClient{ID: "client_id"}
	deviceClient.Public = true
	deviceClient.Scopes = []string{"17", "42"}
	deviceClient.Audience = []string{"aud2"}
	deviceClient.GrantTypes = []string{"urn:ietf:params:oauth:grant-type:device_code"}

	authCodeClient := &DefaultClient{ID: "client_id_2"}
	authCodeClient.Public = true
	authCodeClient.Scopes = []string{"17", "42"}
	authCodeClient.GrantTypes = []string{"authorization_code"}

	t.Cleanup(ctrl.Finish)
	config := &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}
	fosite := &Fosite{Store: store, Config: config}
	for k, c := range []struct {
		header        http.Header
		form          url.Values
		method        string
		expectedError error
		mock          func()
		expect        DeviceRequester
		description   string
	}{{
		description:   "invalid method",
		expectedError: ErrInvalidRequest,
		method:        "GET",
		mock:          func() {},
	}, {
		description:   "empty request",
		expectedError: ErrInvalidRequest,
		method:        "POST",
		mock:          func() {},
	}, {
		description: "invalid client",
		form: url.Values{
			"client_id": {"client_id"},
			"scope":     {"foo bar"},
		},
		expectedError: ErrInvalidClient,
		method:        "POST",
		mock: func() {
			store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
			clientManager.EXPECT().GetClient(gomock.Any(), gomock.Eq("client_id")).Return(nil, errors.New(""))
		},
	}, {
		description: "fails because scope not allowed",
		form: url.Values{
			"client_id": {"client_id"},
			"scope":     {"17 42 foo"},
		},
		method: "POST",
		mock: func() {
			store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
			clientManager.EXPECT().GetClient(gomock.Any(), gomock.Eq("client_id")).Return(deviceClient, nil)
		},
		expectedError: ErrInvalidScope,
	}, {
		description: "audience parameter is ignored even when not whitelisted",
		form: url.Values{
			"client_id": {"client_id"},
			"scope":     {"17 42"},
			"audience":  {"random_aud"},
		},
		method: "POST",
		mock: func() {
			store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
			clientManager.EXPECT().GetClient(gomock.Any(), gomock.Eq("client_id")).Return(deviceClient, nil)
		},
	}, {
		description: "fails because resource is malformed",
		form: url.Values{
			"client_id": {"client_id"},
			"resource":  {"https://api.example.com#fragment"},
		},
		method:        "POST",
		mock:          func() {},
		expectedError: ErrInvalidTarget,
	}, {
		description: "fails because it doesn't have the proper grant",
		form: url.Values{
			"client_id": {"client_id_2"},
			"scope":     {"17 42"},
		},
		method: "POST",
		mock: func() {
			store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
			clientManager.EXPECT().GetClient(gomock.Any(), gomock.Eq("client_id_2")).Return(authCodeClient, nil)
		},
		expectedError: ErrInvalidGrant,
	}, {
		description: "success",
		form: url.Values{
			"client_id": {"client_id"},
			"scope":     {"17 42"},
		},
		method: "POST",
		mock: func() {
			store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
			clientManager.EXPECT().GetClient(gomock.Any(), gomock.Eq("client_id")).Return(deviceClient, nil)
		},
	}} {
		t.Run(fmt.Sprintf("case=%d description=%s", k, c.description), func(t *testing.T) {
			c.mock()
			r := &http.Request{
				Header:   c.header,
				PostForm: c.form,
				Form:     c.form,
				Method:   c.method,
			}

			ar, err := fosite.NewDeviceRequest(context.Background(), r)
			require.ErrorIs(t, err, c.expectedError)
			if c.expectedError == nil {
				assert.NotNil(t, ar.GetRequestedAt())
				// The "audience" request parameter is never ingested.
				assert.Empty(t, ar.GetRequestedAudience())
			}
		})
	}
}

func TestNewDeviceRequestWithClientAuthn(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)
	clientManager := internal.NewMockClientManager(ctrl)
	hasher := internal.NewMockHasher(ctrl)
	client := &DefaultClient{ID: "client_id"}
	t.Cleanup(ctrl.Finish)
	config := &Config{ClientSecretsHasher: hasher, ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}
	fosite := &Fosite{Store: store, Config: config}

	client.Public = false
	client.Secret = []byte("client_secret")
	client.Scopes = []string{"foo", "bar"}
	client.GrantTypes = []string{"urn:ietf:params:oauth:grant-type:device_code"}

	for k, c := range []struct {
		header        http.Header
		form          url.Values
		method        string
		expectedError error
		mock          func()
		expect        DeviceRequester
		description   string
	}{
		{
			form: url.Values{
				"client_id": {"client_id"},
				"scope":     {"foo bar"},
			},
			expectedError: ErrInvalidClient,
			method:        "POST",
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), gomock.Eq("client_id")).Return(client, nil)
				hasher.EXPECT().Compare(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New(""))
			},
			description: "Should failed becaue no client authn provided.",
		},
		{
			form: url.Values{
				"client_id": {"client_id2"},
				"scope":     {"foo bar"},
			},
			header: http.Header{
				"Authorization": {basicAuth("client_id", "client_secret")},
			},
			expectedError: ErrInvalidRequest,
			method:        "POST",
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), gomock.Eq("client_id")).Return(client, nil)
				hasher.EXPECT().Compare(gomock.Any(), gomock.Eq([]byte("client_secret")), gomock.Eq([]byte("client_secret"))).Return(nil)
			},
			description: "should fail because different client is used in authn than in form",
		},
		{
			form: url.Values{
				"client_id": {"client_id"},
				"scope":     {"foo bar"},
			},
			header: http.Header{
				"Authorization": {basicAuth("client_id", "client_secret")},
			},
			method: "POST",
			mock: func() {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), gomock.Eq("client_id")).Return(client, nil)
				hasher.EXPECT().Compare(gomock.Any(), gomock.Eq([]byte("client_secret")), gomock.Eq([]byte("client_secret"))).Return(nil)
			},
			description: "should succeed",
		},
	} {
		t.Run(fmt.Sprintf("case=%d description=%s", k, c.description), func(t *testing.T) {
			c.mock()
			r := &http.Request{
				Header:   c.header,
				PostForm: c.form,
				Form:     c.form,
				Method:   c.method,
			}

			req, err := fosite.NewDeviceRequest(context.Background(), r)
			require.ErrorIs(t, err, c.expectedError)
			if c.expectedError == nil {
				assert.NotZero(t, req.GetRequestedAt())
			}
		})
	}
}

func TestNewDeviceRequestIgnoresUnknownScopes(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockStorage(ctrl)
	clientManager := internal.NewMockClientManager(ctrl)
	defer ctrl.Finish()

	deviceClient := &DefaultClient{ID: "client_id"}
	deviceClient.Public = true
	deviceClient.Scopes = []string{"17", "42"}
	deviceClient.GrantTypes = []string{"urn:ietf:params:oauth:grant-type:device_code"}

	config := &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy, IgnoreUnknownScopes: true}
	fosite := &Fosite{Store: store, Config: config}

	store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
	clientManager.EXPECT().GetClient(gomock.Any(), gomock.Eq("client_id")).Return(deviceClient, nil)

	form := url.Values{
		"client_id": {"client_id"},
		"scope":     {"17 42 foo"},
	}
	r := &http.Request{
		PostForm: form,
		Form:     form,
		Method:   "POST",
	}

	ar, err := fosite.NewDeviceRequest(context.Background(), r)
	require.NoError(t, err)
	// The unknown "foo" scope is dropped instead of failing the request.
	assert.Equal(t, Arguments{"17", "42"}, ar.GetRequestedScopes())
}

func TestNewDeviceRequestMultipleResources(t *testing.T) {
	for _, tc := range []struct {
		description   string
		allowMultiple bool
		resources     []string
		expectErr     error
	}{
		{description: "a single resource is accepted by default", resources: []string{"https://api.example.com"}},
		{description: "repeated resources are rejected by default", resources: []string{"https://api.example.com", "https://other.example.com"}, expectErr: ErrInvalidTarget},
		{description: "repeated resources are accepted when allowed", allowMultiple: true, resources: []string{"https://api.example.com", "https://other.example.com"}},
		{description: "every repeated resource is validated", allowMultiple: true, resources: []string{"https://api.example.com", "https://other.example.com#fragment"}, expectErr: ErrInvalidTarget},
	} {
		t.Run(tc.description, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store := internal.NewMockStorage(ctrl)
			clientManager := internal.NewMockClientManager(ctrl)
			defer ctrl.Finish()

			deviceClient := &DefaultClient{ID: "client_id"}
			deviceClient.Public = true
			deviceClient.GrantTypes = []string{"urn:ietf:params:oauth:grant-type:device_code"}

			config := &Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy, AllowMultipleResourceIndicators: tc.allowMultiple}
			fosite := &Fosite{Store: store, Config: config}

			if tc.expectErr == nil {
				store.EXPECT().FositeClientManager().Return(clientManager).Times(1)
				clientManager.EXPECT().GetClient(gomock.Any(), gomock.Eq("client_id")).Return(deviceClient, nil)
			}

			form := url.Values{
				"client_id": {"client_id"},
				"resource":  tc.resources,
			}
			r := &http.Request{PostForm: form, Form: form, Method: "POST"}

			ar, err := fosite.NewDeviceRequest(context.Background(), r)
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
