// Copyright © 2026 Pocket ID
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetResourceIndicator(t *testing.T) {
	resource, err := GetResourceIndicator(url.Values{})
	require.NoError(t, err)
	assert.Empty(t, resource)

	resource, err = GetResourceIndicator(url.Values{"resource": {"https://api.example.com"}})
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com", resource)

	resource, err = GetResourceIndicator(url.Values{"audience": {"https://api.example.com"}})
	require.NoError(t, err)
	assert.Empty(t, resource)

	resource, err = GetResourceIndicator(url.Values{
		"resource": {"https://api.example.com"},
		"audience": {"https://other.example.com"},
	})
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com", resource)

	_, err = GetResourceIndicator(url.Values{"resource": {"https://api.example.com", "https://other.example.com"}})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidTarget))

	resource, err = GetResourceIndicator(url.Values{"audience": {"https://api.example.com", "https://other.example.com"}})
	require.NoError(t, err)
	assert.Empty(t, resource)
}

func TestValidateResourceIndicator(t *testing.T) {
	resource, err := ValidateResourceIndicator(url.Values{"resource": {"https://api.example.com"}})
	require.NoError(t, err)
	assert.Equal(t, "https://api.example.com", resource)

	resource, err = ValidateResourceIndicator(url.Values{"audience": {"https://api.example.com https://other.example.com"}})
	require.NoError(t, err)
	assert.Empty(t, resource)

	_, err = ValidateResourceIndicator(url.Values{"resource": {"https://api.example.com#fragment"}})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidTarget))

	_, err = ValidateResourceIndicator(url.Values{"resource": {"https://api.example.com", "https://other.example.com"}})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidTarget))
}

func TestGetResourceIndicators(t *testing.T) {
	assert.Empty(t, GetResourceIndicators(url.Values{}))
	assert.Empty(t, GetResourceIndicators(url.Values{"audience": {"https://api.example.com"}}))

	assert.Equal(t, []string{"https://api.example.com"}, GetResourceIndicators(url.Values{"resource": {"https://api.example.com"}}))
	assert.Equal(t,
		[]string{"https://api.example.com", "https://other.example.com"},
		GetResourceIndicators(url.Values{"resource": {"https://api.example.com", "https://other.example.com"}}),
	)

	// The result is a copy: changing it must not change the request form.
	form := url.Values{"resource": {"https://api.example.com"}}
	GetResourceIndicators(form)[0] = "https://changed.example.com"
	assert.Equal(t, "https://api.example.com", form.Get("resource"))
}

func TestValidateResourceIndicators(t *testing.T) {
	const a, b = "https://api.example.com", "https://other.example.com"

	for _, allowMultiple := range []bool{false, true} {
		// Zero and one value behave the same, whatever the option says.
		resources, err := ValidateResourceIndicators(url.Values{}, allowMultiple)
		require.NoError(t, err)
		assert.Empty(t, resources)

		resources, err = ValidateResourceIndicators(url.Values{"resource": {a}}, allowMultiple)
		require.NoError(t, err)
		assert.Equal(t, []string{a}, resources)

		_, err = ValidateResourceIndicators(url.Values{"resource": {a + "#fragment"}}, allowMultiple)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidTarget))
	}

	t.Run("repeated values are rejected by default", func(t *testing.T) {
		_, err := ValidateResourceIndicators(url.Values{"resource": {a, b}}, false)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidTarget))
	})

	t.Run("repeated values are returned in request order when allowed", func(t *testing.T) {
		resources, err := ValidateResourceIndicators(url.Values{"resource": {b, a, "urn:example:resource"}}, true)
		require.NoError(t, err)
		assert.Equal(t, []string{b, a, "urn:example:resource"}, resources)
	})

	t.Run("duplicates are kept", func(t *testing.T) {
		resources, err := ValidateResourceIndicators(url.Values{"resource": {a, a}}, true)
		require.NoError(t, err)
		assert.Equal(t, []string{a, a}, resources)
	})

	t.Run("every value is validated when allowed", func(t *testing.T) {
		for _, invalid := range []string{"", "/relative", b + "#fragment", b + "/with space"} {
			_, err := ValidateResourceIndicators(url.Values{"resource": {a, invalid}}, true)
			require.Error(t, err, invalid)
			assert.True(t, errors.Is(err, ErrInvalidTarget), invalid)

			_, err = ValidateResourceIndicators(url.Values{"resource": {invalid, a}}, true)
			require.Error(t, err, invalid)
			assert.True(t, errors.Is(err, ErrInvalidTarget), invalid)
		}
	})
}

func TestIsValidResourceIndicatorURI(t *testing.T) {
	for _, raw := range []string{
		"https://api.example.com",
		"urn:example:resource",
	} {
		assert.True(t, IsValidResourceIndicatorURI(raw), raw)
	}

	for _, raw := range []string{
		"",
		"/relative",
		"https://api.example.com#fragment",
		"https://api.example.com/with space",
	} {
		assert.False(t, IsValidResourceIndicatorURI(raw), raw)
	}
}

func TestIsValidScopeToken(t *testing.T) {
	for _, scope := range []string{"read", "read:orders", "urn:example:scope"} {
		assert.True(t, IsValidScopeToken(scope), scope)
	}

	for _, scope := range []string{"", "read orders", `read"orders`, `read\\orders`} {
		assert.False(t, IsValidScopeToken(scope), scope)
	}
}
