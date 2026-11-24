// Copyright © 2025 Ory Corp
// Modified by contributors to the Pocket ID fork.
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/pocket-id/fosite/internal/gen"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var header = &Headers{
	Extra: map[string]interface{}{
		"foo": "bar",
	},
}

func TestHash(t *testing.T) {
	for k, tc := range []struct {
		d        string
		strategy Signer
	}{
		{
			d: "RS256",
			strategy: &DefaultSigner{GetPrivateKey: func(_ context.Context) (interface{}, error) {
				return gen.MustRSAKey(), nil
			}},
		},
		{
			d: "ES256",
			strategy: &DefaultSigner{GetPrivateKey: func(_ context.Context) (interface{}, error) {
				return gen.MustES256Key(), nil
			}},
		},
	} {
		t.Run(fmt.Sprintf("case=%d/strategy=%s", k, tc.d), func(t *testing.T) {
			in := []byte("foo")
			out, err := tc.strategy.Hash(context.TODO(), in)
			assert.NoError(t, err)
			assert.NotEqual(t, in, out)
		})
	}
}

func TestAssign(t *testing.T) {
	for k, c := range [][]map[string]interface{}{
		{
			{"foo": "bar"},
			{"baz": "bar"},
			{"foo": "bar", "baz": "bar"},
		},
		{
			{"foo": "bar"},
			{"foo": "baz"},
			{"foo": "bar"},
		},
		{
			{},
			{"foo": "baz"},
			{"foo": "baz"},
		},
		{
			{"foo": "bar"},
			{"foo": "baz", "bar": "baz"},
			{"foo": "bar", "bar": "baz"},
		},
	} {
		assert.EqualValues(t, c[2], assign(c[0], c[1]), "Case %d", k)
	}
}

func TestGenerateJWT(t *testing.T) {
	var key interface{} = gen.MustRSAKey()
	for k, tc := range []struct {
		d        string
		strategy Signer
		resetKey func(strategy Signer)
	}{
		{
			d: "DefaultSigner",
			strategy: &DefaultSigner{
				GetPrivateKey: func(_ context.Context) (interface{}, error) {
					return key, nil
				},
			},
			resetKey: func(strategy Signer) {
				key = gen.MustRSAKey()
			},
		},
		{
			d: "ES256JWTStrategy",
			strategy: &DefaultSigner{
				GetPrivateKey: func(_ context.Context) (interface{}, error) {
					return key, nil
				},
			},
			resetKey: func(strategy Signer) {
				key = &jose.JSONWebKey{
					KeyID:     "test-id",
					Key:       gen.MustES521Key(),
					Algorithm: "ES512",
				}
			},
		},
		{
			d: "ES256JWTStrategy",
			strategy: &DefaultSigner{
				GetPrivateKey: func(_ context.Context) (interface{}, error) {
					return key, nil
				},
			},
			resetKey: func(strategy Signer) {
				key = gen.MustES256Key()
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d/strategy=%s", k, tc.d), func(t *testing.T) {
			claims := &JWTClaims{
				ExpiresAt: time.Now().UTC().Add(time.Hour),
			}

			token, sig, err := tc.strategy.Generate(context.TODO(), claims.ToMapClaims(), header)
			require.NoError(t, err)
			require.NotEmpty(t, token)
			require.NotEmpty(t, sig)

			decoded, err := tc.strategy.Decode(context.TODO(), token)
			require.NoError(t, err)
			require.NotNil(t, decoded)

			if k, ok := key.(*jose.JSONWebKey); ok && k.KeyID != "" {
				require.Equal(t, k.KeyID, decoded.Header["kid"])
			}

			_, err = tc.strategy.Validate(context.TODO(), token)
			require.NoError(t, err)

			_, err = tc.strategy.Validate(context.TODO(), token+"."+"0123456789")
			require.Error(t, err)

			partToken := strings.Split(token, ".")[2]

			_, err = tc.strategy.Validate(context.TODO(), partToken)
			require.Error(t, err)

			// Reset private key
			tc.resetKey(tc.strategy)

			// Lets validate the exp claim
			claims = &JWTClaims{
				ExpiresAt: time.Now().UTC().Add(-time.Hour),
			}
			token, _, err = tc.strategy.Generate(context.TODO(), claims.ToMapClaims(), header)
			require.NoError(t, err)
			require.NotNil(t, token)

			_, err = tc.strategy.Validate(context.TODO(), token)
			require.Error(t, err)

			// Lets validate the nbf claim
			claims = &JWTClaims{
				NotBefore: time.Now().UTC().Add(time.Hour),
			}
			token, _, err = tc.strategy.Generate(context.TODO(), claims.ToMapClaims(), header)
			require.NoError(t, err)
			require.NotNil(t, token)
			// t.Logf("%s.%s", token, sig)
			sig, err = tc.strategy.Validate(context.TODO(), token)
			require.Error(t, err)
			require.Empty(t, sig, "%s", err)
		})
	}
}

func TestValidateSignatureRejectsJWT(t *testing.T) {
	for k, tc := range []struct {
		d        string
		strategy Signer
	}{
		{
			d: "RS256",
			strategy: &DefaultSigner{GetPrivateKey: func(_ context.Context) (interface{}, error) {
				return gen.MustRSAKey(), nil
			},
			},
		},
		{
			d: "ES256",
			strategy: &DefaultSigner{
				GetPrivateKey: func(_ context.Context) (interface{}, error) {
					return gen.MustES256Key(), nil
				},
			},
		},
	} {
		t.Run(fmt.Sprintf("case=%d/strategy=%s", k, tc.d), func(t *testing.T) {
			for k, c := range []string{
				"",
				" ",
				"foo.bar",
				"foo.",
				".foo",
			} {
				_, err := tc.strategy.Validate(context.TODO(), c)
				assert.Error(t, err)
				t.Logf("Passed test case %d", k)
			}
		})
	}
}

func TestDecodeVerifiesSignatureBeforeClaims(t *testing.T) {
	key := gen.MustRSAKey()
	strategy := &DefaultSigner{GetPrivateKey: func(_ context.Context) (interface{}, error) { return key, nil }}

	token, _, err := strategy.Generate(context.TODO(), MapClaims{"sub": "alice", "exp": time.Now().Add(time.Hour).Unix()}, header)
	require.NoError(t, err)
	parts := strings.Split(token, ".")

	t.Run("genuine signature with replaced claims", func(t *testing.T) {
		replaced := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"mallory","padding":"`+strings.Repeat("a", 1<<16)+`"}`)) + "." + parts[2]
		decoded, err := strategy.Decode(context.TODO(), replaced)

		var ve *ValidationError
		require.ErrorAs(t, err, &ve)
		assert.True(t, ve.Has(ValidationErrorSignatureInvalid))
		// No token means the claims were never decoded
		assert.Nil(t, decoded)
	})

	t.Run("malformed claims with an invalid signature fail the signature check", func(t *testing.T) {
		// Decoding the claims first would report them as invalid instead
		malformed := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + "." + parts[2]
		_, err := strategy.Decode(context.TODO(), malformed)

		var ve *ValidationError
		require.ErrorAs(t, err, &ve)
		assert.True(t, ve.Has(ValidationErrorSignatureInvalid))
		assert.False(t, ve.Has(ValidationErrorClaimsInvalid))
	})

	t.Run("large header within the limit", func(t *testing.T) {
		large, _, err := strategy.Generate(context.TODO(), MapClaims{"sub": "alice", "exp": time.Now().Add(time.Hour).Unix()}, &Headers{Extra: map[string]interface{}{"x-chain": strings.Repeat("A", 8<<10)}})
		require.NoError(t, err)
		decoded, err := strategy.Decode(context.TODO(), large)
		require.NoError(t, err)
		assert.Equal(t, "alice", decoded.Claims["sub"])
	})

	t.Run("oversized header", func(t *testing.T) {
		oversized := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","x":"`+strings.Repeat("a", maxVerifiedHeaderLength)+`"}`)) + "." + parts[1] + "." + parts[2]
		_, err := strategy.Decode(context.TODO(), oversized)

		var ve *ValidationError
		require.ErrorAs(t, err, &ve)
		assert.True(t, ve.Has(ValidationErrorMalformed))
	})

	t.Run("expired token still returns its claims", func(t *testing.T) {
		expired, _, err := strategy.Generate(context.TODO(), MapClaims{"sub": "alice", "exp": time.Now().Add(-time.Hour).Unix()}, header)
		require.NoError(t, err)
		decoded, err := strategy.Decode(context.TODO(), expired)

		var ve *ValidationError
		require.ErrorAs(t, err, &ve)
		assert.True(t, ve.Has(ValidationErrorExpired))
		assert.Equal(t, "alice", decoded.Claims["sub"])
	})
}

func TestEd25519JSONWebKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	jsonWebKey := jose.JSONWebKey{Key: privateKey, Algorithm: string(jose.EdDSA)}

	for name, key := range map[string]interface{}{"pointer": &jsonWebKey, "value": jsonWebKey} {
		t.Run(name, func(t *testing.T) {
			strategy := &DefaultSigner{GetPrivateKey: func(_ context.Context) (interface{}, error) { return key, nil }}

			token, sig, err := strategy.Generate(context.TODO(), MapClaims{"sub": "alice", "exp": time.Now().Add(time.Hour).Unix()}, header)
			require.NoError(t, err)

			decoded, err := strategy.Decode(context.TODO(), token)
			require.NoError(t, err)
			assert.Equal(t, "alice", decoded.Claims["sub"])

			validatedSig, err := strategy.Validate(context.TODO(), token)
			require.NoError(t, err)
			assert.Equal(t, sig, validatedSig)
		})
	}
}
