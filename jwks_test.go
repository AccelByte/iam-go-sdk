// Copyright 2026 AccelByte Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iam

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	oldKeyOnce sync.Once
	oldKey     *rsa.PublicKey
	errOldKey  error
)

// testOldKey is a key with different material from testJWTPrivateKey, so tests
// can tell which of the two the client holds.
func testOldKey(t *testing.T) *rsa.PublicKey {
	t.Helper()

	oldKeyOnce.Do(func() {
		var privateKey *rsa.PrivateKey

		privateKey, errOldKey = rsa.GenerateKey(rand.Reader, 2048)
		if errOldKey == nil {
			oldKey = &privateKey.PublicKey
		}
	})
	require.NoError(t, errOldKey)

	return oldKey
}

func testRSAJWK(kid string) (JWK, rsa.PublicKey) {
	publicKey := mustUnmarshalRSA(testJWTPrivateKey).PublicKey

	return JWK{
		Kty: keyTypeRSA,
		Use: keyUseSignature,
		Kid: kid,
		N:   jwtEncoding.EncodeToString(publicKey.N.Bytes()),
		E:   "AQAB",
	}, publicKey
}

func encodeExponent(b ...byte) string { return jwtEncoding.EncodeToString(b) }

// newJWKSClient returns a client whose JWKS endpoint serves keys and which already
// trusts testOldKey under the key ID "old".
func newJWKSClient(t *testing.T, keys []JWK) *DefaultClient {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, jwksPath, r.URL.Path)
		assert.NoError(t, json.NewEncoder(w).Encode(Keys{Keys: keys}))
	}))
	t.Cleanup(server.Close)

	client := NewDefaultClient(&Config{BaseURL: server.URL})
	client.setKeySafe("old", testOldKey(t))

	return client
}

func assertKey(t *testing.T, client *DefaultClient, kid string, want *rsa.PublicKey) {
	t.Helper()

	got, loaded := client.getKeySafe(kid)
	if want == nil {
		assert.False(t, loaded, "key %q should not be loaded", kid)

		return
	}

	require.True(t, loaded, "key %q should be loaded", kid)
	assert.Equal(t, 0, want.N.Cmp(got.N), "key %q modulus", kid)
	assert.Equal(t, want.E, got.E, "key %q exponent", kid)
}

// A key that can't be parsed must not stop the keys after it from loading.
func Test_GetJWKSSkipsUnparsableKey(t *testing.T) {
	t.Parallel()

	goodKey, publicKey := testRSAJWK("good")
	badKey := JWK{Kty: keyTypeRSA, Kid: "bad", N: "not base64url!", E: "AQAB"}

	client := newJWKSClient(t, []JWK{badKey, goodKey})
	require.NoError(t, client.getJWKS(nil))

	assertKey(t, client, "bad", nil)
	assertKey(t, client, "good", &publicKey)
}

// A refresh adds the keys in the response and keeps the ones it already has.
func Test_GetJWKSKeepsKeysMissingFromResponse(t *testing.T) {
	t.Parallel()

	goodKey, publicKey := testRSAJWK("good")

	client := newJWKSClient(t, []JWK{goodKey})
	require.NoError(t, client.getJWKS(nil))

	assertKey(t, client, "good", &publicKey)
	assertKey(t, client, "old", testOldKey(t))
}

// Keys crypto/rsa refuses whatever its settings are skipped, so they never replace
// a usable key with the same ID.
func Test_GetJWKSSkipsKeysRSACannotVerifyWith(t *testing.T) {
	t.Parallel()

	withExponent := func(kid, e string) JWK {
		jwk, _ := testRSAJWK(kid)
		jwk.E = e

		return jwk
	}
	withModulus := func(kid string, n *big.Int) JWK {
		jwk, _ := testRSAJWK(kid)
		jwk.N = jwtEncoding.EncodeToString(n.Bytes())

		return jwk
	}
	publicKey := mustUnmarshalRSA(testJWTPrivateKey).PublicKey
	evenModulus := new(big.Int).SetBit(new(big.Int).Set(publicKey.N), 0, 0)
	encryptionKey, _ := testRSAJWK("enc")
	encryptionKey.Use = "enc"

	unusable := []JWK{
		withExponent("old", encodeExponent(0)), // would replace the usable "old" key
		withExponent("empty-exponent", ""),
		withExponent("exponent-one", encodeExponent(1)),
		withExponent("even-exponent", encodeExponent(4)),
		withExponent("exponent-too-large", encodeExponent(0x80, 0, 0, 1)),
		withExponent("exponent-high-bit", encodeExponent(0x80, 0, 0, 0, 0, 0, 0, 1)),
		withExponent("exponent-too-long", encodeExponent(1, 0, 0, 0, 0, 0, 0, 0, 1)),
		withModulus("zero-modulus", big.NewInt(0)),
		withModulus("one-modulus", big.NewInt(1)),
		withModulus("even-modulus", evenModulus),
		{Kty: "EC", Kid: "ec"},
		encryptionKey,
	}

	client := newJWKSClient(t, unusable)
	require.NoError(t, client.getJWKS(nil))

	assertKey(t, client, "old", testOldKey(t))

	for _, jwk := range unusable[1:] {
		assertKey(t, client, jwk.Kid, nil)
	}
}

func Test_GetJWKSWithEmptyKeyListKeepsCurrentKeys(t *testing.T) {
	t.Parallel()

	client := newJWKSClient(t, nil)

	require.NoError(t, client.getJWKS(nil))
	assertKey(t, client, "old", testOldKey(t))
}

func Test_GetPublicExponent(t *testing.T) {
	t.Parallel()

	valid := map[string]int{
		"AQAB":                                          65537,
		encodeExponent(3):                               3,
		encodeExponent(0x7f, 0xff, 0xff, 0xff):          1<<31 - 1,
		encodeExponent(0, 0, 0, 0, 0, 1, 0, 1):          65537,
		encodeExponent(0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1): 65537, // zero-padded past 8 bytes
	}
	for jwkE, want := range valid {
		got, err := getPublicExponent(jwkE)
		require.NoError(t, err, "exponent %q", jwkE)
		assert.Equal(t, want, got, "exponent %q", jwkE)
	}

	invalid := []string{
		"",
		encodeExponent(0),
		encodeExponent(1),
		encodeExponent(4),
		encodeExponent(0x80, 0, 0, 1),
		encodeExponent(0x80, 0, 0, 0, 0, 0, 0, 1),
		encodeExponent(make([]byte, 9)...),
		encodeExponent(1, 0, 0, 0, 0, 0, 0, 0, 1),
	}
	for _, jwkE := range invalid {
		assert.NotPanics(t, func() {
			_, err := getPublicExponent(jwkE)
			assert.Error(t, err, "exponent %q", jwkE)
		})
	}
}

// kty and use are compared without case, as keys in any case were trusted before.
func Test_GetJWKSAcceptsKeyTypeAndUseInAnyCase(t *testing.T) {
	t.Parallel()

	upper, publicKey := testRSAJWK("upper")
	upper.Use = "SIG"
	lower, _ := testRSAJWK("lower")
	lower.Kty = "rsa"
	bare, _ := testRSAJWK("bare")
	bare.Kty, bare.Use = "", ""

	client := newJWKSClient(t, []JWK{upper, lower, bare})
	require.NoError(t, client.getJWKS(nil))

	for _, kid := range []string{"upper", "lower", "bare"} {
		assertKey(t, client, kid, &publicKey)
	}
}
