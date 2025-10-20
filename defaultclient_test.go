// Copyright 2018-2021 AccelByte Inc
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
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AccelByte/bloom"
	jose "github.com/AccelByte/go-jose"
	"github.com/AccelByte/go-jose/jwt"
	"github.com/AccelByte/go-restful-plugins/v3/pkg/jaeger"
	"github.com/bluele/gcache"
	"github.com/google/uuid"
	"github.com/opentracing/opentracing-go"
	cache "github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	defaultUserRole   = "2251438839e948d783ec0e5281daf05b"
	mockUserRole      = "9a59f28b622e43f4a6edb214a13bb8aa"
	keyID             = "testKey"
	invalid           = "invalid"
	testJWTPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyVnj4nzplD5g3a3bm1kpVNACMSP2MBZ81rD/UHORm3k+DlaY
pL3EY5itPHr2tBYOnXMGsRgUM1hELz004Rabx8CsvzxUzaLMP6bYPZmX5KWmaC6N
y4QGKq8zJTGxRMFDCGq8Fzjle/gHwp+zE6yhCHI94Sxqb+xFphT7tz8CnT+MlS96
M4yBavOUbcJ6pQ7ljdjLSq1W67ND/QhQFPEGAkaJxy7f22dKDsFDGD/5zt4jmQG7
pmdNg7bmijJKGRUsj0wgjHedtGuoBOx4UamBq/B7yEBqBqqGsjJej/GJOAh19Ie5
xYTWPoiPIaTxOlC4N2j46sOCUPtjQ+Ta0qd8pQIDAQABAoIBAQCUMyptML2HlGYd
o/Koo/as6zFB1BNHD7YxGzPAll+MzK9lRE2zq81Z9S1E/8iHglidgOVjAbMUm5oM
HwPFzKs6WlGLrC9K79Ff5EDzDhLjgx05P1K0gec8EZoWfT3ZulnJXy4z9XfLSCMG
GB9pkr0wB04OZ2+sE36sIHOpS6Jz89t57+cD+6Iw1bo3lWDEx46lY25fixCYfsqO
cvqnsrMnWa6xlEQL+3scvhdiiaRJ3x7oDjLAvO3Uj1ZLBTBtxXNmqu4XmCvwBtt1
7NR4RtvCUJ0OJvyQLCcToTC0qzC3e0UaglRfDz3GIeYkuQbdWDhedatCUWjSIrQa
6WYIsgBBAoGBAPrFutzGIcqaTIUzu0lT25gvy3y1wAfwF1W0sS9K7crz25Vf3NK/
kv+GAbmX/XyYAN25S+8WdFvqLPlZdvPyI5dAr3ieE28s7pg1k9+gC7PS4iZBN+DM
/U6P0yrczOSFeophscr2PALlWoL7+KCVv8hpjIiYwwegh1kttYlu1/kRAoGBAM2M
a052luUiGKG7z4+67WOe10wtgS+GRuvBTubHUezzdrhqbObmv/bfFAPsK2CjVEwP
oK7ac8FgaBmDe7kPsZw0qeNPVdQVh5VNI7Fhy6LiwAk6Ze6yX3U4cVx1k1/jESFt
GuDfAZl3gaz8rhAw6wV+/zfF3m7rpBKs9ogsxSpVAoGBAO14w1x/7835Ug8tjuSA
mcnDMPJW9pNNw/swUj3Tud1gEgehMO8N5Xk+AHItQSl0lBVjfEnbvLKxzocONnwK
R7Pa2I/jOcolBYhz7CVvXMWcJPZO+khSNmnn/vNvBkQ9Nm7G1uO5S9j+MjkpvSbs
yCFT+nX8G2wkkydbBrcvlSvRAoGAOMCvlB98NFHAuU8w1P+IsfvWeCsMQ0Hw7QEX
tvKLtT/XpL2Fyg8mK5SWYyrfIzSVftbFx+F7GoZy17CNBaDGqlmEGsX57a/wGpIM
69oTrqqq2SFtqYVIhAYMjrnL8iqwvSjxxers9yGfBVNTABdxnLfe4dhZPQkE6T8m
Zpzt520CgYAHO3H5PpOCmj3I0Udz44gJrgb17myugTXoTzZysUwu+WDOvLMTxW1o
QhLJPw+k1O94WC5Ysmk/rRxL4ZQujNPoz5YI4ELOquzi6Q7cxaieTidz1HuXMf35
RDShmvcHF7W6ost87Z9tLYxaAQJVcMQVXlH/9VJ2QsFBZYZJjkjE9g==
-----END RSA PRIVATE KEY-----`
	jaegerAgentHost = "localhost:6831"
)

type tokenUserData struct {
	Namespace      string
	UserID         string `json:"UserId"`
	DisplayName    string
	PlatformID     string
	PlatformUserID string
	ClientID       string
	Roles          []string
	NamespaceRoles []NamespaceRole `json:"namespace_roles"`
	Permissions    []Permission
	JusticeFlags   int `json:"jflgs"`
}

var (
	testClient *DefaultClient
	privateKey *rsa.PrivateKey
	signer     jose.Signer
)

func init() {
	jaeger.InitGlobalTracer(jaegerAgentHost, "", "test", "")

	privateKey = mustUnmarshalRSA(testJWTPrivateKey)
	testClient = NewDefaultClient(&Config{})

	testClient.keys = make(map[string]*rsa.PublicKey)
	testClient.rolePermissionCache = cache.New(cache.DefaultExpiration, cache.DefaultExpiration)
	testClient.revocationFilter = bloom.New(100)
	testClient.revokedUsers = make(map[string]time.Time)
	testClient.localValidationActive = true
	testClient.clientInfoCache = cache.New(cache.DefaultExpiration, cache.DefaultExpiration)

	var err error

	signer, err = jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key: jose.JSONWebKey{
				KeyID: keyID,
				Key:   privateKey,
			},
		},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}

	testClient.keys[keyID] = &rsa.PublicKey{
		E: privateKey.PublicKey.E,
		N: privateKey.PublicKey.N,
	}

	testClient.rolePermissionCache.Set(
		defaultUserRole,
		[]Permission{
			{
				Resource: "NAMESPACE:{namespace}:USER:{userId}:ORDER",
				Action:   ActionCreate | ActionRead | ActionUpdate,
			},
		},
		cache.DefaultExpiration)

	testClient.rolePermissionCache.Set(
		mockUserRole,
		[]Permission{
			{
				Resource: "NAMESPACE:*:USER:{userId}:FRIENDS",
				Action:   ActionCreate | ActionRead | ActionUpdate,
			},
			{
				Resource: "NAMESPACE:*:USER:*:SLOTDATA",
				Action:   ActionCreate | ActionRead | ActionUpdate,
			},
		},
		cache.DefaultExpiration)

	testClient.remoteTokenValidation =
		func(accessToken string, rootSpan opentracing.Span) (bool, error) {
			if accessToken == invalid {
				return false, nil
			}

			return true, nil
		}
}

func mustUnmarshalRSA(data string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		panic("failed to decode PEM data")
	}

	var key interface{}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			panic("failed to parse RSA key: " + err.Error())
		}
	}

	if key, ok := key.(*rsa.PrivateKey); ok {
		return key
	}

	panic("key is not of type *rsa.PrivateKey")
}

func Test_NewDefaultClient(t *testing.T) {
	t.Parallel()

	conf := &Config{}

	defaultClient := NewDefaultClient(conf)

	assert.Equal(t, defaultRoleCacheTime, defaultClient.config.RolesCacheExpirationTime)
	assert.Equal(t, defaultJWKSRefreshInterval, defaultClient.config.JWKSRefreshInterval)
	assert.Equal(t, defaultRevocationListRefreshInterval, defaultClient.config.RevocationListRefreshInterval)
}

func Test_GetClientToken(t *testing.T) {
	t.Parallel()

	mockAccessToken := "mockAccessToken"

	mockHTTPClient := &httpClientMock{
		doMock: func(req *http.Request) (*http.Response, error) {
			tokenResp := TokenResponse{
				AccessToken: mockAccessToken,
			}

			b, _ := json.Marshal(tokenResp)

			r := ioutil.NopCloser(bytes.NewReader(b))

			return &http.Response{
				Status:     http.StatusText(http.StatusOK),
				StatusCode: http.StatusOK,
				Body:       r,
				Header:     http.Header{},
			}, nil
		},
	}

	conf := &Config{}
	defaultClient := NewDefaultClient(conf)
	defaultClient.httpClient = mockHTTPClient

	err := defaultClient.ClientTokenGrant()
	token := defaultClient.ClientToken()

	assert.NoError(t, err, "client token grant should be successful")
	assert.Equal(t, mockAccessToken, token, "access token should be equal")

	// test tracing
	err = defaultClient.ClientTokenGrant(WithJaegerContext(context.Background()))
	token = defaultClient.ClientToken(WithJaegerContext(context.Background()))

	assert.NoError(t, err, "client token grant should be successful")
	assert.Equal(t, mockAccessToken, token, "access token should be equal")
}

func Test_StartLocalValidation(t *testing.T) {
	t.Parallel()

	mockHTTPClient := &httpClientMock{
		doMock: func(req *http.Request) (*http.Response, error) {
			resp := struct {
				Keys
				RevocationList
			}{}

			b, _ := json.Marshal(resp)

			r := ioutil.NopCloser(bytes.NewReader(b))

			return &http.Response{
				Status:     http.StatusText(http.StatusOK),
				StatusCode: http.StatusOK,
				Body:       r,
				Header:     http.Header{},
			}, nil
		},
	}

	conf := &Config{}
	defaultClient := NewDefaultClient(conf)
	defaultClient.httpClient = mockHTTPClient

	err := defaultClient.StartLocalValidation()

	assert.NoError(t, err, "start local validation should be successful")
	assert.True(t, defaultClient.localValidationActive, "local validation should be active")

	// test tracing
	err = defaultClient.StartLocalValidation(WithJaegerContext(context.Background()))
	assert.NoError(t, err, "start local validation should be successful")
	assert.True(t, defaultClient.localValidationActive, "local validation should be active")
}

// nolint: dupl
func Test_DefaultClientUserEmailVerificationStatus(t *testing.T) {
	t.Parallel()

	type testTable struct {
		justiceFlag              int
		expectedValidationResult bool
	}

	testCases := []testTable{
		{justiceFlag: 0, expectedValidationResult: false},
		{justiceFlag: 1, expectedValidationResult: true},
		{justiceFlag: 2, expectedValidationResult: false},
		{justiceFlag: 3, expectedValidationResult: true},
		{justiceFlag: 4, expectedValidationResult: false},
		{justiceFlag: 5, expectedValidationResult: true},
		{justiceFlag: 6, expectedValidationResult: false},
		{justiceFlag: 7, expectedValidationResult: true},
	}

	for _, testCase := range testCases {
		userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a", JusticeFlags: testCase.justiceFlag}
		claims := generateClaims(t, userData)

		validationResult, _ := testClient.UserEmailVerificationStatus(claims)
		assert.Equal(t, testCase.expectedValidationResult, validationResult, "email verification validation does not match")

		// test tracing
		validationResult, _ = testClient.UserEmailVerificationStatus(claims, WithJaegerContext(context.Background()))
		assert.Equal(t, testCase.expectedValidationResult, validationResult, "email verification validation does not match")
	}
}

// nolint: dupl
func Test_DefaultClientUserPhoneVerificationStatus(t *testing.T) {
	t.Parallel()

	type testTable struct {
		justiceFlag              int
		expectedValidationResult bool
	}

	testCases := []testTable{
		{justiceFlag: 0, expectedValidationResult: false},
		{justiceFlag: 1, expectedValidationResult: false},
		{justiceFlag: 2, expectedValidationResult: true},
		{justiceFlag: 3, expectedValidationResult: true},
		{justiceFlag: 4, expectedValidationResult: false},
		{justiceFlag: 5, expectedValidationResult: false},
		{justiceFlag: 6, expectedValidationResult: true},
		{justiceFlag: 7, expectedValidationResult: true},
	}

	for _, testCase := range testCases {
		userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a", JusticeFlags: testCase.justiceFlag}
		claims := generateClaims(t, userData)

		validationResult, _ := testClient.UserPhoneVerificationStatus(claims)

		assert.Equal(t, testCase.expectedValidationResult, validationResult, "phone verification validation does not match")

		// test tracing
		validationResult, _ = testClient.UserPhoneVerificationStatus(claims, WithJaegerContext(context.Background()))
		assert.Equal(t, testCase.expectedValidationResult, validationResult, "phone verification validation does not match")
	}
}

// nolint: dupl
func Test_DefaultClientUserAnonymousStatus(t *testing.T) {
	t.Parallel()

	type testTable struct {
		justiceFlag              int
		expectedValidationResult bool
	}

	testCases := []testTable{
		{justiceFlag: 0, expectedValidationResult: false},
		{justiceFlag: 1, expectedValidationResult: false},
		{justiceFlag: 2, expectedValidationResult: false},
		{justiceFlag: 3, expectedValidationResult: false},
		{justiceFlag: 4, expectedValidationResult: true},
		{justiceFlag: 5, expectedValidationResult: true},
		{justiceFlag: 6, expectedValidationResult: true},
		{justiceFlag: 7, expectedValidationResult: true},
	}

	for _, testCase := range testCases {
		userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a", JusticeFlags: testCase.justiceFlag}
		claims := generateClaims(t, userData)

		validationResult, _ := testClient.UserAnonymousStatus(claims)

		assert.Equal(t, testCase.expectedValidationResult, validationResult,
			"anonymous verification validation does not match")

		// test tracing
		validationResult, _ = testClient.UserAnonymousStatus(claims, WithJaegerContext(context.Background()))
		assert.Equal(t, testCase.expectedValidationResult, validationResult,
			"anonymous verification validation does not match")
	}
}

func Test_DefaultClientValidateAndParseClaims(t *testing.T) {
	t.Parallel()

	grantedPermission := Permission{
		Resource: "NAMESPACE:foo:USER:888:PROFILE:birthday",
		Action:   ActionCreate | ActionRead | ActionUpdate | ActionDelete,
	}
	userData := &tokenUserData{
		UserID:      "e9b1ed0c1a3d473cd970abc845b51d3a",
		Permissions: []Permission{grantedPermission},
		Namespace:   "testnamespace1234",
	}

	claims := generateClaims(t, userData)

	accessToken, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		panic(err)
	}

	claims, errValidateAndParseClaims := testClient.ValidateAndParseClaims(accessToken)

	assert.Nil(t, errValidateAndParseClaims, "access token is invalid")
	assert.NotNil(t, claims, "claims should not nil")

	// test tracing
	claims, errValidateAndParseClaims = testClient.ValidateAndParseClaims(
		accessToken,
		WithJaegerContext(context.Background()),
	)
	assert.Nil(t, errValidateAndParseClaims, "access token is invalid")
	assert.NotNil(t, claims, "claims should not nil")
	assert.Equal(t, userData.Namespace, claims.Namespace, "namespace should be equal")
	assert.Equal(t, userData.UserID, claims.Subject, "subject should be equal with access token")
	assert.Equal(t, userData.ClientID, claims.ClientID, "clientID should be equal")
	assert.ElementsMatch(t, userData.Permissions, claims.Permissions)
}

func Test_DefaultClientValidateAndParseClaims_ExpiredToken(t *testing.T) {
	t.Parallel()

	grantedPermission := Permission{
		Resource: "NAMESPACE:foo:USER:888:PROFILE:birthday",
		Action:   ActionCreate | ActionRead | ActionUpdate | ActionDelete,
	}
	userData := &tokenUserData{
		UserID:      "e9b1ed0c1a3d473cd970abc845b51d3a",
		Permissions: []Permission{grantedPermission},
	}

	claims := generateClaims(t, userData)
	claims.Expiry = jwt.NewNumericDate(time.Now().UTC().Add(-time.Minute))

	accessToken, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)

	claims, errValidateAndParseClaims := testClient.ValidateAndParseClaims(accessToken)

	assert.Error(t, errValidateAndParseClaims, "access token should be invalid")
	assert.Nil(t, claims, "claims should be nil")

	// test tracing
	claims, errValidateAndParseClaims = testClient.ValidateAndParseClaims(
		accessToken,
		WithJaegerContext(context.Background()),
	)
	assert.Error(t, errValidateAndParseClaims, "access token should be invalid")
	assert.Nil(t, claims, "claims should be nil")
}

// nolint: funlen
func Test_DefaultClientValidatePermission(t *testing.T) {
	t.Parallel()

	type testTable struct {
		requiredResource string
		grantedResource  string
		expectedResult   bool
	}

	testCases := []testTable{
		{
			requiredResource: "NAMESPACE:foo:USER:888:PROFILE:birthday",
			grantedResource:  "NAMESPACE:foo:USER:888:PROFILE:birthday",
			expectedResult:   true,
		},
		{
			requiredResource: "NAMESPACE:foo:USER:888:PROFILE:*",
			grantedResource:  "NAMESPACE:foo:USER:888:PROFILE:birthday",
			expectedResult:   false,
		},
		{
			requiredResource: "NAMESPACE:foo:USER:888:PROFILE:birthday",
			grantedResource:  "NAMESPACE:foo:USER:888:PROFILE:*",
			expectedResult:   true,
		},
		{
			requiredResource: "NAMESPACE:foo:USER:888:PROFILE:birthday",
			grantedResource:  "NAMESPACE:foo:USER:*",
			expectedResult:   false,
		},
		{
			requiredResource: "NAMESPACE:foo:USER:888:PROFILE:birthday",
			grantedResource:  "NAMESPACE:foo:USER:*:*",
			expectedResult:   true,
		},
		{
			requiredResource: "NAMESPACE:foo:USER:888:PROFILE:birthday",
			grantedResource:  "*",
			expectedResult:   true,
		},
		{
			requiredResource: "NAMESPACE:foo:USER:888:PROFILE:birthday",
			grantedResource:  "NAMESPACE:foo:*",
			expectedResult:   true,
		},
		{
			requiredResource: "NAMESPACE:foo:USER:888:PROFILE:birthday",
			grantedResource:  "NAMESPACE:foo:USER",
			expectedResult:   false,
		},
		{
			requiredResource: "NAMESPACE:foo:USER:888",
			grantedResource:  "NAMESPACE:foo:USER:888:*:*",
			expectedResult:   true,
		},
		{
			requiredResource: "NAMESPACE:foo:USER:888",
			grantedResource:  "NAMESPACE:foo:USER:888:PROFILE:*",
			expectedResult:   false,
		},
	}

	for _, testCase := range testCases {
		grantedPermission := Permission{
			Resource: testCase.grantedResource,
			Action:   ActionCreate | ActionRead | ActionUpdate | ActionDelete,
		}
		requiredPermission := Permission{
			Resource: testCase.requiredResource,
			Action:   ActionCreate | ActionRead | ActionUpdate | ActionDelete,
		}

		userData := &tokenUserData{
			UserID:      "e9b1ed0c1a3d473cd970abc845b51d3a",
			Permissions: []Permission{grantedPermission},
		}
		claims := generateClaims(t, userData)

		permissionResources := make(map[string]string)
		permissionResources["{namespace}"] = userData.Namespace
		validationResult, _ := testClient.ValidatePermission(claims, requiredPermission, permissionResources)

		assert.Equal(t, testCase.expectedResult, validationResult, "resource string validation does not match")

		// test tracing
		validationResult, _ = testClient.ValidatePermission(
			claims,
			requiredPermission,
			permissionResources,
			WithJaegerContext(context.Background()),
		)
		assert.Equal(t, testCase.expectedResult, validationResult, "resource string validation does not match")
	}
}

func Test_DefaultClientValidatePermission_ResourceStringOnRole_ValidNamespaceRole(t *testing.T) {
	t.Parallel()

	type testTable struct {
		requiredResource string
		expectedResult   bool
	}

	testCases := []testTable{
		{requiredResource: "NAMESPACE:foo:USER:888:ORDER", expectedResult: true},
		{requiredResource: "NAMESPACE:foo:USER:888:FRIENDS", expectedResult: true},
		{requiredResource: "NAMESPACE:baz:USER:888:ORDER", expectedResult: true},
		{requiredResource: "NAMESPACE:baz:USER:888:ORDER", expectedResult: true},
		{requiredResource: "NAMESPACE:baz:USER:888:ORDER", expectedResult: true},
		{requiredResource: "NAMESPACE:baz:USER:888:FRIENDS", expectedResult: true},
		{requiredResource: "NAMESPACE:bar:USER:888:FRIENDS", expectedResult: true},
		{requiredResource: "NAMESPACE:*:USER:*:SLOTDATA", expectedResult: true},
		{requiredResource: "NAMESPACE:bar:USER:888:ORDER", expectedResult: false},
		{requiredResource: "NAMESPACE:foo:USER:999:ORDER", expectedResult: false},
		{requiredResource: "NAMESPACE:bar:USER:888:ORDER", expectedResult: false},
		{requiredResource: "NAMESPACE:baz:USER:999:ORDER", expectedResult: false},
		{requiredResource: "NAMESPACE:foo:USER:999:FRIENDS", expectedResult: false},
		{requiredResource: "NAMESPACE:baz:USER:999:FRIENDS", expectedResult: false},
	}

	for _, testCase := range testCases {
		requiredPermission := Permission{
			Resource: testCase.requiredResource,
			Action:   ActionCreate | ActionRead | ActionUpdate,
		}

		userData := &tokenUserData{
			UserID:    "888",
			Namespace: "bar",
			NamespaceRoles: []NamespaceRole{
				{
					RoleID:    defaultUserRole,
					Namespace: "foo",
				},
				{
					RoleID:    defaultUserRole,
					Namespace: "baz",
				},
				{
					RoleID:    mockUserRole,
					Namespace: "baz",
				},
			},
		}
		claims := generateClaims(t, userData)

		permissionResources := make(map[string]string)
		permissionResources["{namespace}"] = userData.Namespace
		validationResult, _ := testClient.ValidatePermission(claims, requiredPermission, permissionResources)

		assert.Equal(t, testCase.expectedResult, validationResult,
			"resource string %s validation on roles does not match", requiredPermission.Resource)
	}
}

func Test_DefaultClientValidatePermission_ResourceStringOnRole_InvalidNamespaceRole(t *testing.T) {
	t.Parallel()

	type testTable struct {
		requiredResource string
		expectedResult   bool
	}

	testCases := []testTable{
		{requiredResource: "NAMESPACE:foo:USER:888:FRIENDS", expectedResult: false},
		{requiredResource: "NAMESPACE:baz:USER:888:FRIENDS", expectedResult: false},
		{requiredResource: "NAMESPACE:baz:USER:999:FRIENDS", expectedResult: false},
		{requiredResource: "NAMESPACE:foo:USER:888:FRIENDS", expectedResult: false},
		{requiredResource: "NAMESPACE:*:USER:*:SLOTDATA", expectedResult: false},
	}

	for _, testCase := range testCases {
		requiredPermission := Permission{
			Resource: testCase.requiredResource,
			Action:   ActionCreate | ActionRead | ActionUpdate,
		}

		userData := &tokenUserData{
			UserID:    "888",
			Namespace: "bar",
			NamespaceRoles: []NamespaceRole{
				{
					RoleID:    defaultUserRole,
					Namespace: "foo",
				},
				{
					RoleID:    defaultUserRole,
					Namespace: "baz",
				},
			},
		}
		claims := generateClaims(t, userData)

		permissionResources := make(map[string]string)
		permissionResources["{namespace}"] = userData.Namespace
		validationResult, _ := testClient.ValidatePermission(claims, requiredPermission, permissionResources)

		assert.Equal(t, testCase.expectedResult, validationResult,
			"resource string %s validation on roles does not match", requiredPermission.Resource)

		// test tracing
		validationResult, _ = testClient.ValidatePermission(
			claims,
			requiredPermission,
			permissionResources,
			WithJaegerContext(context.Background()),
		)
		assert.Equal(t, testCase.expectedResult, validationResult,
			"resource string %s validation on roles does not match", requiredPermission.Resource)
	}
}

func Test_DefaultClientValidatePermission_ResourceStringOnRoles(t *testing.T) {
	t.Parallel()

	type testTable struct {
		requiredResource string
		expectedResult   bool
	}

	testCases := []testTable{
		{requiredResource: "NAMESPACE:foo:USER:888:ORDER", expectedResult: true},
		{requiredResource: "NAMESPACE:bar:USER:888:ORDER", expectedResult: false},
		{requiredResource: "NAMESPACE:foo:USER:888:ORDER", expectedResult: true},
		{requiredResource: "NAMESPACE:foo:USER:999:ORDER", expectedResult: false},
	}

	for _, testCase := range testCases {
		requiredPermission := Permission{
			Resource: testCase.requiredResource,
			Action:   ActionCreate | ActionRead | ActionUpdate,
		}

		userData := &tokenUserData{UserID: "888", Namespace: "foo", Roles: []string{defaultUserRole}}
		claims := generateClaims(t, userData)

		permissionResources := make(map[string]string)
		permissionResources["{namespace}"] = userData.Namespace
		validationResult, _ := testClient.ValidatePermission(claims, requiredPermission, permissionResources)

		assert.Equal(t, testCase.expectedResult, validationResult,
			"resource string %s validation on roles does not match", requiredPermission.Resource)

		// test tracing
		validationResult, _ = testClient.ValidatePermission(
			claims,
			requiredPermission,
			permissionResources,
			WithJaegerContext(context.Background()),
		)
		assert.Equal(t, testCase.expectedResult, validationResult,
			"resource string %s validation on roles does not match", requiredPermission.Resource)
	}
}

// nolint: funlen
func Test_DefaultClientValidatePermission_ActionBitMask(t *testing.T) {
	t.Parallel()

	type testTable struct {
		requiredAction int
		grantedAction  int
		expectedResult bool
	}

	testCases := []testTable{
		{
			requiredAction: ActionCreate | ActionRead | ActionUpdate,
			grantedAction:  ActionCreate | ActionRead | ActionUpdate,
			expectedResult: true,
		},
		{
			requiredAction: ActionCreate | ActionRead | ActionUpdate,
			grantedAction:  ActionCreate | ActionRead,
			expectedResult: false,
		},
		{
			requiredAction: ActionCreate | ActionRead | ActionUpdate,
			grantedAction:  ActionCreate | ActionRead | ActionUpdate | ActionDelete,
			expectedResult: true,
		},
		{
			requiredAction: ActionCreate | ActionRead | ActionUpdate,
			grantedAction:  0,
			expectedResult: false,
		},
		{
			requiredAction: ActionCreate,
			grantedAction:  ActionCreate | ActionRead | ActionUpdate | ActionDelete,
			expectedResult: true,
		},
		{
			requiredAction: ActionCreate | ActionRead | ActionUpdate | ActionDelete,
			grantedAction:  1,
			expectedResult: false,
		},
		{
			requiredAction: ActionUpdate | ActionDelete,
			grantedAction:  ActionRead | ActionDelete,
			expectedResult: false,
		},
	}

	for _, testCase := range testCases {
		grantedPermission := Permission{
			Resource: "RESOURCE",
			Action:   testCase.grantedAction,
		}
		requiredPermission := Permission{
			Resource: "RESOURCE",
			Action:   testCase.requiredAction,
		}

		userData := &tokenUserData{
			UserID:      "e9b1ed0c1a3d473cd970abc845b51d3a",
			Permissions: []Permission{grantedPermission},
		}
		claims := generateClaims(t, userData)

		permissionResources := make(map[string]string)
		permissionResources["{namespace}"] = userData.Namespace
		validationResult, _ := testClient.ValidatePermission(claims, requiredPermission, permissionResources)

		assert.Equal(t, testCase.expectedResult, validationResult, "action bitmask validation does not match")

		// test tracing
		validationResult, _ = testClient.ValidatePermission(
			claims,
			requiredPermission,
			permissionResources,
			WithJaegerContext(context.Background()),
		)
		assert.Equal(t, testCase.expectedResult, validationResult, "action bitmask validation does not match")
	}
}

func Test_HasRoleForStudioAndRelatedGames(t *testing.T) {
	t.Parallel()

	grantedPermission := Permission{
		Resource: "NAMESPACE:studio1-:CLIENT",
		Action:   1,
	}
	requiredPermission := Permission{
		Resource: "NAMESPACE:{namespace}:CLIENT",
		Action:   1,
	}

	userData := &tokenUserData{
		UserID:      "e9b1ed0c1a3d473cd970abc845b51d3a",
		Namespace:   "studio1-game1",
		Permissions: []Permission{grantedPermission},
	}
	claims := generateClaims(t, userData)

	permissionResources := make(map[string]string)
	permissionResources["{namespace}"] = userData.Namespace
	validationResult, _ := testClient.ValidatePermission(claims, requiredPermission, permissionResources)
	assert.True(t, validationResult, "should valid")

	userData = &tokenUserData{
		UserID:      "e9b1ed0c1a3d473cd970abc845b51d3a",
		Namespace:   "studio2-game1",
		Permissions: []Permission{grantedPermission},
	}
	claims = generateClaims(t, userData)

	permissionResources["{namespace}"] = userData.Namespace
	validationResult, _ = testClient.ValidatePermission(claims, requiredPermission, permissionResources)
	assert.False(t, validationResult, "should invalid")
}

func Test_HasRoleForStudioAndRelatedGameWithOldFormatNamespace(t *testing.T) {
	t.Parallel()

	mockClient := &DefaultClient{
		config:                &Config{ClientID: "a952b5c054de468bab9e0b4802057f11"},
		keys:                  make(map[string]*rsa.PublicKey),
		rolePermissionCache:   cache.New(cache.DefaultExpiration, cache.DefaultExpiration),
		revocationFilter:      bloom.New(100),
		revokedUsers:          make(map[string]time.Time),
		localValidationActive: true,
		clientInfoCache:       cache.New(cache.DefaultExpiration, cache.DefaultExpiration),
		namespaceContextCache: gcache.New(1000).LRU().
			LoaderExpireFunc(func(namespace interface{}) (interface{}, *time.Duration, error) {
				ttl := time.Hour
				return &NamespaceContext{Type: "Game", StudioNamespace: namespace.(string)}, &ttl, nil
			}).
			Build(),
	}

	grantedPermission := Permission{
		Resource: "NAMESPACE:studio1-:CLIENT",
		Action:   1,
	}
	requiredPermission := Permission{
		Resource: "NAMESPACE:{namespace}:CLIENT",
		Action:   1,
	}

	userData := &tokenUserData{
		UserID:      "e9b1ed0c1a3d473cd970abc845b51d3a",
		Namespace:   "studio1",
		Permissions: []Permission{grantedPermission},
	}
	claims := generateClaims(t, userData)

	permissionResources := make(map[string]string)
	permissionResources["{namespace}"] = userData.Namespace
	validationResult, _ := mockClient.ValidatePermission(claims, requiredPermission, permissionResources)
	assert.True(t, validationResult, "should valid")

	userData = &tokenUserData{
		UserID:      "e9b1ed0c1a3d473cd970abc845b51d3a",
		Namespace:   "studio",
		Permissions: []Permission{grantedPermission},
	}
	claims = generateClaims(t, userData)

	permissionResources["{namespace}"] = userData.Namespace
	validationResult, _ = mockClient.ValidatePermission(claims, requiredPermission, permissionResources)
	assert.False(t, validationResult, "should invalid")
}

func Test_DefaultClientValidateRoleID(t *testing.T) {
	t.Parallel()

	userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a", Roles: []string{defaultUserRole}}
	claims := generateClaims(t, userData)

	validationResult, _ := testClient.ValidateRole(defaultUserRole, claims)

	assert.True(t, validationResult, "resource roles id validation does not match")

	// test tracing
	validationResult, _ = testClient.ValidateRole(defaultUserRole, claims, WithJaegerContext(context.Background()))
	assert.True(t, validationResult, "resource roles id validation does not match")
}

func Test_DefaultClientValidateRoleID_NotExist(t *testing.T) {
	t.Parallel()

	userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a", Roles: []string{defaultUserRole}}
	claims := generateClaims(t, userData)

	validationResult, _ := testClient.ValidateRole("non-exist-required-role-id", claims)

	assert.False(t, validationResult, "resource roles id validation does not match")

	// test tracing
	validationResult, _ = testClient.ValidateRole(
		"non-exist-required-role-id",
		claims,
		WithJaegerContext(context.Background()),
	)
	assert.False(t, validationResult, "resource roles id validation does not match")
}

func Test_DefaultClientValidateAccessToken(t *testing.T) {
	t.Parallel()

	userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a", Namespace: "foo"}
	claims := generateClaims(t, userData)

	accessToken, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		panic(err)
	}

	validationResult, _ := testClient.ValidateAccessToken(accessToken)

	assert.True(t, validationResult, "valid direct verification should be granted")

	// test tracing
	validationResult, _ = testClient.ValidateAccessToken(accessToken, WithJaegerContext(context.Background()))
	assert.True(t, validationResult, "valid direct verification should be granted")
}

func Test_DefaultClientValidateAccessToken_InvalidToken(t *testing.T) {
	t.Parallel()

	validationResult, err := testClient.ValidateAccessToken(invalid)
	if err != nil {
		t.Fatalf("unable to validate : %v", err)
	}

	assert.False(t, validationResult, "invalid direct verification should not be granted")

	// test tracing
	validationResult, err = testClient.ValidateAccessToken(invalid, WithJaegerContext(context.Background()))
	if err != nil {
		t.Fatalf("unable to validate : %v", err)
	}

	assert.False(t, validationResult, "invalid direct verification should not be granted")
}

func Test_DefaultClientValidateAndParseClaims_RevokedUser(t *testing.T) {
	t.Parallel()

	userData := &tokenUserData{
		UserID:       "e71d22e2b270449c90d4c15b89c3f994",
		Namespace:    "foo",
		Permissions:  []Permission{{Resource: "RESOURCE", Action: ActionCreate | ActionRead | ActionUpdate | ActionDelete}},
		Roles:        []string{"roleID"},
		JusticeFlags: 7,
	}
	claims := generateClaims(t, userData)

	accessToken, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		panic(err)
	}

	testClient.setRevokedUserSafe("e71d22e2b270449c90d4c15b89c3f994", time.Now().UTC())

	claims, err = testClient.ValidateAndParseClaims(accessToken)

	assert.NotNil(t, err, "revoked user validation should not be granted on permission validation")
	assert.Nil(t, claims, "claims should be nil")
	assert.Equal(t, errUserRevoked.Error(), errors.Cause(err).Error(), "error message didn't match")

	// test tracing
	claims, err = testClient.ValidateAndParseClaims(accessToken, WithJaegerContext(context.Background()))
	assert.NotNil(t, err, "revoked user validation should not be granted on permission validation")
	assert.Nil(t, claims, "claims should be nil")
	assert.Equal(t, errUserRevoked.Error(), errors.Cause(err).Error(), "error message didn't match")
}

func Test_DefaultClientValidateAndParseClaims_RevokedToken(t *testing.T) {
	t.Parallel()

	userData := &tokenUserData{
		UserID:       "257abbea27b24247daae0702c8a200a1",
		Namespace:    "foo",
		Permissions:  []Permission{{Resource: "RESOURCE", Action: ActionCreate | ActionRead | ActionUpdate | ActionDelete}},
		Roles:        []string{"roleID"},
		JusticeFlags: 7,
	}
	claims := generateClaims(t, userData)

	accessToken, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		panic(err)
	}

	testClient.putRevocationFilterSafe(bytes.NewBufferString(accessToken).Bytes())

	claims, err = testClient.ValidateAndParseClaims(accessToken)

	assert.NotNil(t, err, "revoked token validation should not be granted on role validation")
	assert.Nil(t, claims, "claims should be nil")
	assert.Equal(t, errTokenRevoked.Error(), errors.Cause(err).Error(), "error message didn't match")

	// test jaeger
	claims, err = testClient.ValidateAndParseClaims(accessToken, WithJaegerContext(context.Background()))
	assert.NotNil(t, err, "revoked token validation should not be granted on role validation")
	assert.Nil(t, claims, "claims should be nil")
	assert.Equal(t, errTokenRevoked.Error(), errors.Cause(err).Error(), "error message didn't match")
}

func Test_DefaultClientHasBan(t *testing.T) {
	t.Parallel()

	userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a", Roles: []string{defaultUserRole}}
	claims := generateClaims(t, userData)
	claims.Bans = append(claims.Bans, JWTBan{Ban: "TEST_BAN", EndDate: time.Now().Add(time.Hour), Enabled: true, TargetedNamespace: "gameNamespace"})

	assert.True(t, testClient.HasBan(claims, "TEST_BAN"), "ban not found")

	// test tracing
	assert.True(t, testClient.HasBan(
		claims,
		"TEST_BAN",
		WithJaegerContext(context.Background()),
	), "ban not found")
}

// nolint: dupl
func Test_ValidateAudience(t *testing.T) {
	t.Parallel()

	userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a", Roles: []string{defaultUserRole}}
	claims := generateClaims(t, userData)
	claims.Audience = append(claims.Audience, "http://example.net")

	httpRequestTriggerCount := 0

	mockHTTPClient := &httpClientMock{
		doMock: func(req *http.Request) (*http.Response, error) {
			httpRequestTriggerCount++

			r := ioutil.NopCloser(strings.NewReader(`
{
   "clientID": "5a2cf6407d6349c7a75264c2c1d04a10",
   "clientName": "test client",
   "namespace": "accelbyte",
   "redirectUri": "http://127.0.0.1",
   "oauthClientType": "Confidential",
   "audiences": null,
   "baseUri": "http://example.net",
   "createdAt": "2019-07-27T07:39:31.541500915Z",
   "modifiedAt": "0001-01-01T00:00:00Z",
   "scopes": null
}
`))
			return &http.Response{
				Status:     http.StatusText(http.StatusOK),
				StatusCode: http.StatusOK,
				Body:       r,
				Header:     http.Header{},
			}, nil
		},
	}

	mockClient := &DefaultClient{
		config:                &Config{ClientID: "a952b5c054de468bab9e0b4802057f11"},
		keys:                  make(map[string]*rsa.PublicKey),
		rolePermissionCache:   cache.New(cache.DefaultExpiration, cache.DefaultExpiration),
		revocationFilter:      bloom.New(100),
		revokedUsers:          make(map[string]time.Time),
		localValidationActive: true,
		clientInfoCache:       cache.New(cache.DefaultExpiration, cache.DefaultExpiration),
		httpClient:            mockHTTPClient,
	}

	// 1st test
	err := mockClient.ValidateAudience(claims)
	assert.Nil(t, err)
	assert.Equal(t, 1, httpRequestTriggerCount)

	// 2nd test
	// in this run, the Client is got from cache
	err = mockClient.ValidateAudience(claims)
	assert.Nil(t, err)
	assert.Equal(t, 1, httpRequestTriggerCount) // http request should only called once
}

// nolint: dupl
func Test_ValidateAudience_TokenIsNotIntendedForTheClient(t *testing.T) {
	t.Parallel()

	userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a", Roles: []string{defaultUserRole}}
	claims := generateClaims(t, userData)
	claims.Audience = append(claims.Audience, "http://testexample.net")

	mockHTTPClient := &httpClientMock{
		doMock: func(req *http.Request) (*http.Response, error) {
			r := ioutil.NopCloser(strings.NewReader(`
{
   "clientID": "5a2cf6407d6349c7a75264c2c1d04a10",
   "clientName": "test client",
   "namespace": "accelbyte",
   "redirectUri": "http://127.0.0.1",
   "oauthClientType": "Confidential",
   "audiences": null,
   "baseUri": "http://example.net",
   "createdAt": "2019-07-27T07:39:31.541500915Z",
   "modifiedAt": "0001-01-01T00:00:00Z",
   "scopes": null
}
`))
			return &http.Response{
				Status:     http.StatusText(http.StatusOK),
				StatusCode: http.StatusOK,
				Body:       r,
				Header:     http.Header{},
			}, nil
		},
	}

	mockClient := &DefaultClient{
		config:                &Config{ClientID: "a952b5c054de468bab9e0b4802057f11"},
		keys:                  make(map[string]*rsa.PublicKey),
		rolePermissionCache:   cache.New(cache.DefaultExpiration, cache.DefaultExpiration),
		revocationFilter:      bloom.New(100),
		revokedUsers:          make(map[string]time.Time),
		localValidationActive: true,
		clientInfoCache:       cache.New(cache.DefaultExpiration, cache.DefaultExpiration),
		httpClient:            mockHTTPClient,
	}

	err := mockClient.ValidateAudience(claims)

	assert.NotNil(t, err)
}

// nolint: dupl
func Test_ValidateAudience_ClientNotFound(t *testing.T) {
	t.Parallel()

	userData := &tokenUserData{
		UserID:    "e9b1ed0c1a3d473cd970abc845b51d3a",
		Roles:     []string{defaultUserRole},
		Namespace: "accelbyte",
	}
	claims := generateClaims(t, userData)
	claims.Audience = append(claims.Audience, "http://example.net")

	mockHTTPClient := &httpClientMock{
		doMock: func(req *http.Request) (*http.Response, error) {
			r := ioutil.NopCloser(strings.NewReader(`
{
	"errorCode": "106422",
	"errorMessage:"client with id a952b5c054de468bab9e0b4802057f11 in namespace accelbyte was not found"
}
`))
			return &http.Response{
				Status:     http.StatusText(http.StatusOK),
				StatusCode: http.StatusOK,
				Body:       r,
				Header:     http.Header{},
			}, nil
		},
	}

	mockClient := &DefaultClient{
		config:                &Config{ClientID: "a952b5c054de468bab9e0b4802057f11"},
		keys:                  make(map[string]*rsa.PublicKey),
		rolePermissionCache:   cache.New(cache.DefaultExpiration, cache.DefaultExpiration),
		revocationFilter:      bloom.New(100),
		revokedUsers:          make(map[string]time.Time),
		localValidationActive: true,
		clientInfoCache:       cache.New(cache.DefaultExpiration, cache.DefaultExpiration),
		httpClient:            mockHTTPClient,
	}

	err := mockClient.ValidateAudience(claims)

	assert.NotNil(t, err)
}

// nolint: dupl
func Test_ValidateAudience_NoAudFieldInTheToken(t *testing.T) {
	t.Parallel()

	userData := &tokenUserData{
		UserID:    "e9b1ed0c1a3d473cd970abc845b51d3a",
		Roles:     []string{defaultUserRole},
		Namespace: "accelbyte",
	}
	claims := generateClaims(t, userData)
	mockHTTPClient := &httpClientMock{
		doMock: func(req *http.Request) (*http.Response, error) {
			r := ioutil.NopCloser(strings.NewReader(`
{
   "clientID": "5a2cf6407d6349c7a75264c2c1d04a10",
   "clientName": "test client",
   "namespace": "accelbyte",
   "redirectUri": "http://127.0.0.1",
   "oauthClientType": "Confidential",
   "audiences": null,
   "baseUri": "http://example.net",
   "createdAt": "2019-07-27T07:39:31.541500915Z",
   "modifiedAt": "0001-01-01T00:00:00Z",
   "scopes": null
}
`))
			return &http.Response{
				Status:     http.StatusText(http.StatusOK),
				StatusCode: http.StatusOK,
				Body:       r,
				Header:     http.Header{},
			}, nil
		},
	}

	mockClient := &DefaultClient{
		config:                &Config{ClientID: "a952b5c054de468bab9e0b4802057f11"},
		keys:                  make(map[string]*rsa.PublicKey),
		rolePermissionCache:   cache.New(cache.DefaultExpiration, cache.DefaultExpiration),
		revocationFilter:      bloom.New(100),
		revokedUsers:          make(map[string]time.Time),
		localValidationActive: true,
		clientInfoCache:       cache.New(cache.DefaultExpiration, cache.DefaultExpiration),
		httpClient:            mockHTTPClient,
	}

	err := mockClient.ValidateAudience(claims)

	assert.Nil(t, err)
}

// nolint: dupl
// To prevent accidentally passing an empty claim.
func Test_ValidateAudience_ClaimsIsNil(t *testing.T) {
	t.Parallel()

	mockClient := &DefaultClient{
		config:                &Config{ClientID: "a952b5c054de468bab9e0b4802057f11"},
		keys:                  make(map[string]*rsa.PublicKey),
		rolePermissionCache:   cache.New(cache.DefaultExpiration, cache.DefaultExpiration),
		revocationFilter:      bloom.New(100),
		revokedUsers:          make(map[string]time.Time),
		localValidationActive: true,
		clientInfoCache:       cache.New(cache.DefaultExpiration, cache.DefaultExpiration),
		httpClient:            &http.Client{},
	}

	err := mockClient.ValidateAudience(nil)

	assert.NotNil(t, err)
}

func Test_ValidateScope(t *testing.T) {
	t.Parallel()

	userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a", Roles: []string{defaultUserRole}}
	claims := generateClaims(t, userData)
	claims.Scope = "mockscope otherscope"

	err := testClient.ValidateScope(claims, "mockscope")

	assert.NoError(t, err, "validate scope should be successful")

	// test tracing
	err = testClient.ValidateScope(claims, "mockscope", WithJaegerContext(context.Background()))
	assert.NoError(t, err, "validate scope should be successful")
}

func Test_GetRolePermissions(t *testing.T) {
	t.Parallel()

	type testTable struct {
		roleID         string
		expectedResult []Permission
	}

	testCases := []testTable{
		{
			roleID: defaultUserRole,
			expectedResult: []Permission{
				{
					Resource: "NAMESPACE:{namespace}:USER:{userId}:ORDER",
					Action:   ActionCreate | ActionRead | ActionUpdate,
				},
			},
		},
		{
			roleID: mockUserRole,
			expectedResult: []Permission{
				{
					Resource: "NAMESPACE:*:USER:{userId}:FRIENDS",
					Action:   ActionCreate | ActionRead | ActionUpdate,
				},
				{
					Resource: "NAMESPACE:*:USER:*:SLOTDATA",
					Action:   ActionCreate | ActionRead | ActionUpdate,
				},
			},
		},
	}

	for _, testCase := range testCases {
		getRoleResult, err := testClient.GetRolePermissions(testCase.roleID)

		assert.NoError(t, err)
		assert.Equal(t, testCase.expectedResult, getRoleResult)
	}
}

func Test_GetClientInformation(t *testing.T) {
	t.Parallel()

	httpRequestTriggerCount := 0

	// mock http request
	clientID := generateUUID()
	mockHTTPClient := &httpClientMock{
		doMock: func(req *http.Request) (*http.Response, error) {
			httpRequestTriggerCount++

			r := ioutil.NopCloser(strings.NewReader(`
{
   "clientID": "` + clientID + `",
   "clientName": "test client",
   "namespace": "accelbyte",
   "redirectUri": "http://127.0.0.1",
   "oauthClientType": "Confidential",
   "audiences": null,
   "baseUri": "http://example.net",
   "createdAt": "2019-07-27T07:39:31.541500915Z",
   "modifiedAt": "0001-01-01T00:00:00Z",
   "scopes": null
}
`))
			return &http.Response{
				Status:     http.StatusText(http.StatusOK),
				StatusCode: http.StatusOK,
				Body:       r,
				Header:     http.Header{},
			}, nil
		},
	}
	mockClient := &DefaultClient{
		config:          &Config{ClientID: generateUUID()},
		clientInfoCache: cache.New(cache.DefaultExpiration, cache.DefaultExpiration),
		httpClient:      mockHTTPClient,
	}

	expectedClientInfo := &ClientInformation{
		ClientName:  "test client",
		Namespace:   "accelbyte",
		RedirectURI: "http://127.0.0.1",
		BaseURI:     "http://example.net",
	}

	// 1st test
	clientInfo1, err := mockClient.GetClientInformation("accelbyte", clientID)

	assert.NoError(t, err)
	assert.Equal(t, expectedClientInfo, clientInfo1)
	assert.Equal(t, 1, httpRequestTriggerCount)

	// 2nd test
	// in this run, the Client is got from cache
	clientInfo2, err := mockClient.GetClientInformation("accelbyte", clientID)

	assert.NoError(t, err)
	assert.Equal(t, expectedClientInfo, clientInfo2)
	assert.Equal(t, 1, httpRequestTriggerCount) // http request should only called once
}

func Test_GetClientInformation_ClientNotFound(t *testing.T) {
	t.Parallel()

	// mock http request
	clientID := generateUUID()
	mockHTTPClient := &httpClientMock{
		doMock: func(req *http.Request) (*http.Response, error) {
			r := ioutil.NopCloser(strings.NewReader(`
{
  "errorCode": 10365,
  "errorMessage": "client with id ` + clientID + ` in namespace accelbyte was not found"
}
`))
			return &http.Response{
				Status:     http.StatusText(http.StatusNotFound),
				StatusCode: http.StatusNotFound,
				Body:       r,
				Header:     http.Header{},
			}, nil
		},
	}
	mockClient := &DefaultClient{
		config:          &Config{ClientID: generateUUID()},
		clientInfoCache: cache.New(cache.DefaultExpiration, cache.DefaultExpiration),
		httpClient:      mockHTTPClient,
	}

	// test
	clientInfo, err := mockClient.GetClientInformation("accelbyte", clientID)

	assert.Error(t, err)
	assert.Nil(t, clientInfo)
}

func Test_GetClientInformation_UnauthorizedThenPerformRefreshClientToken(t *testing.T) {
	t.Parallel()

	// mock http request
	refreshTokenFlag := false
	clientID := generateUUID()

	mockHTTPClient := &httpClientMock{
		doMock: func(req *http.Request) (*http.Response, error) {
			isRefreshTokenRequest := strings.Contains(req.URL.Path, "/oauth/token")
			if isRefreshTokenRequest {
				refreshTokenFlag = true

				r := ioutil.NopCloser(strings.NewReader(`
{
    "access_token": "dummy_valid_token",
    "bans": null,
    "display_name": "",
    "expires_in": 3600,
    "namespace": "accelbyte",
    "permissions": [],
    "token_type": "Bearer"
}
`))
				return &http.Response{
					Status:     http.StatusText(http.StatusOK),
					StatusCode: http.StatusOK,
					Body:       r,
					Header:     http.Header{},
				}, nil
			}

			// assume the client token is invalid, so need to refresh token first
			if !refreshTokenFlag {
				r := ioutil.NopCloser(strings.NewReader(`
{
  "errorCode": 20001,
  "errorMessage": "unauthorized access"
}
`))
				return &http.Response{
					Status:     http.StatusText(http.StatusUnauthorized),
					StatusCode: http.StatusUnauthorized,
					Body:       r,
					Header:     http.Header{},
				}, nil
			}

			r := ioutil.NopCloser(strings.NewReader(`
{
   "clientID": "` + clientID + `",
   "clientName": "test client",
   "namespace": "accelbyte",
   "redirectUri": "http://127.0.0.1",
   "oauthClientType": "Confidential",
   "audiences": null,
   "baseUri": "http://example.net",
   "createdAt": "2019-07-27T07:39:31.541500915Z",
   "modifiedAt": "0001-01-01T00:00:00Z",
   "scopes": null
}
`))
			return &http.Response{
				Status:     http.StatusText(http.StatusOK),
				StatusCode: http.StatusOK,
				Body:       r,
				Header:     http.Header{},
			}, nil
		},
	}
	mockClient := &DefaultClient{
		config:          &Config{ClientID: generateUUID()},
		clientInfoCache: cache.New(cache.DefaultExpiration, cache.DefaultExpiration),
		httpClient:      mockHTTPClient,
	}

	expectedClientInfo := &ClientInformation{
		ClientName:  "test client",
		Namespace:   "accelbyte",
		RedirectURI: "http://127.0.0.1",
		BaseURI:     "http://example.net",
	}

	// test
	clientInfo, err := mockClient.GetClientInformation("accelbyte", clientID)

	assert.NoError(t, err)
	assert.Equal(t, expectedClientInfo, clientInfo)
}

func generateClaims(t *testing.T, userData *tokenUserData) *JWTClaims {
	t.Helper()

	tNow := time.Now().UTC()

	return &JWTClaims{
		DisplayName:    userData.DisplayName,
		Namespace:      userData.Namespace,
		Roles:          userData.Roles,
		NamespaceRoles: userData.NamespaceRoles,
		Permissions:    userData.Permissions,
		JusticeFlags:   userData.JusticeFlags,
		ClientID:       userData.ClientID,
		Claims: jwt.Claims{
			Subject:  userData.UserID,
			IssuedAt: jwt.NewNumericDate(tNow),
			Expiry:   jwt.NewNumericDate(tNow.Add(15 * time.Minute)),
		},
	}
}

func generateUUID() string {
	id, _ := uuid.NewRandom()
	return strings.ReplaceAll(id.String(), "-", "")
}

type httpClientMock struct {
	http.Client
	doMock func(req *http.Request) (*http.Response, error)
}

func (c *httpClientMock) Do(req *http.Request) (*http.Response, error) {
	return c.doMock(req)
}
