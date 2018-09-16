/*
 * Copyright 2018 AccelByte Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package iam

import (
	"bytes"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/AccelByte/bloom"
	"github.com/dgrijalva/jwt-go"
	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
)

const (
	defaultUserRole   = "2251438839e948d783ec0e5281daf05b"
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
)

type tokenUserData struct {
	Namespace      string
	UserID         string `json:"UserId"`
	DisplayName    string
	PlatformID     string
	PlatformUserID string
	Roles          []string
	Permissions    []Permission
	JusticeFlags   int `json:"jflgs"`
}

var testClient Client
var privateKey *rsa.PrivateKey

func init() {
	privateKey, _ = jwt.ParseRSAPrivateKeyFromPEM([]byte(testJWTPrivateKey))
	testClient = &DefaultClient{
		keys:                  make(map[string]*rsa.PublicKey),
		rolePermissionCache:   cache.New(cache.DefaultExpiration, cache.DefaultExpiration),
		revocationFilter:      bloom.New(100),
		revokedUsers:          make(map[string]time.Time),
		localValidationActive: true,
	}
	testClient.(*DefaultClient).keys[keyID] = &rsa.PublicKey{
		E: privateKey.PublicKey.E,
		N: privateKey.PublicKey.N,
	}
	testClient.(*DefaultClient).rolePermissionCache.Set(defaultUserRole, []Permission{
		{Resource: "NAMESPACE:{namespace}:USER:{userId}:ORDER", Action: ActionCreate | ActionRead | ActionUpdate},
	}, cache.DefaultExpiration)
	testClient.(*DefaultClient).remoteTokenValidation =
		func(accessToken string) (bool, error) {
			if accessToken == invalid {
				return false, nil
			}
			return true, nil
		}
}

func TestClientUserEmailVerificationStatus(t *testing.T) {
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
	}
}

func TestClientUserPhoneVerificationStatus(t *testing.T) {
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
	}
}

func TestClientUserAnonymousStatus(t *testing.T) {
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

		assert.Equal(t, testCase.expectedValidationResult, validationResult, "anonymous verification validation does not match")
	}
}

func TestClientValidateAndParseClaims(t *testing.T) {
	grantedPermission := Permission{
		Resource: "NAMESPACE:foo:USER:888:PROFILE:birthday",
		Action:   ActionCreate | ActionRead | ActionUpdate | ActionDelete,
	}
	userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a",
		Permissions: []Permission{grantedPermission}}

	claims := generateClaims(t, userData)

	jwtToken := jwt.NewWithClaims(jwt.GetSigningMethod(jwt.SigningMethodRS256.Name), claims)
	jwtToken.Header["kid"] = keyID

	accessToken, _ := jwtToken.SignedString(privateKey)
	claims, errValidateAndParseClaims := testClient.ValidateAndParseClaims(accessToken)

	assert.Nil(t, errValidateAndParseClaims, "access token is invalid")
	assert.NotNil(t, claims, "claims should not nil")
}

func TestClientValidatePermissionResourceString(t *testing.T) {
	type testTable struct {
		requiredResource         string
		grantedResource          string
		expectedValidationResult bool
	}

	testCases := []testTable{
		{requiredResource: "NAMESPACE:foo:USER:888:PROFILE:birthday", grantedResource: "NAMESPACE:foo:USER:888:PROFILE:birthday", expectedValidationResult: true},
		{requiredResource: "NAMESPACE:foo:USER:888:PROFILE:*", grantedResource: "NAMESPACE:foo:USER:888:PROFILE:birthday", expectedValidationResult: false},
		{requiredResource: "NAMESPACE:foo:USER:888:PROFILE:birthday", grantedResource: "NAMESPACE:foo:USER:888:PROFILE:*", expectedValidationResult: true},
		{requiredResource: "NAMESPACE:foo:USER:888:PROFILE:birthday", grantedResource: "NAMESPACE:foo:USER:*", expectedValidationResult: true},
		{requiredResource: "NAMESPACE:foo:USER:888:PROFILE:birthday", grantedResource: "NAMESPACE:foo:USER", expectedValidationResult: false},
		{requiredResource: "NAMESPACE:foo:USER:888", grantedResource: "NAMESPACE:foo:USER:888:*:*", expectedValidationResult: true},
		{requiredResource: "NAMESPACE:foo:USER:888", grantedResource: "NAMESPACE:foo:USER:888:PROFILE:*", expectedValidationResult: false},
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

		userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a",
			Permissions: []Permission{grantedPermission}}
		claims := generateClaims(t, userData)

		var permissionResources map[string]string
		permissionResources = make(map[string]string)
		permissionResources["{namespace}"] = userData.Namespace
		validationResult, _ := testClient.ValidatePermission(claims, requiredPermission, permissionResources)

		assert.Equal(t, testCase.expectedValidationResult, validationResult, "resource string validation does not match")
	}
}

func TestClientValidatePermissionResourceStringOnRole(t *testing.T) {
	type testTable struct {
		requiredResource         string
		expectedValidationResult bool
	}

	testCases := []testTable{
		{requiredResource: "NAMESPACE:foo:USER:888:ORDER", expectedValidationResult: true},
		{requiredResource: "NAMESPACE:bar:USER:888:ORDER", expectedValidationResult: false},
		{requiredResource: "NAMESPACE:foo:USER:888:ORDER", expectedValidationResult: true},
		{requiredResource: "NAMESPACE:foo:USER:999:ORDER", expectedValidationResult: false},
	}

	for _, testCase := range testCases {
		requiredPermission := Permission{
			Resource: testCase.requiredResource,
			Action:   ActionCreate | ActionRead | ActionUpdate,
		}

		userData := &tokenUserData{UserID: "888", Namespace: "foo", Roles: []string{defaultUserRole}}
		claims := generateClaims(t, userData)

		var permissionResources map[string]string
		permissionResources = make(map[string]string)
		permissionResources["{namespace}"] = userData.Namespace
		validationResult, _ := testClient.ValidatePermission(claims, requiredPermission, permissionResources)

		assert.Equal(t, testCase.expectedValidationResult, validationResult, "resource string %s validation on roles does not match", requiredPermission.Resource)
	}
}

func TestClientValidatePermissionActionBitMask(t *testing.T) {
	type testTable struct {
		requiredAction           int
		grantedAction            int
		expectedValidationResult bool
	}

	testCases := []testTable{
		{requiredAction: ActionCreate | ActionRead | ActionUpdate, grantedAction: ActionCreate | ActionRead | ActionUpdate,
			expectedValidationResult: true},
		{requiredAction: ActionCreate | ActionRead | ActionUpdate, grantedAction: ActionCreate | ActionRead,
			expectedValidationResult: false},
		{requiredAction: ActionCreate | ActionRead | ActionUpdate, grantedAction: ActionCreate | ActionRead | ActionUpdate | ActionDelete,
			expectedValidationResult: true},
		{requiredAction: ActionCreate | ActionRead | ActionUpdate, grantedAction: 0,
			expectedValidationResult: false},
		{requiredAction: ActionCreate, grantedAction: ActionCreate | ActionRead | ActionUpdate | ActionDelete,
			expectedValidationResult: true},
		{requiredAction: ActionCreate | ActionRead | ActionUpdate | ActionDelete, grantedAction: 1,
			expectedValidationResult: false},
		{requiredAction: ActionUpdate | ActionDelete, grantedAction: ActionRead | ActionDelete,
			expectedValidationResult: false},
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

		userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a",
			Permissions: []Permission{grantedPermission}}
		claims := generateClaims(t, userData)

		var permissionResources map[string]string
		permissionResources = make(map[string]string)
		permissionResources["{namespace}"] = userData.Namespace
		validationResult, _ := testClient.ValidatePermission(claims, requiredPermission, permissionResources)

		assert.Equal(t, testCase.expectedValidationResult, validationResult, "action bitmask validation does not match")
	}
}

func TestClientValidateRoleIDExist(t *testing.T) {
	userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a", Roles: []string{defaultUserRole}}
	claims := generateClaims(t, userData)

	validationResult, _ := testClient.ValidateRole(defaultUserRole, claims)

	assert.True(t, validationResult, "resource roles id validation does not match")
}

func TestClientValidateRoleIDNotExist(t *testing.T) {
	userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a", Roles: []string{defaultUserRole}}
	claims := generateClaims(t, userData)

	validationResult, _ := testClient.ValidateRole("non-exist-required-role-id", claims)

	assert.False(t, validationResult, "resource roles id validation does not match")
}

func TestVerifyAccessTokenValidToken(t *testing.T) {
	userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a", Namespace: "foo"}
	claims := generateClaims(t, userData)

	jwtToken := jwt.NewWithClaims(jwt.GetSigningMethod(jwt.SigningMethodRS256.Name), claims)
	jwtToken.Header["kid"] = keyID
	accessToken, _ := jwtToken.SignedString(privateKey)

	validationResult, _ := testClient.ValidateAccessToken(accessToken)

	assert.True(t, validationResult, "valid direct verification should be granted")
}

func TestVerifyAccessTokenInvalidToken(t *testing.T) {
	validationResult, err := testClient.ValidateAccessToken(invalid)
	if err != nil {
		t.Fatalf("unable to validate : %v", err)
	}
	assert.False(t, validationResult, "invalid direct verification should not be granted")
}

func TestValidateRevokedUser(t *testing.T) {
	userData := &tokenUserData{UserID: "e71d22e2b270449c90d4c15b89c3f994",
		Namespace:    "foo",
		Permissions:  []Permission{{Resource: "RESOURCE", Action: ActionCreate | ActionRead | ActionUpdate | ActionDelete}},
		Roles:        []string{"roleID"},
		JusticeFlags: 7}
	claims := generateClaims(t, userData)

	jwtToken := jwt.NewWithClaims(jwt.GetSigningMethod(jwt.SigningMethodRS256.Name), claims)
	jwtToken.Header["kid"] = keyID
	accessToken, _ := jwtToken.SignedString(privateKey)

	testClient.(*DefaultClient).revokedUsers["e71d22e2b270449c90d4c15b89c3f994"] = time.Now().UTC()

	claims, err := testClient.ValidateAndParseClaims(accessToken)

	assert.NotNil(t, err, "revoked user validation should not be granted on permission validation")
	assert.Nil(t, claims, "claims should be nil")
	assert.Equal(t, err.Error(), "user has been revoked", "error message didn't match")

}

func TestValidateRevokedToken(t *testing.T) {
	userData := &tokenUserData{UserID: "257abbea27b24247daae0702c8a200a1",
		Namespace:    "foo",
		Permissions:  []Permission{{Resource: "RESOURCE", Action: ActionCreate | ActionRead | ActionUpdate | ActionDelete}},
		Roles:        []string{"roleID"},
		JusticeFlags: 7}
	claims := generateClaims(t, userData)

	jwtToken := jwt.NewWithClaims(jwt.GetSigningMethod(jwt.SigningMethodRS256.Name), claims)
	jwtToken.Header["kid"] = keyID
	accessToken, _ := jwtToken.SignedString(privateKey)

	testClient.(*DefaultClient).revocationFilter.Put(bytes.NewBufferString(accessToken).Bytes())

	claims, err := testClient.ValidateAndParseClaims(accessToken)

	assert.NotNil(t, err, "revoked token validation should not be granted on role validation")
	assert.Nil(t, claims, "claims should be nil")
	assert.Equal(t, err.Error(), "token has been revoked", "error message didn't match")
}

func TestTokenHasBan(t *testing.T) {
	userData := &tokenUserData{UserID: "e9b1ed0c1a3d473cd970abc845b51d3a", Roles: []string{defaultUserRole}}
	claims := generateClaims(t, userData)
	claims.Bans = append(claims.Bans, JWTBan{Ban: "TEST_BAN"})

	assert.True(t, testClient.HasBan(claims, "TEST_BAN"), "ban not found")
}

func generateClaims(t *testing.T, userData *tokenUserData) *JWTClaims {
	t.Helper()
	tNow := time.Now().UTC()
	return &JWTClaims{
		DisplayName:  userData.DisplayName,
		Namespace:    userData.Namespace,
		Roles:        userData.Roles,
		Permissions:  userData.Permissions,
		JusticeFlags: userData.JusticeFlags,
		StandardClaims: jwt.StandardClaims{
			Subject:   userData.UserID,
			IssuedAt:  tNow.Unix(),
			ExpiresAt: tNow.Add(15 * time.Minute).Unix(),
		},
	}
}
