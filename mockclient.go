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
	"errors"

	"github.com/dgrijalva/jwt-go"
)

// Mock IAM constants
const (
	MockUnauthorized = "unauthorized"
	MockForbidden    = "forbidden"
)

// MockClient define mock oauth client config
type MockClient struct {
	Healthy bool // set this to false to mock unhealthy IAM service
}

// NewMockClient creates new mock IAM DefaultClient
func NewMockClient() Client {
	return &MockClient{
		Healthy: true,
	}
}

// ClientTokenGrant starts client token grant to get client bearer token for role caching
func (client *MockClient) ClientTokenGrant() error {
	return nil
}

// ClientToken returns client access token
func (client *MockClient) ClientToken() string {
	return "mock_token"
}

// StartLocalValidation starts goroutines to refresh JWK and revocation list periodically
// this enables local token validation
func (client *MockClient) StartLocalValidation() error {
	return nil
}

// ValidateAccessToken validates access token by calling IAM service
func (client *MockClient) ValidateAccessToken(accessToken string) (bool, error) {
	switch accessToken {
	case MockUnauthorized, MockForbidden:
		return false, nil
	}
	return true, nil
}

// ValidateAndParseClaims validates access token locally and returns the JWT claims contained in the token
func (client *MockClient) ValidateAndParseClaims(accessToken string) (*JWTClaims, error) {
	claims := &JWTClaims{
		StandardClaims: jwt.StandardClaims{Subject: accessToken},
		Namespace:      "MOCK",
	}

	switch accessToken {
	case MockUnauthorized:
		return nil, errors.New("invalid access token")
	case MockForbidden:
		claims.Roles = append(claims.Roles, MockForbidden)
		claims.Permissions = append(claims.Permissions,
			Permission{Resource: MockForbidden, Action: 0})
		return claims, nil
	}

	claims.Roles = append(claims.Roles, MockForbidden)
	claims.Permissions = append(claims.Permissions,
		Permission{Resource: "MOCK", Action: ActionCreate | ActionRead | ActionUpdate | ActionDelete})

	return claims, nil
}

// ValidatePermission validates if an access token has right for a specific permission
// requiredPermission: permission to access resource, example: {Resource: "NAMESPACE:{namespace}:USER:{userId}", Action: 2}
// permissionResources: resource string to replace the `{}` placeholder in `requiredPermission`, example: p["{namespace}"] = "accelbyte"
func (client *MockClient) ValidatePermission(claims *JWTClaims, requiredPermission Permission, permissionResources map[string]string) (bool, error) {
	if claims.Permissions[0].Resource == MockForbidden {
		return false, nil
	}
	return true, nil
}

// ValidateRole validates if an access token has a specific role
func (client *MockClient) ValidateRole(requiredRoleID string, claims *JWTClaims) (bool, error) {
	if claims.Roles[0] == MockForbidden {
		return false, nil
	}
	return true, nil
}

// UserPhoneVerificationStatus gets user phone verification status on access token
func (client *MockClient) UserPhoneVerificationStatus(claims *JWTClaims) (bool, error) {
	phoneVerified := claims.JusticeFlags&UserStatusPhoneVerified == UserStatusPhoneVerified
	return phoneVerified, nil
}

// UserEmailVerificationStatus gets user email verification status on access token
func (client *MockClient) UserEmailVerificationStatus(claims *JWTClaims) (bool, error) {
	emailVerified := claims.JusticeFlags&UserStatusEmailVerified == UserStatusEmailVerified
	return emailVerified, nil
}

// UserAnonymousStatus gets user anonymous status on access token
func (client *MockClient) UserAnonymousStatus(claims *JWTClaims) (bool, error) {
	anonymousStatus := claims.JusticeFlags&UserStatusAnonymous == UserStatusAnonymous
	return anonymousStatus, nil
}

// HasBan validates if certain ban exist
func (client *MockClient) HasBan(claims *JWTClaims, banType string) bool {
	for _, ban := range claims.Bans {
		if ban.Ban == banType {
			return true
		}
	}
	return false
}

// HealthCheck lets caller know the health of the IAM client
func (client *MockClient) HealthCheck() bool {
	return client.Healthy
}
