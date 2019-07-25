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

// Client provides interface for IAM Client
// It can be used as mocking point
// usage example:
//
// func main() {
// 	config := Config{
// 		BaseURL:      "/iam",
// 		ClientID:     "clientID",
// 		ClientSecret: "clientSecret",
// 	}
//
// 	iamClient, _ := client.NewClient(&config)
// 	myFunction(iamClient)
// }
//
// func myFunction(iamClient *client.IAMClientAPI) {
// 	iamClient.ValidateTokenPermission(models.Permission{
// 		Resource: "NAMESPACE:{namespace}:EXAMPLE", Action: 4
// 		}, "accessToken")
// }
//
type Client interface {
	// ClientTokenGrant starts client token grant to get client bearer token for role caching
	ClientTokenGrant() error

	// ClientToken returns client access token
	ClientToken() string

	// StartLocalValidation starts goroutines to refresh JWK and revocation list periodically
	// this enables local token validation
	StartLocalValidation() error

	// ValidateAccessToken validates access token by calling IAM service
	ValidateAccessToken(accessToken string) (bool, error)

	// ValidateAndParseClaims validates access token locally and returns the JWT claims contained in the token
	ValidateAndParseClaims(accessToken string) (*JWTClaims, error)

	// ValidatePermission validates if an access token has right for a specific permission
	// requiredPermission: permission to access resource, example:
	// 		{Resource: "NAMESPACE:{namespace}:USER:{userId}", Action: 2}
	// permissionResources: resource string to replace the `{}` placeholder in
	// 		`requiredPermission`, example: p["{namespace}"] = "accelbyte"
	ValidatePermission(claims *JWTClaims, requiredPermission Permission,
		permissionResources map[string]string) (bool, error)

	// ValidateRole validates if an access token has a specific role
	ValidateRole(requiredRoleID string, claims *JWTClaims) (bool, error)

	// UserPhoneVerificationStatus gets user phone verification status on access token
	UserPhoneVerificationStatus(claims *JWTClaims) (bool, error)

	// UserEmailVerificationStatus gets user email verification status on access token
	UserEmailVerificationStatus(claims *JWTClaims) (bool, error)

	// UserAnonymousStatus gets user anonymous status on access token
	UserAnonymousStatus(claims *JWTClaims) (bool, error)

	// HasBan validates if certain ban exist
	HasBan(claims *JWTClaims, banType string) bool

	// HealthCheck lets caller know the health of the IAM client
	HealthCheck() bool

	// ValidateAudience validate audience of user access token
	ValidateAudience(claims *JWTClaims) error

	// ValidateScope validate scope of user access token
	ValidateScope(claims *JWTClaims, scope string) error
}
