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
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/AccelByte/bloom"
	"github.com/cenkalti/backoff"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
)

// JFlags constants
const (
	UserStatusEmailVerified = 1
	UserStatusPhoneVerified = 1 << 1
	UserStatusAnonymous     = 1 << 2
)

const (
	jwksPath              = "/oauth/jwks"
	grantPath             = "/oauth/token"
	revocationListPath    = "/oauth/revocationlist"
	verifyPath            = "/oauth/verify"
	getRolePath           = "/roles"
	clientInformationPath = "/v3/admin/namespaces/%s/clients/%s"

	defaultTokenRefreshRate              = 0.8
	maxBackOffTime                       = 65 * time.Second
	defaultRoleCacheTime                 = 60 * time.Second
	defaultJWKSRefreshInterval           = 60 * time.Second
	defaultRevocationListRefreshInterval = 60 * time.Second

	baseURIKey             = "baseURI"
	baseURICacheExpiration = 1 * time.Minute
	scopeSeparator         = " "
)

// Config contains IAM configurations
type Config struct {
	BaseURL                       string
	ClientID                      string
	ClientSecret                  string
	RolesCacheExpirationTime      time.Duration // default: 60s
	JWKSRefreshInterval           time.Duration // default: 60s
	RevocationListRefreshInterval time.Duration // default: 60s
	Debug                         bool
}

// DefaultClient define oauth client config
type DefaultClient struct {
	keys                       map[string]*rsa.PublicKey
	clientAccessToken          string
	config                     *Config
	rolePermissionCache        *cache.Cache
	revocationFilter           *bloom.Filter
	revokedUsers               map[string]time.Time
	tokenRefreshActive         bool
	localValidationActive      bool
	jwksRefreshError           error
	revocationListRefreshError error
	tokenRefreshError          error
	remoteTokenValidation      func(accessToken string) (bool, error)
	baseURICache               *cache.Cache
	// for easily mocking the HTTP call
	httpClient HTTPClient
}

// HTTPClient is an interface for http.Client.
// The purpose for having this so we could easily mock the HTTP call.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

var debug bool

// NewDefaultClient creates new IAM DefaultClient
func NewDefaultClient(config *Config) Client {
	if config.RolesCacheExpirationTime <= 0 {
		config.RolesCacheExpirationTime = defaultRoleCacheTime
	}
	if config.JWKSRefreshInterval <= 0 {
		config.JWKSRefreshInterval = defaultJWKSRefreshInterval
	}
	if config.RevocationListRefreshInterval <= 0 {
		config.RevocationListRefreshInterval = defaultRevocationListRefreshInterval
	}

	client := &DefaultClient{
		config: config,
		rolePermissionCache: cache.New(
			config.RolesCacheExpirationTime,
			2*config.RolesCacheExpirationTime,
		),
		baseURICache: cache.New(
			baseURICacheExpiration,
			baseURICacheExpiration,
		),
		httpClient: &http.Client{},
	}
	client.remoteTokenValidation = client.validateAccessToken

	debug = config.Debug
	log("NewDefaultClient: debug enabled")

	return client
}

// ClientTokenGrant starts client token grant to get client bearer token for role caching
func (client *DefaultClient) ClientTokenGrant() error {
	refreshInterval, err := client.clientTokenGrant()
	if err != nil {
		return logAndReturnErr(
			errors.WithMessage(err,
				"ClientTokenGrant: unable to do token grant"))
	}

	go func() {
		client.tokenRefreshActive = true
		time.Sleep(refreshInterval)
		client.refreshAccessToken()
	}()

	log("ClientTokenGrant: token grant success")
	return nil
}

// ClientToken returns client access token
func (client *DefaultClient) ClientToken() string {
	return client.clientAccessToken
}

// StartLocalValidation starts goroutines to refresh JWK and revocation list periodically
// this enables local token validation
func (client *DefaultClient) StartLocalValidation() error {
	err := client.getJWKS()
	if err != nil {
		return logAndReturnErr(
			errors.WithMessage(err,
				"StartLocalValidation: unable to get JWKS"))
	}

	err = client.getRevocationList()
	if err != nil {
		return logAndReturnErr(
			errors.WithMessage(err,
				"StartLocalValidation: unable to get revocation list"))
	}

	go client.refreshJWKS()
	go client.refreshRevocationList()

	client.localValidationActive = true

	log("StartLocalValidation: local validation activated")
	return nil
}

// ValidateAccessToken validates access token by calling IAM service
func (client *DefaultClient) ValidateAccessToken(accessToken string) (bool, error) {
	var isValid bool
	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime

	err := backoff.
		Retry(
			func() error {
				var e error

				isValid, e = client.remoteTokenValidation(accessToken)
				if e != nil {
					if errors.Cause(e) == errUnauthorized {
						client.refreshAccessToken()
						return e
					}

					return backoff.Permanent(e)
				}

				return nil
			},
			b,
		)

	err = logAndReturnErr(
		errors.WithMessage(err,
			"ValidateAccessToken: unable to validate token"))

	if isValid {
		log("ValidateAccessToken: token is valid")
	}

	return isValid, err
}

// ValidateAndParseClaims validates access token locally and returns the JWT claims contained in the token
func (client *DefaultClient) ValidateAndParseClaims(accessToken string) (*JWTClaims, error) {
	if !client.localValidationActive {
		err := logAndReturnErr(
			errors.Wrap(errNoLocalValidation,
				"ValidateAndParseClaims: unable to validate claims"))
		return nil, err
	}

	claims, err := client.validateJWT(accessToken)
	if err != nil {
		err = logAndReturnErr(
			errors.WithMessage(err,
				"ValidateAndParseClaims: unable to validate JWT"))
		return nil, err
	}

	if client.userRevoked(claims.Subject, int64(claims.IssuedAt)) {
		err = logAndReturnErr(
			errors.Wrap(errUserRevoked,
				"ValidateAndParseClaims: user (owner) of JWT is revoked"))
		return nil, err
	}

	if client.tokenRevoked(accessToken) {
		err = logAndReturnErr(
			errors.Wrap(errTokenRevoked,
				"ValidateAndParseClaims: token is revoked"))
		return nil, err
	}

	log("ValidateAndParseClaims: JWT validated")
	return claims, nil
}

// ValidatePermission validates if an access token has right for a specific permission
// requiredPermission: permission to access resource, example:
// 		{Resource: "NAMESPACE:{namespace}:USER:{userId}", Action: 2}
// permissionResources: resource string to replace the `{}` placeholder in
// 		`requiredPermission`, example: p["{namespace}"] = "accelbyte"
func (client *DefaultClient) ValidatePermission(claims *JWTClaims,
	requiredPermission Permission, permissionResources map[string]string) (bool, error) {

	if claims == nil {
		log("ValidatePermission: claim is nil")
		return false, nil
	}

	for placeholder, value := range permissionResources {
		requiredPermission.Resource = strings.Replace(requiredPermission.Resource, placeholder, value, 1)
	}

	if client.permissionAllowed(claims.Permissions, requiredPermission) {
		log("ValidatePermission: permission allowed to access resource")
		return true, nil
	}

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime

	for _, roleID := range claims.Roles {
		grantedRolePermissions := make([]Permission, 0)
		err := backoff.
			Retry(
				func() error {
					var e error

					grantedRolePermissions, e = client.getRolePermission(roleID)
					if e != nil {

						switch errors.Cause(e) {
						case errRoleNotFound:
							return nil
						case errUnauthorized:
							client.refreshAccessToken()
							return e
						}

						return backoff.Permanent(e)
					}

					return nil
				},
				b,
			)

		if err != nil {
			err = logAndReturnErr(
				errors.WithMessage(err,
					"ValidatePermission: unable to get role perms"))
			return false, err
		}

		grantedRolePermissions = client.applyUserPermissionResourceValues(grantedRolePermissions, claims)
		if client.permissionAllowed(grantedRolePermissions, requiredPermission) {
			log("ValidatePermission: permission allowed to access resource")
			return true, nil
		}
	}

	log("ValidatePermission: permission not allowed to access resource")
	return false, nil
}

// ValidateRole validates if an access token has a specific role
func (client *DefaultClient) ValidateRole(requiredRoleID string, claims *JWTClaims) (bool, error) {
	for _, grantedRoleID := range claims.Roles {
		if grantedRoleID == requiredRoleID {
			log("ValidateRole: role allowed to access resource")
			return true, nil
		}
	}

	log("ValidateRole: role not allowed to access resource")
	return false, nil
}

// UserPhoneVerificationStatus gets user phone verification status on access token
func (client *DefaultClient) UserPhoneVerificationStatus(claims *JWTClaims) (bool, error) {
	phoneVerified := claims.JusticeFlags&UserStatusPhoneVerified == UserStatusPhoneVerified

	log("UserPhoneVerificationStatus: ", phoneVerified)
	return phoneVerified, nil
}

// UserEmailVerificationStatus gets user email verification status on access token
func (client *DefaultClient) UserEmailVerificationStatus(claims *JWTClaims) (bool, error) {
	emailVerified := claims.JusticeFlags&UserStatusEmailVerified == UserStatusEmailVerified

	log("UserEmailVerificationStatus: ", emailVerified)
	return emailVerified, nil
}

// UserAnonymousStatus gets user anonymous status on access token
func (client *DefaultClient) UserAnonymousStatus(claims *JWTClaims) (bool, error) {
	anonymousStatus := claims.JusticeFlags&UserStatusAnonymous == UserStatusAnonymous

	log("UserAnonymousStatus: ", anonymousStatus)
	return anonymousStatus, nil
}

// HasBan validates if certain ban exist
func (client *DefaultClient) HasBan(claims *JWTClaims, banType string) bool {
	for _, ban := range claims.Bans {
		if ban.Ban == banType {
			log("HasBan: user banned")
			return true
		}
	}

	log("HasBan: user not banned")
	return false
}

// HealthCheck lets caller know the health of the IAM client
func (client *DefaultClient) HealthCheck() bool {
	if client.jwksRefreshError != nil {
		logErr(client.jwksRefreshError,
			"HealthCheck: error in JWKs refresh")
		return false
	}

	if client.revocationListRefreshError != nil {
		logErr(client.revocationListRefreshError,
			"HealthCheck: error in revocation list refresh")
		return false
	}

	if client.tokenRefreshActive && client.tokenRefreshError != nil {
		logErr(client.tokenRefreshError,
			"HealthCheck: error in token refresh")
		return false
	}

	log("HealthCheck: all OK")
	return true
}

// ValidateAudience validate audience of user access token
func (client *DefaultClient) ValidateAudience(claims *JWTClaims) error {
	if claims == nil {
		return logAndReturnErr(
			errors.Wrap(errNilClaim,
				"ValidateAudience: invalid audience"))
	}

	// no need to check if no audience found in the claims. https://tools.ietf.org/html/rfc7519#section-4.1.3
	if claims.Audience == nil {
		log("ValidateAudience: no audience found in the token. " +
			"Skipping the audience validation")
		return nil
	}

	baseURI, found := client.baseURICache.Get(baseURIKey)
	if !found {
		path := fmt.Sprintf(clientInformationPath, claims.Namespace, client.config.ClientID)
		getClientInformationURL := client.config.BaseURL + path

		b := backoff.NewExponentialBackOff()
		b.MaxElapsedTime = maxBackOffTime

		err := backoff.
			Retry(
				func() error {
					e := client.getClientInformation(getClientInformationURL)
					if e != nil {
						if errors.Cause(e) == errUnauthorized {
							client.refreshAccessToken()
							return e
						}

						return backoff.Permanent(e)
					}

					return nil
				},
				b,
			)

		if err != nil {
			return logAndReturnErr(
				errors.WithMessage(err,
					"ValidateAudience: get client detail returns error"))
		}

		baseURI, _ = client.baseURICache.Get(baseURIKey)
	}

	isAllowed := false
	for _, reqAud := range claims.Audience {
		if reqAud == baseURI {
			isAllowed = true
			break
		}
	}

	if !isAllowed {
		return logAndReturnErr(
			errors.Wrap(errInvalidAud,
				"ValidateAudience: audience is not valid"))
	}

	log("ValidateAudience: audience is valid")
	return nil
}

// ValidateScope validate scope of user access token
func (client *DefaultClient) ValidateScope(claims *JWTClaims, reqScope string) error {
	scopes := strings.Split(claims.Scope, scopeSeparator)

	var isValid = false
	for _, scope := range scopes {
		if reqScope == scope {
			isValid = true
			break
		}
	}

	if !isValid {
		return logAndReturnErr(errors.Wrap(
			errInvalidScope,
			"ValidateScope: invalid scope"))
	}

	log("ValidateScope: scope valid")
	return nil
}

// getClientInformation get client base URI
// need client access token for authorization
func (client *DefaultClient) getClientInformation(getClientInformationURL string) (err error) {

	clientInformation := struct {
		BaseURI string `json:"baseUri"`
	}{}

	req, err := http.NewRequest(http.MethodGet, getClientInformationURL, nil)
	if err != nil {
		return errors.Wrap(err, "getClientInformation: unable to create new HTTP request")
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+client.clientAccessToken)

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime
	resp := &http.Response{}

	err = backoff.
		Retry(
			func() error {
				var e error
				resp, e = client.httpClient.Do(req)

				if e != nil {
					return backoff.Permanent(e)
				}

				if resp.StatusCode >= http.StatusInternalServerError {
					return e
				}

				return nil
			},
			b,
		)

	if err != nil {
		return errors.Wrap(err, "getClientInformation: unable to do HTTP request")
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "getClientInformation: unable to read body response")
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return errors.Wrap(errUnauthorized, "getClientInformation: unauthorized")
	}

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("getClientInformation: unable to get client information: error code : %d, error message : %s",
			resp.StatusCode, string(bodyBytes))
	}

	err = json.Unmarshal(bodyBytes, &clientInformation)
	if err != nil {
		return errors.Wrap(err, "getClientInformation: unable to unmarshal response body")
	}

	client.baseURICache.Set(baseURIKey, clientInformation.BaseURI, cache.DefaultExpiration)

	return nil
}
