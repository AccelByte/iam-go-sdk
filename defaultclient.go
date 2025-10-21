// Copyright 2018 AccelByte Inc
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
	"crypto/rsa"
	"encoding/json"
	gerror "errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AccelByte/bloom"
	"github.com/AccelByte/go-restful-plugins/v3/pkg/jaeger"
	"github.com/bluele/gcache"
	"github.com/cenkalti/backoff"
	"github.com/opentracing/opentracing-go"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"go.uber.org/atomic"
)

// JFlags constants
const (
	UserStatusEmailVerified = 1
	UserStatusPhoneVerified = 1 << 1
	UserStatusAnonymous     = 1 << 2
)

const (
	jwksPath              = "/v3/oauth/jwks"
	grantPath             = "/v3/oauth/token"
	revocationListPath    = "/v3/oauth/revocationlist"
	verifyPath            = "/v3/oauth/verify"
	getRolePath           = "/v3/admin/roles"
	getNamespaceRolePath  = "/v3/admin/namespaces/%s/roleoverride/%s/permissions"
	clientInformationPath = "/v3/admin/namespaces/%s/clients/%s"

	defaultTokenRefreshRate              = 0.8
	maxBackOffTime                       = 65 * time.Second
	defaultRoleCacheTime                 = 60 * time.Second
	defaultJWKSRefreshInterval           = 60 * time.Second
	defaultRevocationListRefreshInterval = 60 * time.Second

	clientInfoExpiration = 1 * time.Minute
	scopeSeparator       = " "

	defaultBasicServiceBaseURI = "http://justice-basic-service/basic"
)

// Config contains IAM configurations
type Config struct {
	BaseURL                       string
	BasicBaseURL                  string
	ClientID                      string
	ClientSecret                  string
	RolesCacheExpirationTime      time.Duration // default: 60s
	JWKSRefreshInterval           time.Duration // default: 60s
	RevocationListRefreshInterval time.Duration // default: 60s
	Debug                         bool
}

// DefaultClient define oauth client config
type DefaultClient struct {
	keys      map[string]*rsa.PublicKey
	keysMutex sync.RWMutex

	clientAccessToken     atomic.String
	config                *Config
	rolePermissionCache   *cache.Cache
	revocationFilter      *bloom.Filter
	revocationFilterMutex sync.RWMutex

	revokedUsers      map[string]time.Time
	revokedUsersMutex sync.RWMutex

	tokenRefreshActive           atomic.Bool
	localValidationActive        bool
	jwksRefreshError             error
	revocationListRefreshError   error
	tokenRefreshError            atomic.Error
	remoteTokenValidation        func(accessToken string, span opentracing.Span) (bool, error)
	clientInfoCache              *cache.Cache
	delegateTokenCache           gcache.Cache
	namespaceContextCache        gcache.Cache
	roleNamespacePermissionCache gcache.Cache
	// for easily mocking the HTTP call
	httpClient HTTPClient
}

// HTTPClient is an interface for http.Client.
// The purpose for having this so we could easily mock the HTTP call.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

var debug atomic.Bool

// NewDefaultClient creates new IAM DefaultClient
func NewDefaultClient(config *Config) *DefaultClient {
	if config.RolesCacheExpirationTime <= 0 {
		config.RolesCacheExpirationTime = defaultRoleCacheTime
	}

	if config.JWKSRefreshInterval <= 0 {
		config.JWKSRefreshInterval = defaultJWKSRefreshInterval
	}

	if config.RevocationListRefreshInterval <= 0 {
		config.RevocationListRefreshInterval = defaultRevocationListRefreshInterval
	}

	if len(config.BasicBaseURL) == 0 {
		config.BasicBaseURL = defaultBasicServiceBaseURI
	}

	client := &DefaultClient{
		config: config,
		rolePermissionCache: cache.New(
			config.RolesCacheExpirationTime,
			2*config.RolesCacheExpirationTime,
		),
		clientInfoCache: cache.New(
			clientInfoExpiration,
			clientInfoExpiration,
		),
		keys:         make(map[string]*rsa.PublicKey),
		revokedUsers: make(map[string]time.Time),
		httpClient:   &http.Client{},
	}
	client.remoteTokenValidation = client.validateAccessToken
	client.delegateTokenCache = gcache.New(1000).LRU().
		LoaderExpireFunc(func(extendNamespace interface{}) (interface{}, *time.Duration, error) {
			token, ttl, err := client.clientDelegateTokenGrant(extendNamespace.(string), nil)
			return token, ttl, err
		}).
		Build()

	client.namespaceContextCache = gcache.New(1000).LRU().
		LoaderExpireFunc(func(namespace interface{}) (interface{}, *time.Duration, error) {
			namespaceCtx, err := client.getNamespaceContext(namespace.(string))
			ttl := time.Hour
			if gerror.Is(err, ErrNamespaceNotFound) {
				ttl = time.Minute * 3
				// by this way, these not found namespace can still have a short time cache
				return &NamespaceContext{NotFound: true}, &ttl, nil
			}
			return namespaceCtx, &ttl, err
		}).
		Build()

	client.roleNamespacePermissionCache = gcache.New(100).LRU().
		LoaderExpireFunc(func(namespaceAndIdentity interface{}) (interface{}, *time.Duration, error) {
			namespace, identity, err := extractRoleOverrideCacheKey(namespaceAndIdentity.(string))
			if err != nil {
				return nil, nil, err
			}
			reqSpan := jaeger.StartChildSpan(nil, "cache.getRoleNamespacePermission")
			defer jaeger.Finish(reqSpan)
			permissions, err := client.remoteGetRoleNamespacePermission(namespace, identity, reqSpan)
			if err != nil {
				return nil, nil, err
			}
			ttl := 1 * time.Minute
			return permissions, &ttl, err
		}).Build()

	debug.Store(config.Debug)

	log("NewDefaultClient: debug enabled")

	return client
}

func (client *DefaultClient) setKeySafe(key string, value *rsa.PublicKey) {
	client.keysMutex.Lock()
	defer client.keysMutex.Unlock()

	if len(client.keys) == 0 {
		client.keys = make(map[string]*rsa.PublicKey)
	}
	client.keys[key] = value
}

func (client *DefaultClient) getKeySafe(key string) (value *rsa.PublicKey, exists bool) {
	client.keysMutex.RLock()
	defer client.keysMutex.RUnlock()

	value, ok := client.keys[key]
	return value, ok
}

func (client *DefaultClient) setRevokedUsersSafe(values map[string]time.Time) {
	client.revokedUsersMutex.Lock()
	defer client.revokedUsersMutex.Unlock()

	client.revokedUsers = values
}

func (client *DefaultClient) setRevokedUserSafe(key string, value time.Time) {
	client.revokedUsersMutex.Lock()
	defer client.revokedUsersMutex.Unlock()

	client.revokedUsers[key] = value
}

func (client *DefaultClient) getRevokedUserSafe(key string) (value time.Time, exists bool) {
	client.revokedUsersMutex.RLock()
	defer client.revokedUsersMutex.RUnlock()

	value, ok := client.revokedUsers[key]
	return value, ok
}

// ClientTokenGrant starts client token grant to get client bearer token for role caching
func (client *DefaultClient) ClientTokenGrant(opts ...Option) error {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "client.ClientTokenGrant")

	defer jaeger.Finish(span)

	refreshInterval, err := client.clientTokenGrant(span)
	if err != nil {
		jaeger.TraceError(span, err)

		return logAndReturnErr(
			errors.WithMessage(err,
				"ClientTokenGrant: unable to do token grant"))
	}

	go func() {
		client.tokenRefreshActive.Store(true)

		time.Sleep(refreshInterval)
		client.spawnRefreshAccessTokenScheduler(span)
	}()

	log("ClientTokenGrant: token grant success")

	return nil
}

// ClientToken returns client access token
func (client *DefaultClient) ClientToken(opts ...Option) string {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "client.ClientToken")
	defer jaeger.Finish(span)

	return client.clientAccessToken.Load()
}

func (client *DefaultClient) DelegateToken(extendNamespace string, opts ...Option) (string, error) {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "client.DelegateToken")
	defer jaeger.Finish(span)

	delegateToken, err := client.delegateTokenCache.Get(extendNamespace)
	if err != nil {
		return "", err
	}
	return delegateToken.(string), err
}

// StartLocalValidation starts goroutines to refresh JWK and revocation list periodically
// this enables local token validation
func (client *DefaultClient) StartLocalValidation(opts ...Option) error {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "client.StartLocalValidation")

	defer jaeger.Finish(span)

	err := client.getJWKS(span)
	if err != nil {
		jaeger.TraceError(span, errors.WithMessage(err,
			"StartLocalValidation: unable to get JWKS"))

		return logAndReturnErr(
			errors.WithMessage(err,
				"StartLocalValidation: unable to get JWKS"))
	}

	err = client.getRevocationList(span)
	if err != nil {
		jaeger.TraceError(span, errors.WithMessage(err,
			"StartLocalValidation: unable to get revocation list"))

		return logAndReturnErr(
			errors.WithMessage(err,
				"StartLocalValidation: unable to get revocation list"))
	}

	go client.refreshJWKS(span)

	go client.refreshRevocationList(span)

	client.localValidationActive = true

	log("StartLocalValidation: local validation activated")

	return nil
}

// ValidateAccessToken validates access token by calling IAM service
func (client *DefaultClient) ValidateAccessToken(accessToken string, opts ...Option) (bool, error) {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "client.ValidateAccessToken")

	defer jaeger.Finish(span)

	var isValid bool

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime

	err := backoff.
		Retry(
			func() error {
				var e error

				reqSpan := jaeger.StartChildSpan(span, "client.ValidateAccessToken.Retry")
				defer jaeger.Finish(reqSpan)

				isValid, e = client.remoteTokenValidation(accessToken, reqSpan)
				if e != nil {
					if errors.Cause(e) == errUnauthorized {
						_, _ = client.refreshAccessToken(reqSpan)
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
func (client *DefaultClient) ValidateAndParseClaims(accessToken string, opts ...Option) (*JWTClaims, error) {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "client.ValidateAccessToken")

	defer jaeger.Finish(span)

	if !client.localValidationActive {
		err := logAndReturnErr(
			errors.Wrap(errNoLocalValidation,
				"ValidateAndParseClaims: unable to validate claims"))
		jaeger.TraceError(span, err)

		return nil, err
	}

	claims, err := client.validateJWT(accessToken, span)
	if err != nil {
		if err == errTokenExpired {
			jaeger.TraceError(span, err)
			return nil, err
		}
		err = logAndReturnErr(
			errors.WithMessage(err,
				"ValidateAndParseClaims: unable to validate JWT"))
		jaeger.TraceError(span, err)

		return nil, err
	}

	if client.userRevoked(claims.Subject, int64(claims.IssuedAt)) {
		err = logAndReturnErr(
			errors.Wrap(errUserRevoked,
				"ValidateAndParseClaims: user (owner) of JWT is revoked"))
		jaeger.TraceError(span, err)

		return nil, err
	}

	if client.tokenRevoked(accessToken) {
		err = logAndReturnErr(
			errors.Wrap(errTokenRevoked,
				"ValidateAndParseClaims: token is revoked"))
		jaeger.TraceError(span, err)

		return nil, err
	}

	log("ValidateAndParseClaims: JWT validated")

	return claims, nil
}

// ValidatePermission validates if an access token has right for a specific permission
// requiredPermission: permission to access resource, example:
//
//	{Resource: "NAMESPACE:{namespace}:USER:{userId}", Action: 2}
//
// permissionResources: resource string to replace the `{}` placeholder in
//
//	`requiredPermission`, example: p["{namespace}"] = "accelbyte"
//
// nolint: funlen
func (client *DefaultClient) ValidatePermission(claims *JWTClaims,
	requiredPermission Permission, permissionResources map[string]string, opts ...Option,
) (bool, error) {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "client.ValidateAccessToken")

	defer jaeger.Finish(span)

	if claims == nil {
		log("ValidatePermission: claim is nil")
		return false, nil
	}

	for placeholder, value := range permissionResources {
		requiredPermission.Resource = strings.Replace(requiredPermission.Resource, placeholder, value, 1)
	}
	targetNamespace, _ := permissionResources["{namespace}"]

	if client.permissionAllowed(claims.Permissions, requiredPermission) {
		log("ValidatePermission: permission allowed to access resource")
		return true, nil
	}

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime

	for _, namespaceRole := range claims.NamespaceRoles {
		namespaceRole := namespaceRole
		grantedRolePermissions := make([]Permission, 0)

		err := backoff.
			Retry(
				func() error {
					var e error

					reqSpan := jaeger.StartChildSpan(span, "client.ValidatePermission.Retry")
					defer jaeger.Finish(reqSpan)

					grantedRolePermissions, e = client.GetRoleNamespacePermission(namespaceRole.Namespace, namespaceRole.RoleID, targetNamespace, span)
					if e != nil {
						switch errors.Cause(e) {
						case errRoleNotFound:
							return nil
						case errUnauthorized:
							_, _ = client.refreshAccessToken(reqSpan)
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
			jaeger.TraceError(span, err)

			return false, err
		}

		grantedRolePermissions = client.applyUserPermissionResourceValues(grantedRolePermissions, claims,
			namespaceRole.Namespace)
		if client.permissionAllowed(grantedRolePermissions, requiredPermission) {
			jaeger.AddLog(span, "msg", "ValidatePermission: permission allowed to access resource")
			log("ValidatePermission: permission allowed to access resource")

			return true, nil
		}
	}

	// will remove permissions checking using roles once namespace role has fully used
	for _, roleID := range claims.Roles {
		roleID := roleID

		grantedRolePermissions := make([]Permission, 0)
		err := backoff.
			Retry(
				func() error {
					var e error

					reqSpan := jaeger.StartChildSpan(span, "client.ValidatePermission.Retry")
					defer jaeger.Finish(reqSpan)

					grantedRolePermissions, e = client.getRolePermission(roleID, span)
					if e != nil {
						switch errors.Cause(e) {
						case errRoleNotFound:
							return nil
						case errUnauthorized:
							_, _ = client.refreshAccessToken(reqSpan)
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
			jaeger.TraceError(span, err)

			return false, err
		}

		grantedRolePermissions = client.applyUserPermissionResourceValues(grantedRolePermissions, claims, "")
		if client.permissionAllowed(grantedRolePermissions, requiredPermission) {
			jaeger.AddLog(span, "msg", "ValidatePermission: permission allowed to access resource")
			log("ValidatePermission: permission allowed to access resource")

			return true, nil
		}
	}

	jaeger.AddLog(span, "msg", "ValidatePermission: permission not allowed to access resource")
	log("ValidatePermission: permission not allowed to access resource")

	return false, nil
}

// ValidateRole validates if an access token has a specific role
func (client *DefaultClient) ValidateRole(requiredRoleID string, claims *JWTClaims, opts ...Option) (bool, error) {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "client.ValidateAccessToken")

	defer jaeger.Finish(span)

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
func (client *DefaultClient) UserPhoneVerificationStatus(claims *JWTClaims, opts ...Option) (bool, error) {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "client.ValidateAccessToken")

	defer jaeger.Finish(span)

	phoneVerified := claims.JusticeFlags&UserStatusPhoneVerified == UserStatusPhoneVerified

	log("UserPhoneVerificationStatus: ", phoneVerified)

	return phoneVerified, nil
}

// UserEmailVerificationStatus gets user email verification status on access token
func (client *DefaultClient) UserEmailVerificationStatus(claims *JWTClaims, opts ...Option) (bool, error) {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "client.UserEmailVerificationStatus")

	defer jaeger.Finish(span)

	emailVerified := claims.JusticeFlags&UserStatusEmailVerified == UserStatusEmailVerified

	log("UserEmailVerificationStatus: ", emailVerified)

	return emailVerified, nil
}

// UserAnonymousStatus gets user anonymous status on access token
func (client *DefaultClient) UserAnonymousStatus(claims *JWTClaims, opts ...Option) (bool, error) {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "client.UserAnonymousStatus")

	defer jaeger.Finish(span)

	anonymousStatus := claims.JusticeFlags&UserStatusAnonymous == UserStatusAnonymous

	log("UserAnonymousStatus: ", anonymousStatus)

	return anonymousStatus, nil
}

// HasBan validates if certain ban exist
func (client *DefaultClient) HasBan(claims *JWTClaims, banType string, opts ...Option) bool {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "client.HasBan")

	defer jaeger.Finish(span)

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
func (client *DefaultClient) HealthCheck(opts ...Option) bool {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "client.HealthCheck")

	defer jaeger.Finish(span)

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

	isTokenRefreshActive := client.tokenRefreshActive.Load()
	tokenRefreshError := client.tokenRefreshError.Load()
	if isTokenRefreshActive && tokenRefreshError != nil {
		logErr(
			tokenRefreshError,
			"HealthCheck: error in token refresh",
		)
		return false
	}

	log("HealthCheck: all OK")

	return true
}

// ValidateAudience validate audience of user access token
// nolint: funlen
func (client *DefaultClient) ValidateAudience(claims *JWTClaims, opts ...Option) error {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "client.ValidateAudience")

	defer jaeger.Finish(span)

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

	clientInfo, err := client.GetClientInformation(claims.Namespace, client.config.ClientID)
	if err != nil {
		jaeger.TraceError(span, errors.WithMessage(err, "ValidateAudience: get client detail returns error"))

		return logAndReturnErr(
			errors.WithMessage(err,
				"ValidateAudience: get client detail returns error"))
	}

	isAllowed := false

	for _, reqAud := range claims.Audience {
		if reqAud == clientInfo.BaseURI {
			isAllowed = true
			break
		}
	}

	if !isAllowed {
		jaeger.TraceError(span, errors.Wrap(errInvalidAud, "ValidateAudience: audience is not valid"))

		return logAndReturnErr(
			errors.Wrap(errInvalidAud,
				"ValidateAudience: audience is not valid"))
	}

	log("ValidateAudience: audience is valid")

	return nil
}

// ValidateScope validate scope of user access token
func (client *DefaultClient) ValidateScope(claims *JWTClaims, reqScope string, opts ...Option) error {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "client.ValidateAccessToken")

	defer jaeger.Finish(span)

	scopes := strings.Split(claims.Scope, scopeSeparator)

	isValid := false

	for _, scope := range scopes {
		if reqScope == scope {
			isValid = true
			break
		}
	}

	if !isValid {
		jaeger.TraceError(span, errors.Wrap(
			errInvalidScope,
			"ValidateScope: invalid scope"))

		return logAndReturnErr(errors.Wrap(
			errInvalidScope,
			"ValidateScope: invalid scope"))
	}

	log("ValidateScope: scope valid")

	return nil
}

// GetRolePermissions gets permissions of a role
func (client *DefaultClient) GetRolePermissions(roleID string, opts ...Option) (perms []Permission, err error) {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "client.GetRolePermission")

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime

	err = backoff.
		Retry(
			func() error {
				var e error

				reqSpan := jaeger.StartChildSpan(span, "client.GetRolePermission.Retry")
				defer jaeger.Finish(reqSpan)

				perms, e = client.getRolePermission(roleID, span)
				if e != nil {
					switch errors.Cause(e) {
					case errRoleNotFound:
						return nil
					case errUnauthorized:
						_, _ = client.refreshAccessToken(reqSpan)
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
				"GetRolePermissions: unable to get role perms"))
		jaeger.TraceError(span, err)

		return []Permission{}, err
	}

	return perms, err
}

// GetClientInformation gets IAM client information,
// it will look into cache first, if not found then fetch it to IAM.
func (client *DefaultClient) GetClientInformation(namespace string, clientID string, opts ...Option) (*ClientInformation, error) {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "client.GetClientInformation")

	defer jaeger.Finish(span)

	cachedClientInfo, found := client.clientInfoCache.Get(clientID)
	if found {
		return cachedClientInfo.(*ClientInformation), nil
	}

	clientInfo, err := client.fetchClientInformation(namespace, clientID)
	if err != nil {
		return nil, err
	}
	client.clientInfoCache.Set(clientID, clientInfo, cache.DefaultExpiration)
	return clientInfo, nil
}

// fetchClientInformation fetch client information to IAM
func (client *DefaultClient) fetchClientInformation(namespace string, clientID string, opts ...Option) (clientInfo *ClientInformation, err error) {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "client.getClientInformation")

	defer jaeger.Finish(span)

	getClientInformationURL := client.config.BaseURL + fmt.Sprintf(clientInformationPath, namespace, clientID)
	req, err := http.NewRequest(http.MethodGet, getClientInformationURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "getClientInformation: unable to create new HTTP request")
	}

	req.Header.Add("Content-Type", "application/json")

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime

	var responseStatusCode int

	var responseBodyBytes []byte

	// nolint: dupl
	err = backoff.
		Retry(
			func() error {
				var e error

				req.Header.Set("Authorization", "Bearer "+client.clientAccessToken.Load())

				reqSpan := jaeger.StartChildSpan(span, "HTTP Request: "+req.Method+" "+req.URL.Path)
				defer jaeger.Finish(reqSpan)
				jErr := jaeger.InjectSpanIntoRequest(reqSpan, req)
				logErr(jErr)

				resp, e := client.httpClient.Do(req)
				if e != nil {
					return backoff.Permanent(e)
				}
				defer resp.Body.Close()

				responseStatusCode = resp.StatusCode
				if resp.StatusCode >= http.StatusInternalServerError {
					jaeger.TraceError(reqSpan, fmt.Errorf("StatusCode: %v", resp.StatusCode))
					return errors.Errorf("getClientInformation: endpoint returned status code : %v", responseStatusCode)
				} else if resp.StatusCode == http.StatusUnauthorized {
					jaeger.TraceError(span, errors.Wrap(errUnauthorized, "getClientInformation: unauthorized"))

					// refresh the client accessToken
					log("fetchClientInformation: refresh client token")
					_, _ = client.refreshAccessToken(reqSpan)

					return errors.Wrap(errUnauthorized, "getClientInformation: unauthorized")
				}

				responseBodyBytes, e = io.ReadAll(resp.Body)
				if e != nil {
					jaeger.TraceError(reqSpan, fmt.Errorf("Body.ReadAll: %s", e))
					return errors.Wrap(e, "getClientInformation: unable to read body response")
				}

				return nil
			},
			b,
		)
	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "getClientInformation: unable to do HTTP request"))
		return nil, errors.Wrap(err, "getClientInformation: unable to do HTTP request")
	}

	if responseStatusCode != http.StatusOK {
		jaeger.TraceError(span,
			errors.Errorf(
				"getClientInformation: unable to get client information: error code : %d, error message : %s",
				responseStatusCode, string(responseBodyBytes)))

		return nil, errors.Errorf("getClientInformation: unable to get client information: error code : %d, error message : %s",
			responseStatusCode, string(responseBodyBytes))
	}

	var clientInformation ClientInformation
	err = json.Unmarshal(responseBodyBytes, &clientInformation)
	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "getClientInformation: unable to unmarshal response body"))
		return nil, errors.Wrap(err, "getClientInformation: unable to unmarshal response body")
	}

	return &clientInformation, nil
}
