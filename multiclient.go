package iam

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/AccelByte/go-jose/jwt"
	"github.com/AccelByte/go-restful-plugins/v3/pkg/jaeger"
	"github.com/cenkalti/backoff"
	gojwt "github.com/golang-jwt/jwt/v4"

	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
)

const (
	defaultMultiJWKSRefreshInterval = 5 * time.Minute
)

type MultiClientConfig struct {
	JWKSRefreshInterval time.Duration // default: 5minutes
	Debug               bool
}

// DefaultClient define oauth multiClient config
type MultiClient struct {
	keys      map[string]map[string]*rsa.PublicKey
	keysMutex sync.RWMutex

	config *MultiClientConfig

	localValidationActive bool
	jwksNextRefresh       sync.Map
	jwksRefreshError      sync.Map

	// for easily mocking the HTTP call
	httpClient HTTPClient
}

// NewMultiClient creates new IAM DefaultClient
func NewMultiClient(config *MultiClientConfig) *MultiClient {
	if config.JWKSRefreshInterval <= 0 {
		config.JWKSRefreshInterval = defaultMultiJWKSRefreshInterval
	}

	multiClient := &MultiClient{
		config:           config,
		keys:             make(map[string]map[string]*rsa.PublicKey),
		jwksNextRefresh:  sync.Map{},
		jwksRefreshError: sync.Map{},
		httpClient:       &http.Client{},
	}

	debug.Store(config.Debug)

	return multiClient
}

// ClientTokenGrant starts multiClient token grant to get multiClient bearer token for role caching
func (multiClient *MultiClient) ClientTokenGrant(opts ...Option) error {
	return errors.New("ClientTokenGrant not implemented on MultiClient")
}

// ClientToken returns multiClient access token
func (multiClient *MultiClient) ClientToken(opts ...Option) string {
	logErr(errors.New("ClientToken not implemented on MultiClient"))
	return ""
}

// StartLocalValidation starts goroutines to refresh JWK and revocation list periodically
// this enables local token validation
func (multiClient *MultiClient) StartLocalValidation(opts ...Option) error {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "multiClient.StartLocalValidation")

	defer jaeger.Finish(span)

	go multiClient.refreshJWKS(span)

	multiClient.localValidationActive = true

	log("StartLocalValidation: local validation activated")

	return nil
}

// ValidateAccessToken validates access token by calling IAM service
func (multiClient *MultiClient) ValidateAccessToken(accessToken string, opts ...Option) (bool, error) {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "multiClient.ValidateAccessToken")
	defer jaeger.Finish(span)

	if !multiClient.localValidationActive {
		return false, errors.New("need to call StartLocalValidation first")
	}

	claims := gojwt.RegisteredClaims{}
	parser := gojwt.Parser{}
	_, _, err := parser.ParseUnverified(accessToken, &claims)
	if err != nil {
		return false, err
	}
	if _, ok := multiClient.jwksNextRefresh.Load(claims.Issuer); !ok {
		err := multiClient.getJWKS(claims.Issuer, span)
		if err != nil {
			log(fmt.Sprintf("unable get JWKS from IAM issuer: %s; error: %s", claims.Issuer, err))
			return false, nil
		}
	}

	_, err = multiClient.validateJWT(claims.Issuer, accessToken, span)
	return err == nil, err
}

// ValidateAndParseClaims validates access token locally and returns the JWT claims contained in the token
func (multiClient *MultiClient) ValidateAndParseClaims(accessToken string, opts ...Option) (*JWTClaims, error) {
	options := processOptions(opts)
	span, _ := jaeger.StartSpanFromContext(options.jaegerCtx, "multiClient.ValidateAndParseClaims")
	defer jaeger.Finish(span)

	if !multiClient.localValidationActive {
		return nil, errors.New("need to call StartLocalValidation first")
	}

	claims := gojwt.RegisteredClaims{}
	parser := gojwt.Parser{}
	_, _, err := parser.ParseUnverified(accessToken, &claims)
	if err != nil {
		return nil, err
	}
	if _, ok := multiClient.jwksNextRefresh.Load(claims.Issuer); !ok {
		err := multiClient.getJWKS(claims.Issuer, span)
		if err != nil {
			log(fmt.Sprintf("unable get JWKS from IAM issuer: %s; error: %s", claims.Issuer, err))
			return nil, nil
		}
	}
	return multiClient.validateJWT(claims.Issuer, accessToken, span)
}

// ValidatePermission validates if an access token has right for a specific permission
// requiredPermission: permission to access resource, example:
// 		{Resource: "NAMESPACE:{namespace}:USER:{userId}", Action: 2}
// permissionResources: resource string to replace the `{}` placeholder in
// 		`requiredPermission`, example: p["{namespace}"] = "accelbyte"
func (multiClient *MultiClient) ValidatePermission(claims *JWTClaims, requiredPermission Permission,
	permissionResources map[string]string, opts ...Option) (bool, error) {
	return false, errors.New("ValidatePermission not implemented on MultiClient")
}

// ValidateRole validates if an access token has a specific role
func (multiClient *MultiClient) ValidateRole(requiredRoleID string, claims *JWTClaims, opts ...Option) (bool, error) {
	return false, errors.New("ValidateRole not implemented on MultiClient")
}

// UserPhoneVerificationStatus gets user phone verification status on access token
func (multiClient *MultiClient) UserPhoneVerificationStatus(claims *JWTClaims, opts ...Option) (bool, error) {
	return false, errors.New("UserPhoneVerificationStatus not implemented on MultiClient")
}

// UserEmailVerificationStatus gets user email verification status on access token
func (multiClient *MultiClient) UserEmailVerificationStatus(claims *JWTClaims, opts ...Option) (bool, error) {
	return false, errors.New("UserEmailVerificationStatus not implemented on MultiClient")
}

// UserAnonymousStatus gets user anonymous status on access token
func (multiClient *MultiClient) UserAnonymousStatus(claims *JWTClaims, opts ...Option) (bool, error) {
	return false, errors.New("UserAnonymousStatus not implemented on MultiClient")
}

// HasBan validates if certain ban exist
func (multiClient *MultiClient) HasBan(claims *JWTClaims, banType string, opts ...Option) bool {
	logErr(errors.New("HasBan not implemented on MultiClient"))
	return false
}

// HealthCheck lets caller know the health of the IAM multiClient
func (multiClient *MultiClient) HealthCheck(opts ...Option) bool {
	var err error
	multiClient.jwksRefreshError.Range(func(key, value interface{}) bool {
		issuer := key.(string)
		jwksErr := key.(error)
		if jwksErr != nil {
			newError := fmt.Errorf("issuer: %s: error: %s", issuer, jwksErr)
			if err == nil {
				err = newError
			} else {
				err = fmt.Errorf("%s [%w]", err, newError)
			}
		}
		return true
	})
	if err != nil {
		logErr(err,
			"HealthCheck: error in JWKs refresh")
		return false
	}
	return true
}

// ValidateAudience validate audience of user access token
func (multiClient *MultiClient) ValidateAudience(claims *JWTClaims, opts ...Option) error {
	return errors.New("ValidateAudience not implemented on MultiClient")
}

// ValidateScope validate scope of user access token
func (multiClient *MultiClient) ValidateScope(claims *JWTClaims, scope string, opts ...Option) error {
	return errors.New("ValidateScope not implemented on MultiClient")
}

// GetRolePermissions gets permissions of a role
func (multiClient *MultiClient) GetRolePermissions(roleID string, opts ...Option) (perms []Permission, err error) {
	return nil, errors.New("GetRolePermissions not implemented on MultiClient")
}

// GetClientInformation gets IAM multiClient information,
// it will look into cache first, if not found then fetch it to IAM.
func (multiClient *MultiClient) GetClientInformation(namespace string, multiClientID string, opts ...Option) (*ClientInformation, error) {
	return nil, errors.New("GetClientInformation not implemented on MultiClient")
}

func (multiClient *MultiClient) getJWKS(issuer string, rootSpan opentracing.Span) error {
	span := jaeger.StartChildSpan(rootSpan, "multiClient.getJWKS")
	defer jaeger.Finish(span)

	req, err := http.NewRequest("GET", issuer+"/iam"+jwksPath, nil)
	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "getJWKS: unable to create new JWKS request"))
		return errors.Wrap(err, "getJWKS: unable to create new JWKS request")
	}

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime

	var responseStatusCode int

	var responseBodyBytes []byte

	// nolint: dupl
	err = backoff.
		Retry(
			func() error {
				var e error

				reqSpan := jaeger.StartChildSpan(span, "HTTP Request: "+req.Method+" "+req.URL.Path)
				defer jaeger.Finish(reqSpan)
				jErr := jaeger.InjectSpanIntoRequest(reqSpan, req)
				logErr(jErr)

				resp, e := multiClient.httpClient.Do(req)
				if e != nil {
					return backoff.Permanent(e)
				}
				defer resp.Body.Close()

				responseStatusCode = resp.StatusCode
				if resp.StatusCode >= http.StatusInternalServerError {
					jaeger.TraceError(reqSpan, fmt.Errorf("StatusCode: %v", resp.StatusCode))
					return errors.Errorf("getJWKS: endpoint returned status code : %v", responseStatusCode)
				}

				responseBodyBytes, e = ioutil.ReadAll(resp.Body)
				if e != nil {
					jaeger.TraceError(reqSpan, fmt.Errorf("Body.ReadAll: %s", e))
					return errors.Wrap(e, "getJWKS: unable to read response body")
				}

				return nil
			},
			b,
		)

	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "getJWKS: unable to do HTTP request to get JWKS"))
		return errors.Wrap(err, "getJWKS: unable to do HTTP request to get JWKS")
	}

	if responseStatusCode != http.StatusOK {
		jaeger.TraceError(span, errors.Errorf("getJWKS: unable to get JWKS: error code : %d, error message : %s",
			responseStatusCode, string(responseBodyBytes)))

		return errors.Errorf("getJWKS: unable to get JWKS: error code : %d, error message : %s",
			responseStatusCode, string(responseBodyBytes))
	}

	var jwks Keys

	err = json.Unmarshal(responseBodyBytes, &jwks)
	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "getJWKS: unable to unmarshal response body"))
		return errors.Wrap(err, "getJWKS: unable to unmarshal response body")
	}

	multiClient.setKeysSafe(issuer, make(map[string]*rsa.PublicKey))

	for i := range jwks.Keys {
		jwk := &jwks.Keys[i]

		key, errGenerate := generatePublicKey(jwk)
		if errGenerate != nil {
			jaeger.TraceError(span, errors.WithMessage(errGenerate, "getJWKS: unable to generate public key"))
			return errors.WithMessage(err, "getJWKS: unable to generate public key")
		}

		multiClient.setKeySafe(issuer, jwk.Kid, key)
	}

	multiClient.jwksNextRefresh.Store(issuer, time.Now().Add(multiClient.config.JWKSRefreshInterval))

	return nil
}

func (multiClient *MultiClient) setKeysSafe(issuer string, values map[string]*rsa.PublicKey) {
	multiClient.keysMutex.Lock()
	defer multiClient.keysMutex.Unlock()

	multiClient.keys[issuer] = values
}

func (multiClient *MultiClient) setKeySafe(issuer, key string, value *rsa.PublicKey) {
	multiClient.keysMutex.Lock()
	defer multiClient.keysMutex.Unlock()

	multiClient.keys[issuer][key] = value
}

func (multiClient *MultiClient) getKeySafe(issuer, key string) (value *rsa.PublicKey, exists bool) {
	multiClient.keysMutex.RLock()
	defer multiClient.keysMutex.RUnlock()

	issuerValue, ok := multiClient.keys[issuer]
	if !ok {
		return nil, false
	}
	value, ok = issuerValue[key]
	return value, ok
}

func (multiClient *MultiClient) getPublicKey(issuer, keyID string) (*rsa.PublicKey, error) {
	key, ok := multiClient.getKeySafe(issuer, keyID)
	if !ok {
		return nil, errors.New("getPublicKey: public key doesn't exist")
	}

	return key, nil
}

func (multiClient *MultiClient) validateJWT(issuer, accessToken string, rootSpan opentracing.Span) (*JWTClaims, error) {
	jwtClaims := JWTClaims{}

	webToken, err := jwt.ParseSigned(accessToken)
	if err != nil {
		return nil, errors.Wrap(err, "validateJWT: unable to parse JWT")
	}

	if webToken.Headers[0].KeyID == "" {
		return nil, errors.WithMessage(errInvalidTokenSignatureKey, "validateJWT: invalid header")
	}

	publicKey, err := multiClient.getPublicKey(issuer, webToken.Headers[0].KeyID)
	if err != nil {
		return nil, errors.WithMessage(err, "validateJWT: invalid key")
	}

	err = webToken.Claims(publicKey, &jwtClaims)
	if err != nil {
		return nil, errors.Wrap(err, "validateJWT: unable to deserialize JWT claims")
	}

	err = jwtClaims.Validate()
	if err != nil {
		return nil, errors.Wrap(err, "validateJWT: unable to validate JWT")
	}
	return &jwtClaims, nil
}

func (multiClient *MultiClient) refreshJWKS(rootSpan opentracing.Span) {
	span := jaeger.StartChildSpan(rootSpan, "multiClient.refreshJWKS")
	defer jaeger.Finish(span)

	mutex := sync.RWMutex{}
	onProgress := map[string]struct{}{}
	for {
		issuers := []string{}
		now := time.Now()
		mutex.Lock()
		multiClient.jwksNextRefresh.Range(func(key, value interface{}) bool {
			if now.After(value.(time.Time)) {
				issuer := key.(string)
				if _, ok := onProgress[issuer]; !ok {
					issuers = append(issuers, issuer)
				}
			}
			return true
		})
		mutex.Unlock()
		for _, issuer := range issuers {
			go func(m *sync.RWMutex, op map[string]struct{}, jwksRefreshError *sync.Map, iamUrl string) {
				m.Lock()
				op[iamUrl] = struct{}{}
				m.Unlock()
				err := multiClient.getJWKS(iamUrl, rootSpan)
				if err != nil {
					log(fmt.Sprintf("error refresh JWKS for issuer: %s; error: %s", iamUrl, err))
				}
				jwksRefreshError.Store(iamUrl, err)
				m.Lock()
				delete(op, iamUrl)
				m.Unlock()
			}(&mutex, onProgress, &multiClient.jwksRefreshError, issuer)
		}
		time.Sleep(1 * time.Second)
	}
}
