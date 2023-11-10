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
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/AccelByte/go-jose/jwt"
	"github.com/AccelByte/go-restful-plugins/v3/pkg/jaeger"
	"github.com/cenkalti/backoff"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
)

// nolint: funlen
func (client *DefaultClient) validateAccessToken(accessToken string, rootSpan opentracing.Span) (bool, error) {
	span := jaeger.StartChildSpan(rootSpan, "client.validateAccessToken")
	defer jaeger.Finish(span)

	form := url.Values{}
	form.Add("token", accessToken)

	req, err := http.NewRequest(http.MethodPost, client.config.BaseURL+verifyPath, bytes.NewBufferString(form.Encode()))
	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "validateAccessToken: unable to create new HTTP request"))
		return false, errors.Wrap(err, "validateAccessToken: unable to create new HTTP request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.config.ClientID, client.config.ClientSecret)

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime

	var responseStatusCode int

	err = backoff.
		Retry(
			func() error {
				reqSpan := jaeger.StartChildSpan(span, "HTTP Request: "+req.Method+" "+req.URL.Path)
				defer jaeger.Finish(reqSpan)
				jErr := jaeger.InjectSpanIntoRequest(reqSpan, req)
				logErr(jErr)

				resp, e := client.httpClient.Do(req)
				if e != nil {
					jaeger.TraceError(reqSpan, e)
					return backoff.Permanent(e)
				}
				defer resp.Body.Close()

				responseStatusCode = resp.StatusCode
				if resp.StatusCode >= http.StatusInternalServerError {
					jaeger.TraceError(
						reqSpan,
						errors.Errorf(
							"validateAccessToken: endpoint returned status code : %v",
							responseStatusCode,
						),
					)

					return errors.Errorf("validateAccessToken: endpoint returned status code : %v", responseStatusCode)
				}

				return nil
			},
			b,
		)

	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "validateAccessToken: unable to do HTTP request"))
		return false, errors.Wrap(err, "validateAccessToken: unable to do HTTP request")
	}

	if responseStatusCode == http.StatusUnauthorized {
		jaeger.TraceError(span, errors.Wrap(errUnauthorized, "validateAccessToken: unauthorized"))
		return false, errors.Wrap(errUnauthorized, "validateAccessToken: unauthorized")
	}

	if responseStatusCode != http.StatusOK {
		return false, errors.Errorf("validateAccessToken: unable to validate access token: error code : %d",
			responseStatusCode)
	}

	return true, nil
}

func (client *DefaultClient) validateJWT(token string, rootSpan opentracing.Span) (*JWTClaims, error) {
	span := jaeger.StartChildSpan(rootSpan, "client.validateJWT")
	defer jaeger.Finish(span)

	if token == "" {
		return nil, errors.WithMessage(errEmptyToken, "validateJWT: invalid token")
	}

	jwtClaims := JWTClaims{}

	webToken, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, errors.Wrap(err, "validateJWT: unable to parse JWT")
	}

	if webToken.Headers[0].KeyID == "" {
		return nil, errors.WithMessage(errInvalidTokenSignatureKey, "validateJWT: invalid header")
	}

	publicKey, err := client.getPublicKey(webToken.Headers[0].KeyID)
	if err != nil {
		return nil, errors.WithMessage(err, "validateJWT: invalid key")
	}

	err = webToken.Claims(publicKey, &jwtClaims)
	if err != nil {
		return nil, errors.Wrap(err, "validateJWT: unable to deserialize JWT claims")
	}

	err = jwtClaims.Validate()
	if err != nil {
		if err == jwt.ErrExpired {
			return nil, errTokenExpired
		}
		return nil, errors.Wrap(err, "validateJWT: unable to validate JWT")
	}

	return &jwtClaims, nil
}

func (client *DefaultClient) tokenRevoked(token string) bool {
	client.revocationFilterMutex.RLock()
	defer client.revocationFilterMutex.RUnlock()

	return client.revocationFilter.MightContain([]byte(token))
}

func (client *DefaultClient) userRevoked(userID string, issuedAt int64) bool {
	revokedAt, _ := client.getRevokedUserSafe(userID)
	return revokedAt.Unix() >= issuedAt
}

func (client *DefaultClient) refreshAccessToken(rootSpan opentracing.Span) (time.Duration, error) {
	span := jaeger.StartChildSpan(rootSpan, "client.refreshAccessToken")
	defer jaeger.Finish(span)

	var tokenRefreshInterval time.Duration

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime

	err := backoff.Retry(
		func() error {
			var e error

			reqSpan := jaeger.StartChildSpan(span, "client.refreshAccessToken.Retry")
			defer jaeger.Finish(reqSpan)

			tokenRefreshInterval, e = client.clientTokenGrant(reqSpan)
			if e != nil {
				jaeger.TraceError(reqSpan, e)
				return e
			}

			return nil
		},
		b,
	)
	if err != nil {
		jaeger.AddLog(span, "msg", "refreshAccessToken: client token refreshed")
		log("refreshAccessToken: client token refreshed")
	}

	client.tokenRefreshError.Store(err)

	return tokenRefreshInterval, err
}

func (client *DefaultClient) spawnRefreshAccessTokenScheduler(rootSpan opentracing.Span) {
	span := jaeger.StartChildSpan(rootSpan, "client.spawnRefreshAccessTokenScheduler")
	defer jaeger.Finish(span)

	for {
		tokenRefreshInterval, err := client.refreshAccessToken(span)
		if err != nil {
			continue
		}

		jaeger.AddLog(span, "msg", "refreshAccessToken: client token refreshed")
		log("refreshAccessToken: client token refreshed")
		time.Sleep(tokenRefreshInterval)
	}
}

// nolint: funlen, dupl
func (client *DefaultClient) clientTokenGrant(rootSpan opentracing.Span) (time.Duration, error) {
	span := jaeger.StartChildSpan(rootSpan, "client.clientTokenGrant")
	defer jaeger.Finish(span)

	form := url.Values{}
	form.Add("grant_type", "client_credentials")

	req, err := http.NewRequest(
		http.MethodPost,
		client.config.BaseURL+grantPath,
		bytes.NewBufferString(form.Encode()),
	)
	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "clientTokenGrant: unable to create new HTTP request"))
		return 0, errors.Wrap(err, "clientTokenGrant: unable to create new HTTP request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.config.ClientID, client.config.ClientSecret)

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime

	var responseStatusCode int

	var responseBodyBytes []byte

	err = backoff.
		Retry(
			func() error {
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
					return errors.Errorf("clientTokenGrant: endpoint returned status code : %v", responseStatusCode)
				}

				responseBodyBytes, e = ioutil.ReadAll(resp.Body)
				if e != nil {
					jaeger.TraceError(reqSpan, fmt.Errorf("Body.ReadAll: %s", e))
					return errors.Wrap(e, "clientTokenGrant: unable to read response body")
				}

				return nil
			},
			b,
		)

	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "clientTokenGrant: unable to do HTTP request"))
		return 0, errors.Wrap(err, "clientTokenGrant: unable to do HTTP request")
	}

	if responseStatusCode != http.StatusOK {
		jaeger.TraceError(
			span,
			errors.Errorf(
				"clientTokenGrant: unable to grant client token: error code : %d, error message : %s",
				responseStatusCode,
				string(responseBodyBytes),
			),
		)

		return 0, errors.Errorf("clientTokenGrant: unable to grant client token: error code : %d, error message : %s",
			responseStatusCode, string(responseBodyBytes))
	}

	var tokenResponse *TokenResponse

	err = json.Unmarshal(responseBodyBytes, &tokenResponse)
	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "clientTokenGrant: unable to unmarshal response body"))
		return 0, errors.Wrap(err, "clientTokenGrant: unable to unmarshal response body")
	}

	client.clientAccessToken.Store(tokenResponse.AccessToken)
	refreshInterval := time.Duration(float64(tokenResponse.ExpiresIn)*defaultTokenRefreshRate) * time.Second

	return refreshInterval, nil
}

// nolint: funlen, dupl
func (client *DefaultClient) clientDelegateTokenGrant(extendNamespace string, rootSpan opentracing.Span) (token string, ttl *time.Duration, err error) {
	span := jaeger.StartChildSpan(rootSpan, "client.clientDelegateTokenGrant")
	defer jaeger.Finish(span)

	form := url.Values{}
	form.Add("grant_type", "urn:ietf:params:oauth:grant-type:extend_client_credentials")
	form.Add("extendNamespace", extendNamespace)

	req, err := http.NewRequest(
		http.MethodPost,
		client.config.BaseURL+grantPath,
		bytes.NewBufferString(form.Encode()),
	)
	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "clientDelegateTokenGrant: unable to create new HTTP request"))
		return "", nil, errors.Wrap(err, "clientDelegateTokenGrant: unable to create new HTTP request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.config.ClientID, client.config.ClientSecret)

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime

	var responseStatusCode int

	var responseBodyBytes []byte

	err = backoff.
		Retry(
			func() error {
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
					return errors.Errorf("clientDelegateTokenGrant: endpoint returned status code : %v", responseStatusCode)
				}

				responseBodyBytes, e = ioutil.ReadAll(resp.Body)
				if e != nil {
					jaeger.TraceError(reqSpan, fmt.Errorf("Body.ReadAll: %s", e))
					return errors.Wrap(e, "clientDelegateTokenGrant: unable to read response body")
				}

				return nil
			},
			b,
		)

	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "clientDelegateTokenGrant: unable to do HTTP request"))
		return "", nil, errors.Wrap(err, "clientDelegateTokenGrant: unable to do HTTP request")
	}

	if responseStatusCode != http.StatusOK {
		jaeger.TraceError(
			span,
			errors.Errorf(
				"clientDelegateTokenGrant: unable to grant delegate client token: error code : %d, error message : %s",
				responseStatusCode,
				string(responseBodyBytes),
			),
		)

		return "", nil, errors.Errorf("clientDelegateTokenGrant: unable to grant client delegate token: error code : %d, error message : %s",
			responseStatusCode, string(responseBodyBytes))
	}

	var tokenResponse *TokenResponse

	err = json.Unmarshal(responseBodyBytes, &tokenResponse)
	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "clientDelegateTokenGrant: unable to unmarshal response body"))
		return "", nil, errors.Wrap(err, "clientDelegateTokenGrant: unable to unmarshal response body")
	}
	refreshInterval := time.Duration(float64(tokenResponse.ExpiresIn)*defaultTokenRefreshRate) * time.Second
	return tokenResponse.AccessToken, &refreshInterval, nil
}
