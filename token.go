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
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/AccelByte/go-jose/jwt"
	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
)

func (client *DefaultClient) validateAccessToken(accessToken string) (bool, error) {
	form := url.Values{}
	form.Add("token", accessToken)

	req, err := http.NewRequest(http.MethodPost, client.config.BaseURL+verifyPath, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return false, errors.Wrap(err, "validateAccessToken: unable to create new HTTP request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.config.ClientID, client.config.ClientSecret)

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
		return false, errors.Wrap(err, "validateAccessToken: unable to do HTTP request")
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return false, errors.Wrap(errUnauthorized, "validateAccessToken: unauthorized")
	}

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	return true, nil
}

func (client *DefaultClient) validateJWT(token string) (*JWTClaims, error) {
	if token == "" {
		return nil, errors.WithMessage(errEmptyToken, "validateJWT: invalid token")
	}

	var jwtClaims = JWTClaims{}

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
		return nil, errors.Wrap(err, "validateJWT: unable to validate JWT")
	}

	return &jwtClaims, nil
}

func (client *DefaultClient) tokenRevoked(token string) bool {
	return client.revocationFilter.MightContain([]byte(token))
}

func (client *DefaultClient) userRevoked(userID string, issuedAt int64) bool {
	revokedAt := client.revokedUsers[userID]
	return revokedAt.Unix() >= issuedAt
}

func (client *DefaultClient) refreshAccessToken() {
	var tokenRefreshInterval time.Duration
	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime

	for {

		client.tokenRefreshError = backoff.
			Retry(
				func() error {
					var e error

					tokenRefreshInterval, e = client.clientTokenGrant()
					if e != nil {
						return e
					}

					return nil
				},
				b,
			)

		if client.tokenRefreshError != nil {
			continue
		}

		log("refreshAccessToken: client token refreshed")
		time.Sleep(tokenRefreshInterval)
	}
}

func (client *DefaultClient) clientTokenGrant() (time.Duration, error) {
	form := url.Values{}
	form.Add("grant_type", "client_credentials")

	req, err := http.NewRequest(
		http.MethodPost,
		client.config.BaseURL+grantPath,
		bytes.NewBufferString(form.Encode()),
	)
	if err != nil {
		return 0, errors.Wrap(err, "clientTokenGrant: unable to create new HTTP request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.config.ClientID, client.config.ClientSecret)

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
		return 0, errors.Wrap(err, "clientTokenGrant: unable to do HTTP request")
	}

	if resp.StatusCode != http.StatusOK {
		return 0, errors.Wrap(err, "clientTokenGrant: endpoint returned non-OK")
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, errors.Wrap(err, "clientTokenGrant: unable to read response body")
	}

	var tokenResponse *TokenResponse
	err = json.Unmarshal(bodyBytes, &tokenResponse)
	if err != nil {
		return 0, errors.Wrap(err, "clientTokenGrant: unable to unmarshal response body")
	}

	client.clientAccessToken = tokenResponse.AccessToken
	refreshInterval := time.Duration(float64(tokenResponse.ExpiresIn)*defaultTokenRefreshRate) * time.Second
	return refreshInterval, nil
}
