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
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
)

var jwtEncoding = base64.URLEncoding.WithPadding(base64.NoPadding)

// JWK contains json web key's data
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// Keys contains json web keys
type Keys struct {
	Keys []JWK `json:"keys"`
}

func (client *DefaultClient) refreshJWKS() {
	backOffTime := time.Second
	time.Sleep(client.config.JWKSRefreshInterval)
	for {
		client.jwksRefreshError = client.getJWKS()
		if client.jwksRefreshError != nil {
			time.Sleep(backOffTime)
			if backOffTime < maxBackOffTime {
				backOffTime *= 2
			}
			continue
		}
		backOffTime = time.Second
		time.Sleep(client.config.JWKSRefreshInterval)
	}
}

func (client *DefaultClient) getJWKS() error {
	req, err := http.NewRequest("GET", client.config.BaseURL+jwksPath, nil)
	if err != nil {
		return errors.Wrap(err, "getJWKS: unable to create new JWKS request")
	}

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
		return errors.Wrap(err, "getJWKS: unable to do HTTP request to get JWKS")
	}

	if resp.StatusCode != http.StatusOK {
		return errors.Wrap(err, "getJWKS: endpoint returned non-OK")
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "getJWKS: unable to read response body")
	}

	var jwks Keys
	err = json.Unmarshal(respBody, &jwks)
	if err != nil {
		return errors.Wrap(err, "getJWKS: unable to unmarshal response body")
	}

	client.keys = make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		key, errGenerate := generatePublicKey(&jwk)
		if errGenerate != nil {
			return errors.WithMessage(err, "getJWKS: unable to generate public key")
		}
		client.keys[jwk.Kid] = key
	}

	return nil
}

func (client *DefaultClient) getPublicKey(keyID string) (*rsa.PublicKey, error) {
	key, ok := client.keys[keyID]
	if !ok {
		return nil, errors.New("getPublicKey: public key doesn't exist")
	}
	return key, nil
}

func generatePublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	n, err := getModulus(jwk.N)
	if err != nil {
		return nil, err
	}

	e, err := getPublicExponent(jwk.E)
	if err != nil {
		return nil, err
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func getModulus(jwkN string) (*big.Int, error) {
	decodedN, err := jwtEncoding.DecodeString(jwkN)
	if err != nil {
		return nil, errors.Wrap(err, "getModulus: unable to decode JWK modulus string")
	}
	n := big.NewInt(0)
	n.SetBytes(decodedN)

	return n, nil
}

func getPublicExponent(jwkE string) (int, error) {
	decodedE, err := jwtEncoding.DecodeString(jwkE)
	if err != nil {
		return 0, errors.Wrap(err, "getPublicExponent: unable to decode JWK exponent string")
	}

	var eBytes []byte
	if len(eBytes) < 8 {
		eBytes = make([]byte, 8-len(decodedE), 8)
		eBytes = append(eBytes, decodedE...)
	} else {
		eBytes = decodedE
	}

	eReader := bytes.NewReader(eBytes)
	var e uint64
	err = binary.Read(eReader, binary.BigEndian, &e)
	if err != nil {
		return 0, errors.Wrap(err, "getPublicExponent: unable to read JWK exponent bytes")
	}

	return int(e), nil
}
