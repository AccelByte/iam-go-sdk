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
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"

	"github.com/AccelByte/go-restful-plugins/v3/pkg/jaeger"
	"github.com/cenkalti/backoff"
	"github.com/opentracing/opentracing-go"
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

func (client *DefaultClient) refreshJWKS(rootSpan opentracing.Span) {
	span := jaeger.StartChildSpan(rootSpan, "client.refreshJWKS")
	defer jaeger.Finish(span)

	backOffTime := time.Second
	time.Sleep(client.config.JWKSRefreshInterval)

	for {
		client.jwksRefreshError = client.getJWKS(span)
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

// nolint: funlen
func (client *DefaultClient) getJWKS(rootSpan opentracing.Span) error {
	span := jaeger.StartChildSpan(rootSpan, "client.getJWKS")
	defer jaeger.Finish(span)

	req, err := http.NewRequest("GET", client.config.BaseURL+jwksPath, nil)
	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "getJWKS: unable to create new JWKS request"))
		return errors.Wrap(err, "getJWKS: unable to create new JWKS request")
	}

	req.SetBasicAuth(client.config.ClientID, client.config.ClientSecret)

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

				resp, e := client.httpClient.Do(req)
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

	client.setKeysSafe(make(map[string]*rsa.PublicKey))

	for i := range jwks.Keys {
		jwk := &jwks.Keys[i]

		key, errGenerate := generatePublicKey(jwk)
		if errGenerate != nil {
			jaeger.TraceError(span, errors.WithMessage(errGenerate, "getJWKS: unable to generate public key"))
			return errors.WithMessage(err, "getJWKS: unable to generate public key")
		}

		client.setKeySafe(jwk.Kid, key)
	}

	return nil
}

func (client *DefaultClient) getPublicKey(keyID string) (*rsa.PublicKey, error) {
	key, ok := client.getKeySafe(keyID)
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
