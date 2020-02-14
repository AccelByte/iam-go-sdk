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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/AccelByte/bloom"
	"github.com/AccelByte/go-restful-plugins/v3/pkg/jaeger"
	"github.com/cenkalti/backoff"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
)

func (client *DefaultClient) refreshRevocationList(rootSpan opentracing.Span) {
	span := jaeger.StartChildSpan(rootSpan, "client.refreshJWKS")
	defer jaeger.Finish(span)

	time.Sleep(client.config.RevocationListRefreshInterval)
	backOffTime := time.Second
	for {
		client.revocationListRefreshError = client.getRevocationList(span)
		if client.revocationListRefreshError != nil {
			time.Sleep(backOffTime)
			if backOffTime < maxBackOffTime {
				backOffTime *= 2
			}
			continue
		}
		backOffTime = time.Second
		time.Sleep(client.config.RevocationListRefreshInterval)
	}
}

func (client *DefaultClient) getRevocationList(rootSpan opentracing.Span) error {
	span := jaeger.StartChildSpan(rootSpan, "client.getRevocationList")
	defer jaeger.Finish(span)

	req, err := http.NewRequest(http.MethodGet, client.config.BaseURL+revocationListPath, nil)
	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "getRevocationList: unable to make new HTTP request"))
		return errors.Wrap(err, "getRevocationList: unable to make new HTTP request")
	}

	req.SetBasicAuth(client.config.ClientID, client.config.ClientSecret)

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime
	resp := &http.Response{}

	err = backoff.
		Retry(
			func() error {
				var e error

				reqSpan := jaeger.StartChildSpan(span, "client.getRevocationList.Retry")
				defer jaeger.Finish(reqSpan)
				jaeger.InjectSpanIntoRequest(reqSpan, req)

				resp, e = client.httpClient.Do(req)

				if e != nil {
					return backoff.Permanent(e)
				}

				if resp.StatusCode >= http.StatusInternalServerError {
					jaeger.TraceError(reqSpan, fmt.Errorf("StatusCode: %v", resp.StatusCode))
					return e
				}

				return nil
			},
			b,
		)

	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "getRevocationList: unable to do HTTP request"))
		return errors.Wrap(err, "getRevocationList: unable to do HTTP request")
	}

	if resp.StatusCode != http.StatusOK {
		jaeger.TraceError(span, errors.Wrap(err, "getRevocationList: endpoint returned non-OK"))
		return errors.Wrap(err, "getRevocationList: endpoint returned non-OK")
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "getRevocationList: unable to read HTTP response body"))
		return errors.Wrap(err, "getRevocationList: unable to read HTTP response body")
	}

	var revocationList *RevocationList
	err = json.Unmarshal(bodyBytes, &revocationList)
	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "getRevocationList: unable to unmarshal response body"))
		return errors.Wrap(err, "getRevocationList: unable to unmarshal response body")
	}

	client.revokedUsers = make(map[string]time.Time)
	client.revocationFilter = bloom.From(revocationList.RevokedTokens.B, revocationList.RevokedTokens.K)
	for _, revokedUser := range revocationList.RevokedUsers {
		client.revokedUsers[revokedUser.ID] = revokedUser.RevokedAt
	}
	return nil
}
