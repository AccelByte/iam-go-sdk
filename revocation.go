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
)

func (client *DefaultClient) refreshRevocationList() {
	time.Sleep(client.config.RevocationListRefreshInterval)
	backOffTime := time.Second
	for {
		client.revocationListRefreshError = client.getRevocationList()
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

func (client *DefaultClient) getRevocationList() error {
	req, err := http.NewRequest(http.MethodGet, client.config.BaseURL+revocationListPath, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(client.config.ClientID, client.config.ClientSecret)
	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var revocationList *RevocationList
	err = json.Unmarshal(bodyBytes, &revocationList)
	if err != nil {
		return fmt.Errorf("unable to unmarshal response body: %v", err)
	}

	client.revokedUsers = make(map[string]time.Time)
	client.revocationFilter = bloom.From(revocationList.RevokedTokens.B, revocationList.RevokedTokens.K)
	for _, revokedUser := range revocationList.RevokedUsers {
		client.revokedUsers[revokedUser.ID] = revokedUser.RevokedAt
	}
	return nil
}
