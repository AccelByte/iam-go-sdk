// Copyright 2024 AccelByte Inc
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
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

const (
	getNamespaceContextPath = "%s/v1/admin/namespaces/%s/context?activeOnly=%v"
	NamespaceTypeGame       = "Game"
)

var ErrNamespaceNotFound = errors.New("namespace not found")

type ErrorRes struct {
	ErrorCode int64 `json:"errorCode"`
}

type NamespaceContext struct {
	NotFound        bool   `json:"-"`
	Type            string `json:"type"`
	StudioNamespace string `json:"studioNamespace"`
}

func (client *DefaultClient) getNamespaceContext(namespace string) (context *NamespaceContext, err error) {
	getNamespaceURL := fmt.Sprintf(getNamespaceContextPath, client.config.BasicBaseURL, namespace, true)
	// nolint:noctx
	req, err := http.NewRequest(http.MethodGet, getNamespaceURL, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to generate request: %v", err)
	}

	req.Header.Add("Authorization", "Bearer "+client.ClientToken())
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to perform http request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, errReadBody := ioutil.ReadAll(resp.Body)
		if errReadBody != nil {
			logrus.Warnf("unable to read response body: %v", errReadBody)
		}
		basicErr := &ErrorRes{}
		jsonErr := json.Unmarshal(respBody, &basicErr)
		if jsonErr == nil {
			if basicErr.ErrorCode == 11337 {
				return nil, ErrNamespaceNotFound
			}
		}
		return nil, fmt.Errorf("failed with code: %v, response body: %s", resp.StatusCode, string(respBody))
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}
	var namespaceContext NamespaceContext
	if err = json.Unmarshal(bodyBytes, &namespaceContext); err != nil {
		return nil, fmt.Errorf("unable to unmarshal response body: %v", err)
	}
	return &namespaceContext, nil
}
