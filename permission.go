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
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	cache "github.com/patrickmn/go-cache"
)

func (client *DefaultClient) permissionAllowed(grantedPermissions []Permission, requiredPermission Permission) bool {
	for _, grantedPermission := range grantedPermissions {
		grantedAction := grantedPermission.Action
		if grantedPermission.IsScheduled() {
			grantedAction = grantedPermission.ScheduledAction
		}
		if client.resourceAllowed(grantedPermission.Resource, requiredPermission.Resource) &&
			client.actionAllowed(grantedAction, requiredPermission.Action) {
			return true
		}
	}
	return false
}

func (client *DefaultClient) applyUserPermissionResourceValues(
	grantedPermissions []Permission, claims *JWTClaims) []Permission {
	for i := range grantedPermissions {
		grantedPermissions[i].Resource = strings.Replace(
			grantedPermissions[i].Resource, "{userId}", claims.Subject, -1)
		grantedPermissions[i].Resource = strings.Replace(
			grantedPermissions[i].Resource, "{namespace}", claims.Namespace, -1)
	}
	return grantedPermissions
}

func (client *DefaultClient) resourceAllowed(accessPermissionResource string, requiredPermissionResource string) bool {
	requiredPermResSections := strings.Split(requiredPermissionResource, ":")
	requiredPermResSectionLen := len(requiredPermResSections)
	accessPermResSections := strings.Split(accessPermissionResource, ":")
	accessPermResSectionLen := len(accessPermResSections)

	minSectionLen := accessPermResSectionLen
	if minSectionLen > requiredPermResSectionLen {
		minSectionLen = requiredPermResSectionLen
	}
	for i := 0; i < minSectionLen; i++ {
		userSection := accessPermResSections[i]
		requiredSection := requiredPermResSections[i]
		if userSection != requiredSection && userSection != "*" {
			return false
		}
	}

	if accessPermResSectionLen == requiredPermResSectionLen {
		return true
	}

	if accessPermResSectionLen < requiredPermResSectionLen {
		return accessPermResSections[accessPermResSectionLen-1] == "*"
	}

	for i := requiredPermResSectionLen; i < accessPermResSectionLen; i++ {
		if accessPermResSections[i] != "*" {
			return false
		}
	}
	return true
}

func (client *DefaultClient) actionAllowed(grantedAction int, requiredAction int) bool {
	return grantedAction&requiredAction == requiredAction
}

func (client *DefaultClient) getRolePermission(roleID string) ([]Permission, error) {
	if cachedRolePermission, found := client.rolePermissionCache.Get(roleID); found {
		return cachedRolePermission.([]Permission), nil
	}

	req, err := http.NewRequest("GET", client.config.BaseURL+getRolePath+"/"+roleID, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to create new http request %v", err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+client.clientAccessToken)

	httpClient := http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to do http request %v", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// do nothing
	case http.StatusUnauthorized:
		return nil, errors.New("access unauthorized, make sure you have valid client access token using ClientTokenGrant")
	case http.StatusForbidden:
		return nil, errors.New("access forbidden, make sure you have client creds that has sufficient permission")
	case http.StatusNotFound:
		return nil, errors.New("role not found")
	default:
		return nil, errors.New("unexpected error: " + http.StatusText(resp.StatusCode))
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	var role Role
	err = json.Unmarshal(bodyBytes, &role)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal response body: %v", err)
	}

	client.rolePermissionCache.Set(roleID, role.Permissions, cache.DefaultExpiration)

	return role.Permissions, nil
}
