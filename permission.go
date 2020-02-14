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
	"strings"

	"github.com/AccelByte/go-restful-plugins/v3/pkg/jaeger"
	"github.com/cenkalti/backoff"
	"github.com/opentracing/opentracing-go"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
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

func (client *DefaultClient) getRolePermission(roleID string, rootSpan opentracing.Span) ([]Permission, error) {
	span := jaeger.StartChildSpan(rootSpan, "client.getRolePermission")
	defer jaeger.Finish(span)

	if cachedRolePermission, found := client.rolePermissionCache.Get(roleID); found {
		return cachedRolePermission.([]Permission), nil
	}

	req, err := http.NewRequest("GET", client.config.BaseURL+getRolePath+"/"+roleID, nil)
	if err != nil {
		return nil, errors.Wrap(err, "getRolePermission: unable to create new HTTP request")
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+client.clientAccessToken)

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime
	resp := &http.Response{}

	err = backoff.
		Retry(
			func() error {
				var e error

				reqSpan := jaeger.StartChildSpan(span, "HTTP Request: "+req.Method+" "+req.URL.Path)
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
		jaeger.TraceError(span, errors.Wrap(err, "getRolePermission: unable to do HTTP request"))
		return nil, errors.Wrap(err, "getRolePermission: unable to do HTTP request")
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// do nothing
	case http.StatusUnauthorized:
		jaeger.TraceError(span, errors.Wrap(errUnauthorized, "getRolePermission: unauthorized"))
		return nil, errors.Wrap(errUnauthorized, "getRolePermission: unauthorized")
	case http.StatusForbidden:
		jaeger.TraceError(span, errors.Wrap(errForbidden, "getRolePermission: forbidden"))
		return nil, errors.Wrap(errForbidden, "getRolePermission: forbidden")
	case http.StatusNotFound:
		jaeger.TraceError(span, errors.Wrap(errRoleNotFound, "getRolePermission: not found"))
		return nil, errors.Wrap(errRoleNotFound, "getRolePermission: not found")
	default:
		jaeger.TraceError(span, errors.New("unexpected error: "+http.StatusText(resp.StatusCode)))
		return nil, errors.New("unexpected error: " + http.StatusText(resp.StatusCode))
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "getRolePermission: unable to read response body"))
		return nil, errors.Wrap(err, "getRolePermission: unable to read response body")
	}

	var role Role
	err = json.Unmarshal(bodyBytes, &role)
	if err != nil {
		jaeger.TraceError(span, errors.Wrap(err, "getRolePermission: unable to unmarshal response body"))
		return nil, errors.Wrap(err, "getRolePermission: unable to unmarshal response body")
	}

	client.rolePermissionCache.Set(roleID, role.Permissions, cache.DefaultExpiration)

	return role.Permissions, nil
}
