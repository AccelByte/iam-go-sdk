// Copyright 2019 AccelByte Inc
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

import "errors"

// nolint: lll
var (
	errUnauthorized             = errors.New("access unauthorized, make sure you have valid client access token using ClientTokenGrant")
	errForbidden                = errors.New("access forbidden, make sure you have client creds that has sufficient permission")
	errUserRevoked              = errors.New("user has been revoked")
	errTokenRevoked             = errors.New("token has been revoked")
	errNilClaim                 = errors.New("claims is nil")
	errInvalidAud               = errors.New("audience doesn't match the client's base uri. access denied")
	errInvalidScope             = errors.New("insufficient scope")
	errEmptyToken               = errors.New("token is empty")
	errInvalidTokenSignatureKey = errors.New("invalid token signature key ID")
	errRoleNotFound             = errors.New("role not found")
	errNoLocalValidation        = errors.New("local validation is not active, activate by calling StartLocalValidation()")
	errTokenExpired             = errors.New("token is expired")
)
