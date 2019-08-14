// Copyright (c) 2019 AccelByte Inc. All Rights Reserved.
// This is licensed software from AccelByte Inc, for limitations
// and restrictions contact your company contract manager.

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
)
