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
	"time"

	"github.com/AccelByte/bloom"
	"github.com/AccelByte/go-jose/jwt"
	"github.com/gorhill/cronexpr"
)

// Permission action bit flags
const (
	ActionCreate = 1
	ActionRead   = 1 << 1
	ActionUpdate = 1 << 2
	ActionDelete = 1 << 3
)

// TokenResponse is the data structure for the response on successful
// token request.
type TokenResponse struct {
	AccessToken    string       `json:"access_token"`
	RefreshToken   string       `json:"refresh_token"`
	ExpiresIn      int          `json:"expires_in"`
	TokenType      string       `json:"token_type"`
	Roles          []string     `json:"roles"`
	Permissions    []Permission `json:"permissions"`
	Bans           []JWTBan     `json:"bans"`
	UserID         string       `json:"user_id"`
	PlatformID     string       `json:"platform_id,omitempty"`
	PlatformUserID string       `json:"platform_user_id,omitempty"`
	JusticeFlags   int          `json:"jflgs,omitempty"`
	DisplayName    string       `json:"display_name"`
	Namespace      string       `json:"namespace"`
}

// Permission holds information about the actions can be performed to the resource.
// Action is a bit flag of CREATE READ UPDATE and DELETE.
// Schedule is a string in quartz compatible cron syntax that
// is using github.com/gorhill/cronexpr to parse.
// in range type, first element will be start date, and second one will be end date
type Permission struct {
	Resource        string
	Action          int
	ScheduledAction int      `json:"SchedAction,omitempty"`
	CronSchedule    string   `json:"SchedCron,omitempty"`
	RangeSchedule   []string `json:"SchedRange,omitempty"`
}

// IsScheduled checks if the schedule is
// active at current time
func (perm Permission) IsScheduled() bool {
	ok := false
	if len(perm.CronSchedule) > 0 {
		ok = perm.isRecurring()
	}
	if ok {
		return ok
	}

	if len(perm.RangeSchedule) > 0 {
		ok = perm.isInRange()
	}

	return ok
}

func (perm Permission) isRecurring() bool {
	expression, err := cronexpr.Parse(perm.CronSchedule)
	if err != nil {
		return true
	}

	now := time.Now()
	nextTime := expression.Next(now)

	if nextTime.IsZero() || nextTime.Sub(now) > time.Second {
		return false
	}

	return true
}

func (perm Permission) isInRange() bool {
	start, errStart := cronexpr.Parse(perm.RangeSchedule[0])
	end, errEnd := cronexpr.Parse(perm.RangeSchedule[1])
	if errStart != nil || errEnd != nil {
		return true
	}

	now := time.Now()
	nextStart := start.Next(now)
	nextEnd := end.Next(now)

	if !nextStart.IsZero() && nextStart.Sub(now) > time.Second {
		return false
	}
	if nextEnd.IsZero() {
		return false
	}

	return true
}

// Role holds info about a user role.
type Role struct {
	RoleID      string `json:"RoleId"`
	RoleName    string
	Permissions []Permission
}

// JWTClaims holds data stored in a JWT access token with additional Justice Flags field
type JWTClaims struct {
	Namespace    string       `json:"namespace"`
	DisplayName  string       `json:"display_name"`
	Roles        []string     `json:"roles"`
	Permissions  []Permission `json:"permissions"`
	Bans         []JWTBan     `json:"bans"`
	JusticeFlags int          `json:"jflgs"`
	Scope        string       `json:"scope"`
	Country      string       `json:"country"`
	ClientID     string       `json:"client_id"`
	jwt.Claims
}

// Validate checks if the JWT is still valid
func (c *JWTClaims) Validate() error {
	return c.Claims.Validate(jwt.Expected{
		Time: time.Now().UTC(),
	})
}

// RevocationList contains revoked user and token
type RevocationList struct {
	RevokedTokens bloom.FilterJSON           `json:"revoked_tokens"`
	RevokedUsers  []UserRevocationListRecord `json:"revoked_users"`
}

// UserRevocationListRecord is used to store revoked user data
type UserRevocationListRecord struct {
	ID        string    `json:"id" bson:"id"`
	RevokedAt time.Time `json:"revoked_at" bson:"revoked_at"`
}

// JWTBan holds information about ban record in JWT
type JWTBan struct {
	Ban     string    `json:"ban"`
	EndDate time.Time `json:"end_date"`
}
