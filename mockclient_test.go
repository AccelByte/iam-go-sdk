// Copyright 2021 AccelByte Inc
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
	"testing"

	jose "github.com/AccelByte/go-jose"
	"github.com/AccelByte/go-jose/jwt"
	"github.com/AccelByte/go-restful-plugins/v3/pkg/jaeger"
	"github.com/stretchr/testify/assert"
)

var (
	testMockClient *MockClient
	mockSigner     jose.Signer
)

func init() {
	jaeger.InitGlobalTracer(jaegerAgentHost, "", "test", "")

	var err error

	mockSigner, err = jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.HS256,
			Key:       []byte(MockSecret),
		},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(err)
	}
}

func Test_MockClientValidateAndParseClaims(t *testing.T) {
	t.Parallel()

	payload := &tokenUserData{
		Namespace: "Accelbyte",
		UserID:    "e9b1ed0c1a3d473cd970abc845b51d3a",
		ClientID:  "ea192a6c74404de4a105f0c4882325ce",
	}

	claims := generateClaims(t, payload)

	accessToken, err := jwt.Signed(mockSigner).Claims(claims).CompactSerialize()
	if err != nil {
		panic(err)
	}

	claims, errValidateAndParseClaims := testMockClient.ValidateAndParseClaims(accessToken)

	assert.Nil(t, errValidateAndParseClaims, "access token is invalid")
	assert.NotNil(t, claims, "claims should not nil")
	assert.Equal(t, payload.Namespace, claims.Namespace, "namespace should be equal")
	assert.Equal(t, payload.UserID, claims.Subject, "userID should be equal")
	assert.Equal(t, payload.ClientID, claims.ClientID, "clientID should be equal")
	assert.ElementsMatch(t, claims.Permissions, []Permission{
		{Resource: "MOCK", Action: ActionCreate | ActionRead | ActionUpdate | ActionDelete},
	})

	if len(claims.Audience) == 1 {
		assert.Equal(t, MockAudience, claims.Audience[0], "audience should be equal")
	} else {
		assert.Fail(t, "audience size isn't match")
	}

	if len(claims.Roles) == 1 {
		assert.Equal(t, MockForbidden, claims.Roles[0], "roles should be equal")
	} else {
		assert.Fail(t, "roles size isn't match")
	}

	if len(claims.Permissions) == 1 {
		assert.Equal(t, "MOCK", claims.Permissions[0].Resource, "permissions resource should be equal")
		assert.Equal(t, ActionCreate|ActionRead|ActionUpdate|ActionDelete, claims.Permissions[0].Action,
			"permissions action should be equal")
	} else {
		assert.Fail(t, "permissions size isn't match")
	}
}

func Test_MockClientValidateAndParseClaims_EmptyPayload(t *testing.T) {
	t.Parallel()

	payload := &tokenUserData{}

	claims := generateClaims(t, payload)

	accessToken, err := jwt.Signed(mockSigner).Claims(claims).CompactSerialize()
	if err != nil {
		panic(err)
	}

	claims, errValidateAndParseClaims := testMockClient.ValidateAndParseClaims(accessToken)

	assert.Nil(t, errValidateAndParseClaims, "access token is invalid")
	assert.NotNil(t, claims, "claims should not nil")
	assert.Equal(t, payload.Namespace, claims.Namespace, "namespace should be equal")
	assert.Equal(t, accessToken, claims.Subject, "subject should be equal with access token")
	assert.Equal(t, payload.ClientID, claims.ClientID, "clientID should be equal")

	if len(claims.Audience) == 1 {
		assert.Equal(t, MockAudience, claims.Audience[0], "audience should be equal")
	} else {
		assert.Fail(t, "audience size isn't match")
	}

	if len(claims.Roles) == 1 {
		assert.Equal(t, MockForbidden, claims.Roles[0], "roles should be equal")
	} else {
		assert.Fail(t, "roles size isn't match")
	}

	if len(claims.Permissions) == 1 {
		assert.Equal(t, "MOCK", claims.Permissions[0].Resource, "permissions resource should be equal")
		assert.Equal(t, ActionCreate|ActionRead|ActionUpdate|ActionDelete, claims.Permissions[0].Action,
			"permissions action should be equal")
	} else {
		assert.Fail(t, "permissions size isn't match")
	}
}
