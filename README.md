[![Build Status](https://travis-ci.com/AccelByte/iam-go-sdk.svg?branch=master)](https://travis-ci.com/AccelByte/iam-go-sdk)

# IAM Go SDK

This is AccelByte's IAM Go SDK for integrating with IAM in Go projects.

## Usage

### Importing package

```go
import "github.com/AccelByte/iam-go-sdk"
```

### Creating default IAM client

```go
cfg := &iam.Config{
    BaseURL: "<IAM URL>",
    ClientID: "<client ID>",
    ClientSecret: "<client secret>",
}

client := iam.NewDefaultClient(cfg)
```

It's recommended that you store the **interface** rather than the type since it enables you to mock the client during tests.

```go
var client iam.Client

client := iam.NewDefaultClient(cfg)
```

So during tests, you can replace the `client` with:

```go
var client iam.Client

client := iam.NewMockClient() // or create your own mock implementation that suits your test case
```

**Note**

By default, the client can only do token validation by requesting to IAM service.

To enable local validation, you need to call:

```go
client.StartLocalValidation()
```

Then the client will automatically get JWK and revocation list and refreshing them periodically.
This enables you to do local token validation and JWT claims parsing.

However, if you need to validate permission, you'll need to call `ClientTokenGrant()` to retrieve client access token that will be used as bearer token when requesting role details to IAM service.

Calling `ClientTokenGrant()` once will automatically trigger periodic token refresh.

```go
client.ClientTokenGrant()
```

### Validating token

#### Validating locally using downloaded JWK and revocation list:

```go
claims, _ := client.ValidateAndParseClaims(accessToken)
```

**Note**

Store the `claims` output if you need to validate it's permission, role, or other properties.

#### Validating by sending request to IAM service:

```go
ok, _ := client.ValidateAccessToken(accessToken)
```

### Validating permission

For example, you have a resource permission that needs `NAMESPACE:{namespace}:USER:{userId}` resource string and `4 [UPDATE]` action to access.

Using `claims` you can verify if the token owner is allowed to access the resource by:

```go
permissionResource := make(map[string]string)
permissionResource["{namespace}"] = "example"
permissionResource["{userId}"] = "example"
client.ValidatePermission(claims, iam.Permission{Resource:"NAMESPACE:{namespace}:USER:{userId}", Action:4}, permissionResource)
```

### Validating Audience

Validate audience from token owner with client baseURI

```go
_ = client.ValidateAudience(claims *JWTClaims) error
```

**Note**

Required client access token to get client information (client base URI)

### Validating Scope

Validate scope from token owner with client scope

```go
_ = client.ValidateScope(claims *JWTClaims, scope string) error
```

### Health check

Whenever the IAM service went unhealthy, the client will know by detecting if any of the automated refresh goroutines has error.

You can check the health by:

```go
client.HealthCheck()
```
