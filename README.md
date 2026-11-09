
[![Build Status](https://travis-ci.com/AccelByte/iam-go-sdk.svg?branch=master)](https://travis-ci.com/AccelByte/iam-go-sdk)

# IAM Go SDK

This is AccelByte's IAM Go SDK for integrating with IAM in Go projects.

## Usage

### Import package

```go
import "github.com/AccelByte/iam-go-sdk/v2"
```

### Create default IAM client

```go
cfg := &iam.Config{
    BaseURL: "<IAM URL>",
    BasicBaseURL: "<Basic URL>",
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

During tests, you can replace the `client` with:

```go
var client iam.Client

client := iam.NewMockClient() // or create your own mock implementation that suits your test case
```

**Note**

By default, the client can only do token validation by requesting to the IAM service.

To enable local validation, you need to call:

```go
client.StartLocalValidation()
```

Then, the client will automatically get JWK and the revocation list, refreshing them periodically.
This enables you to do a local token validation and JWT claims parsing.

However, if you need to validate permissions, you'll need to call `ClientTokenGrant()` to retrieve the client access token that will be used as a bearer token when requesting role details to the IAM service.

Calling `ClientTokenGrant()` once will automatically trigger periodic token refresh.

```go
client.ClientTokenGrant()
```

### Validate token

#### Validate locally using downloaded JWK and revocation list

```go
claims, _ := client.ValidateAndParseClaims(accessToken)
```

**Note**

Store the `claims` output if you need to validate it's permission, role, or other properties.

#### Validate by sending a request to IAM service

```go
ok, _ := client.ValidateAccessToken(accessToken)
```

### Validate permission

As an example, assume you have a resource permission that needs `NAMESPACE:{namespace}:USER:{userId}` resource string and `4 [UPDATE]` action to access.

Using `claims`, you can verify if the token owner is allowed to access the resource with:

```go
permissionResource := make(map[string]string)
permissionResource["{namespace}"] = "example"
permissionResource["{userId}"] = "example"
client.ValidatePermission(claims, iam.Permission{Resource:"NAMESPACE:{namespace}:USER:{userId}", Action:4}, permissionResource)
```

### Validate audience

Validate the audience from the token owner with client's base URI:

```go
_ = client.ValidateAudience(claims *JWTClaims) error
```

**Note**

A client access token is required to get client information (client base URI).

### Validate scope

Validate scope from the token owner with the client scope:

```go
_ = client.ValidateScope(claims *JWTClaims, scope string) error
```

### Health check

Whenever the IAM service is unhealthy, the client will know by detecting if any of the automated refresh goroutines have an error.

You can check the health with:

```go
client.HealthCheck()
```

## Tracing

The client creates [OpenTracing](https://github.com/opentracing/opentracing-go) spans through `opentracing.GlobalTracer()` and, where a call has a span, injects the span context into the request it sends to IAM. It doesn't configure a tracer itself:

- If the application registers an OpenTracing tracer with `opentracing.SetGlobalTracer`, the client's spans are recorded by it, and the header format is whatever that tracer uses.
- If no tracer is registered, the spans are no-ops.

The parent span comes from the OpenTracing span in the context passed with `WithContext` (see `opentracing.ContextWithSpan`). The client can't see an OpenTelemetry span in that context, so in an application traced with OpenTelemetry its spans start new traces unless the context also carries an OpenTracing span.

### Tracing usage

Pass the request context with `WithContext` so the client's spans become children of the OpenTracing span in it. The context is used only for tracing: it doesn't cancel or time out the client's requests. `WithJaegerContext` is a deprecated alias of `WithContext` and still works:

```go
// instead of 
validationResult, err := testClient.ValidatePermission(
    claims,
    requiredPermission,
    permissionResources,
)

// use what's received from the request context
validationResult, err := testClient.ValidatePermission(
    claims,
    requiredPermission,
    permissionResources,
    WithContext(ctx),
)

// or an empty context to start a new span
validationResult, err := testClient.ValidatePermission(
    claims,
    requiredPermission,
    permissionResources,
    WithContext(context.Background()),
)
```