Release v2.9.0 (unreleased)
===========================
### Added
1. `WithContext(ctx)` option, which sets the parent context for the client's tracing spans

### Deprecated
1. `WithJaegerContext(ctx)`. Use `WithContext(ctx)`, which behaves the same. The option isn't specific to Jaeger

### Fixed
1. `StartLocalValidation` and the JWKS refresh stopped loading keys at the first key that couldn't be parsed and still reported success. The client now skips that key, logs it, and loads the rest
2. A JWKS key whose exponent was longer than 8 bytes made the client panic, which crashed the application when it happened in the background refresh. Keys `crypto/rsa` can't verify with were stored anyway, and could replace a usable key with the same `kid`. The client now skips a key, with a logrus warning, unless its exponent is odd and from 3 to 2^31-1, its modulus is odd and greater than 1, its `kty` is `RSA` or missing, and its `use` is `sig` or missing (compared without case). The minimum key size is left to `crypto/rsa`, so a key that's too small is still stored
3. Data race: the JWKS and revocation-list refresh errors and the local-validation flag were read by `HealthCheck` and token validation while the background refreshes wrote them
4. The client token refresh logged "client token refreshed" only when the refresh failed
5. Tracing: `GetRolePermissions` never finished its span; `ValidateAudience` and `GetClientInformation` didn't pass the trace context on to the client-information request; retried permission requests weren't children of their retry span; several spans had another method's name (`ValidateAndParseClaims`, `ValidatePermission`, `ValidateRole`, `UserPhoneVerificationStatus`, `ValidateScope` and the revocation-list refresh); and the `error` tag was the string `"true"` instead of the boolean the OpenTracing convention uses

### Changed behaviour
1. The SDK no longer sets the global logrus formatter. Importing `go-restful-plugins/v3` used to run its `pkg/logger/event` `init()`, which calls `logrus.SetFormatter` with a UTC, millisecond-timestamp text formatter. An application that relied on that side effect, and doesn't import `go-restful-plugins` itself, should call `logrus.SetFormatter` on its own

### Modified
1. Require Go 1.26.0 (`go 1.26.0` in `go.mod`)
2. Remove the dependency on `github.com/AccelByte/go-restful-plugins/v3`. The OpenTracing span helpers now live in an internal package, so the client no longer pulls in the Jaeger client or `github.com/emicklei/go-restful`. Spans still go to the tracer registered with `opentracing.SetGlobalTracer`
3. Remove `docker-compose.yml` and `docker-compose-test.yml`, which only ran a Jaeger agent for the tests. The tests now record spans with OpenTracing's in-memory `mocktracer`
4. Update `github.com/AccelByte/go-jose` to v2.1.5
5. Update dependencies: `golang.org/x/crypto` v0.58.0, `golang.org/x/sys` v0.49.0, `github.com/sirupsen/logrus` v1.9.3, `github.com/google/uuid` v1.6.0, `github.com/opentracing/opentracing-go` v1.2.0, `github.com/pkg/errors` v0.9.1, `go.uber.org/atomic` v1.11.0, `github.com/stretchr/testify` v1.11.1

Release v2.5.1 (2024-09-11)
===========================
### Modified
1. Fix permission issue in v2.5.0

Release v2.5.0 (2024-07-25)
===========================
### Added
1. Support role override permission feature
2. This version depends on IAM version 7.20.0 and above (AGS version >=3.77 )

Release v2.4.2 (2024-02-06)
===========================
### Modified
1. Add `sp` to token claims

Release v2.4.1 (2024-01-24)
===========================
### Modified
1. Fix the permission check logic for role assignment `{studio}-`

Release v2.4.0 (2024-01-23)
===========================
### Modified
1. adjust new game namespace ```{studio}-{game}```

Release v2.3.0 (2024-01-12)
===========================
### Modified
1. Update permission check logic to support latest namespace roles format ```{studio}+```
2. this version need following config if in multi-tenant:
   * default basic service base url is: ```http://justice-basic-service/basic```, can be overridden by setting `Config/BasicBaseURL`
   * client permission should include: ```action: 2 resource: ADMIN:NAMESPACE:*:NAMESPACE```


Release v2.2.1 (2023-11-10)
===========================
### Added
1. Support delegate token grant & update claim to include extend_namespace

Release v2.0.0 (2023-04-11)
===========================
### Modified
1. Upgrade to use IAM v3 version 
* Required Permission:
  * (required) `ADMIN:ROLE [READ]`

Release v1.9.1 (2023-03-31)
===========================
### Modified
1. Add union_id & union_namespace to JWTClaims

Release v1.7.1 (2022-03-29)
===========================
### Modified
1. Add custom redirectURI on GetClientInformation mock

Release v1.7.0 (2021-05-11)
===========================
### Added
1. Expose GetClientInformation method as interface

### Fixed
1. refreshAccessToken that blocking the request

Release v1.5.0 (2021-03-10)
===========================
### Added
1. Expose GetRolePermission method as interface

Release v1.4.0 (2020-09-10)
===========================
### Changed
1. When the granted permission ends with wildcard, check if the wildcard
   only applies to matches any namspace and user, or the wildcard should
   match any resources after the namespace and user

### Fixed
1. Sync changelog file with github release version

Release v1.3.4 (2020-03-13)
===========================
### Fixed
1. Fix null pointer dereference

Release v1.3.3 (2020-03-11)
===========================
### Fixed
1. Upgrade dependencies and remove cached library

Release v1.3.2 (2020-03-10)
===========================
### Fixed
1. Fix wrapping error with nil value

Release v1.3.1 (2020-03-10)
===========================
### Changed
1. Support backward compatibility for permission checking with `roles` field

Release v1.3.0 (2020-03-02)
===========================
### Changed
1. Change permission checking (ValidatePermission) with allowed namespace / namespace roles field

Release v1.2.0 (2020-02-27)
===========================
### Added
1. Implement jaeger tracing

Release v1.1.4 (2020-02-20)
===========================
### Fixed
1. Fix return of role permissions

Release v1.1.3 (2019-11-04)
===========================
### Fixed
1. Fix json tag in JWTBan

Release v1.1.2 (2019-10-02)
===========================
### Changed
1. Update Client response field into camelCase

Release v1.1.1 (2019-07-28)
===========================
### Added
1. Enable automatically refresh the token when receiving 401 when calling IAM service
2. Added retry when receiving 500 from IAM
3. Added debug flag in config to toggle logging debug messages

Release v1.1.0 (2019-07-28)
===========================
### Added
1. No checking if no `aud` field found in the token.
2. Write unit tests for making sure `ValidateAudience` works as expected.

Release v1.0.7 (2019-07-26)
===========================
### Fixed
1. Fix audience validation in mock client

Release v1.0.6 (2019-07-25)
===========================
### Changed
1. Separate audience and scope validation 

Release v1.0.5 (2019-07-24)
===========================
### Fixed
1. Fix scope validation

Release v1.0.4 (2019-07-23)
===========================
### Added
1. Add audience and scope validation

Release v1.0.3 (2019-04-23)
===========================
### Fixed
1. Fixed misconfiguration during permission validation

Release v1.0.2 (2019-03-11)
===========================
### Fixed
1. Fixed JWT validation

Release v1.0.1 (2019-03-07)
===========================
### Changed
1. Use go modules for dependency management

Release v1.0.0 (2019-03-06)
===========================
### Changed
1. Use `go-jose` for JWT handling

Release v0.1.0 (2019-02-02)
===========================
### Notes
Stable version using `jwt-go`

### Fixed
1. Missing key ID handling
