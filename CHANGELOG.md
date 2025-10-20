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
