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
