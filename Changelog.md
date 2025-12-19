# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.5] - 2025-12-19

### Added

- Policy version tracking support (compatible with Treetop REST API ≥ 0.0.12):
  - `PolicyVersion` dataclass with `hash` (SHA-256 of policy text) and `loaded_at` (timezone-aware datetime)
  - `CheckResponse.version` field (optional, `None` for older API versions)
  - `version_hash()` and `version_loaded_at()` helper methods for safe access to version data
- `Decision` enum (`ALLOW`, `DENY`) for type-safe decision handling
- Backward compatibility with Treetop REST API < 0.0.12 (versions without policy tracking)

### Changed

- **BREAKING**: `CheckResponse.decision` and `CheckResponseBrief.decision` now use `Decision` enum instead of string literals
- `PolicyVersion.loaded_at` is now a `datetime` object instead of a string (automatically parses ISO 8601 timestamps)
- Updated README examples to demonstrate `Decision` enum usage and version tracking

## [0.0.4] - 2025-12-04

### Added

- `__str__` methods to `QualifiedId`, `Group`, `Action`, and `User` classes for better string representation.
- Automatic type conversion for `ResourceAttribute`: BOOLEAN values are converted to actual booleans and NUMBER values to floats in API calls.

### Changed

- Updated `Resource.new()` method signature to use `dict[str, ResourceAttribute]` for attributes instead of `dict[str, Any]`.
- Updated README examples to demonstrate the new `ResourceAttribute` API with `ResourceAttributeType`.

## [0.0.3] - 2025-09-01

### Fixed

- Removed debug print statements.
- Updated to the new flatter API format from Treetop Core 0.0.11 onwards. Backwards compatibility is *not* retained.

## [0.0.2] - 2025-07-28

### Added

- This Changelog.
- Support for Correlation IDs in requests.

## [0.0.1] - 2025-07-11

### Added

- Initial release.
