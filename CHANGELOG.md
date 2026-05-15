# CHANGELOG

As of the 3.6 release [the CHANGELOG is no longer used](https://github.com/opensearch-project/OpenSearch/issues/21071) to generate release notes.
[Use this PR search](https://github.com/opensearch-project/security/pulls?q=sort%3Amerged-desc+is%3Apr+-label%3Askip-changelog+is%3Amerged+base%3Amain+) to browse unreleased changes.

## [Unreleased 3.x]
### Added
- Add `plugins.security.audit.config.log4j.maximum_index_characters_per_message` setting to allow splitting of Log4j audit log messages to keep the `audit_trace_indices` and `audit_trace_resolved_indices` fields below the maximum characters specified. ([5977](https://github.com/opensearch-project/security/pull/5977))

### Changed

### Features

### Enhancements
- Make `plugins.security.dfm_empty_overrides_all` dynamically toggleable ([#6016](https://github.com/opensearch-project/security/pull/6016)
- Cache FLS status information when processing index query cache on a node ([#6044](https://github.com/opensearch-project/security/pull/6044))
- Only update internal compiled privileges configuration when the base config objects have actually changed ([#6037](https://github.com/opensearch-project/security/pull/6037))

### Bug Fixes
- Update RequestContentValidator to only validate fields from request payload and not pre-existing values stored in security index ([#6061](https://github.com/opensearch-project/security/pull/6061))

### Refactoring

### Maintenance
- Bump `gradle-wrapper` from 9.4.0 to 9.4.1 ([#6049](https://github.com/opensearch-project/security/pull/6049))
- Bump `1password/load-secrets-action` from 3 to 4 ([#6047](https://github.com/opensearch-project/security/pull/6047))
- Bump `io.projectreactor:reactor-core` from 3.8.2 to 3.8.4 ([#6046](https://github.com/opensearch-project/security/pull/6046))
- Bump `commons-logging:commons-logging` from 1.3.5 to 1.3.6 ([#6050](https://github.com/opensearch-project/security/pull/6050))
- Bump `org.mockito:mockito-core` from 5.21.0 to 5.23.0 ([#6048](https://github.com/opensearch-project/security/pull/6048))

### Removed

### Documentation

[Unreleased 3.x]: https://github.com/opensearch-project/security/compare/3.6...main
Release notes are now auto-generated from PR metadata at release time using an LLM-based pipeline in [opensearch-build](https://github.com/opensearch-project/opensearch-build).
See the [release notes script](https://github.com/opensearch-project/opensearch-build/blob/main/src/release_notes_workflow/release_notes.py) and [LLM prompt](https://github.com/opensearch-project/opensearch-build/blob/main/src/release_notes_workflow/release_notes_prompt.txt) for details.
