# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Added

* Integrating APIs with security from [@ohltyler](https://github.com/ohltyler)

### Changed 
* Corrected ml/stats/nodes permissions spelling from [@camAtGitHub](https://github.com/camAtGitHub)
* Internal user usage clarification from [@reshippie](https://github.com/reshippie)
* Remove `advanced_modules_enabled` examples from [@wjordan](https://github.com/wjordan)
* CHANGELOG.md replaces release-notes

### Security

* Security patch for `org.cryptacular:cryptacular`
* Security patch for `org.springframework:spring-core`
* Security patch for `org.apache.kafka:kafka-clients`
* Security patch for `org.springframework.kafka:spring-kafka-test`

## [2.0.0-rc1] - 2022-04-20

### Added

* DLS privileges evaluation can process security roles from [@ch-govau](https://github.com/ch-govau)
* Setting to enable role without DLS/FLS to override roles
* DLS Term Lookup Queries

### Changed 

* Support for JDK17
* Support for Gradle 7
* Use standard Issue/Pull request templates from [@dblock](https://github.com/dblock)
* Security configuration are placed side-by-side with other plugins
* Cleaned up developer guide

### Deprecated

* Security tools deprecation

### Removed

* No longer supporting JDK14
* Removed TransportClient

### Fixed 

* Log messages are sent to the OpenSearch log, reported by [@patcable](https://github.com/patcable)
* Wild-card expressions are properly invalidate from [@sandeshkr419](https://github.com/sandeshkr419)
* DLS replication action failure reports correct failure from [@saikaranam-amazon](https://github.com/saikaranam-amazon)
* Improvement to test speed / reliability
* Backward compataiblity tests download binaries, rather than use a checked in binary

### Security

* DLS `min_doc_count` of zero will no longer disclose aggregate keys that user does not have permissions to see
