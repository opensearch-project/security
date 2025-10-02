## Version 3.3.0 Release Notes

Compatible with OpenSearch and OpenSearch Dashboards version 3.3.0

### Added
* Introduced new experimental versioned security configuration management feature ([#5357](https://github.com/opensearch-project/security/pull/5357))
* Introduced View API and Rollback API for experimental versioned security configurations ([#5431](https://github.com/opensearch-project/security/pull/5431))

### Features
* [Rule-based Autotagging] Add logic to extract security attributes for rule-based autotagging ([#5606](https://github.com/opensearch-project/security/pull/5606))

### Enhancements
* [Resource Sharing] Use DLS to automatically filter sharable resources for authenticated user based on `all_shared_principals` ([#5600](https://github.com/opensearch-project/security/pull/5600))
* [Resource Sharing] Keep track of list of principals for which sharable resource is visible for searching ([#5596](https://github.com/opensearch-project/security/pull/5596))
* [Resource Sharing] Keep track of tenant for sharable resources by persisting user requested tenant with sharing info ([#5588](https://github.com/opensearch-project/security/pull/5588))
* [SecurityPlugin Health Check] Add AuthZ initialization completion check in health check API ([#5626](https://github.com/opensearch-project/security/pull/5626))
* [Resource Sharing] Adds API to provide dashboards support for resource access management ([#5597](https://github.com/opensearch-project/security/pull/5597))
* Direct JWKS (JSON Web Key Set) support in the JWT authentication backend ([#5578](https://github.com/opensearch-project/security/pull/5578))
* Adds a list setting to explicitly specify resources to be protected ([#5671](https://github.com/opensearch-project/security/pull/5671))
* Make configuration setting for user custom attribute serialization dynamic ([#5657](https://github.com/opensearch-project/security/pull/5657))

### Bug Fixes
* Added new option skip_users to client cert authenticator  (clientcert_auth_domain.http_authenticator.config.skip_users in config.yml) ([#5525](https://github.com/opensearch-project/security/pull/5525))
* [Resource Sharing] Fixes accessible resource ids search by marking created_by.user field as keyword search instead of text ([#5574](https://github.com/opensearch-project/security/pull/5574))
* [Resource Sharing] Reverts @Inject pattern usage for ResourceSharingExtension to client accessor pattern. ([#5576](https://github.com/opensearch-project/security/pull/5576))
* Inject user custom attributes when injecting user and role information to the thread context ([#5560](https://github.com/opensearch-project/security/pull/5560))
* Allow any plugin system request when `plugins.security.system_indices.enabled` is set to `false` ([#5579](https://github.com/opensearch-project/security/pull/5579))
* [Resource Sharing] Always treat GET _doc request as indices request even when performed on sharable resource index ([#5631](https://github.com/opensearch-project/security/pull/5631))
* Fix JWT log spam when JWT authenticator is configured with an empty list for roles_key ([#5640](https://github.com/opensearch-project/security/pull/5640))
* Updates resource visibility when handling PATCH api to update sharing record ([#5654](https://github.com/opensearch-project/security/pull/5654))
* Handles resource updates which otherwise may wipe out all_shared_principals ([#5658](https://github.com/opensearch-project/security/pull/5658))
* Makes initial share map mutable to allow multiple shares ([#5666](https://github.com/opensearch-project/security/pull/5666))
* Add the fallback logic to use 'ssl_engine' if 'ssl_handler' attribute is not available / compatible ([#5667](https://github.com/opensearch-project/security/pull/5667))

### Refactoring
* [Resource Sharing] Match index settings of .kibana indices for resource sharing indices ([#5605](https://github.com/opensearch-project/security/pull/5605))

### Documentation
* [Resource Sharing] Adds comprehensive documentation for Resource Access Control feature ([#5540](https://github.com/opensearch-project/security/pull/5540))