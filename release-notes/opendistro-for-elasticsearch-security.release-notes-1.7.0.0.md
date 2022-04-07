## 2020-05-01 Version 1.7.0.0

- Supported Elasticsearch version 7.6.1 (same as Open Distro for Elasticsearch Security plugin version 1.6.0.0)
- Implemented APIs and datamodel to configure nodes_dn dynamically
- Performance improvement by memorizing results of resolveIndexPatterns for Bulk requests
- Performance improvement by implementing faster version of implies type perm
- Enabled limited OpenSSL support
- Changed file permissions for securityconfig and tools
- Fixed bug which caused user to lose roles on account password update
- Refactored to use Greenrobot EventBus
- Refactored Resolved class, dropped unused fields and simplified logic
- Refactored audit logging and compliance config classes
