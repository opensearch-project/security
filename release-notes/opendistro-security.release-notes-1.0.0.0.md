## 2019-06-21, Version 1.0.0.0

- New configuration syntax
- Streamlined the YAML configuration file syntax and added a migration feature to `securityadmin.sh` to help you move from the old file format to the new format.
- Request bodies for calls to the REST API are also slightly different.
- Static default roles
- Previously, all roles were dynamically configured and stored in the Security plugin configuration index, including default roles such as `kibana_read_only` and `logstash`
- Now, all default roles are static, so permission changes to these roles are automatically applied when you upgrade Open Distro for Elasticsearch.
