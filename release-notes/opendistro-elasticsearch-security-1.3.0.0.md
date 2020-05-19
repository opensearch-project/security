## 2019-11-18 Version 1.3.0.0

- Support for Elasticsearch 7.3.2
- Validate all config files before uploading them via securityadmin and make sure yaml parser does not tolerate duplicate keys
- Make built-in roles work with ILM, add built-in ILM action groups
- Fix built-in roles to work with xp monitoring when multi cluster monitoring is supported
- Add opendistro_security.unsupported.load_static_resources config property so that integrators can disable static resources
- Add ChaCha20 support for TLS 1.2 
- rename "roles" to "backend_roles" in user info/authinfo  
- Update Bouncycastle dependency to 1.62
- Fix permissions for built-in logstash role to work with ILM
- Introduce opendistro_security_roles in internal_users.yml
- Fix index resolution for "*,-index" patterns, introduce opendistro_security.filter_securityindex_from_all_requests option
- Fixed when tenants not handled correctly when using impersonation
- Fix unit tests 
- Revised logging code 
- Simplify EmptyLeafReader 
- Move DLS for search requests from DlsFlsFilterLeafReader to DlsFlsVavleImpl
