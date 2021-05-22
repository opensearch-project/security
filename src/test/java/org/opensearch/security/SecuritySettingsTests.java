/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security;

import com.google.common.collect.Lists;
import org.junit.Assert;
import org.junit.Test;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.ssl.util.LegacyOpenDistroSSLSecuritySettings;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.ssl.util.SSLSecuritySettings;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.LegacyOpenDistroSecuritySettings;
import org.opensearch.security.support.SecuritySettings;

import java.util.List;
import java.util.Map;
import java.util.function.Function;

public class SecuritySettingsTests {
    
    @Test
    public void testLegacyOpenDistroSettingsFallback() {
        Assert.assertEquals(
                SecuritySettings.SECURITY_ADVANCED_MODULES_ENABLED.get(Settings.EMPTY),
                LegacyOpenDistroSecuritySettings.SECURITY_ADVANCED_MODULES_ENABLED.get(Settings.EMPTY)
        );
        Assert.assertEquals(
                SSLSecuritySettings.SECURITY_SSL_HTTP_ENABLED.get(Settings.EMPTY),
                LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_ENABLED.get(Settings.EMPTY)
        );
    }
    
    @Test
    public void testSettingsGetValue() {
        Settings settings = Settings.builder()
                .put("plugins.security.disabled", true)
                .put("plugins.security.ssl.http.enabled", true)
        .build();
        Assert.assertEquals(SecuritySettings.SECURITY_DISABLED.get(settings), true);
        Assert.assertEquals(LegacyOpenDistroSecuritySettings.SECURITY_DISABLED.get(settings), false);
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_ENABLED.get(settings), true);
        Assert.assertEquals(LegacyOpenDistroSSLSecuritySettings.SECURITY_SSL_HTTP_ENABLED.get(settings), false);
    }
    
    @Test
    public void testSettingsGetValueWithLegacyFallback() {
        Settings settings = Settings.builder()
                .put("opendistro_security.ssl_only", false)
                .put("opendistro_security_config.ssl_dual_mode_enabled", false)
                // Protected index settings
                .put("opendistro_security.protected_indices.enabled", false)
                .putList("opendistro_security.protected_indices.indices", "a", "b")
                .putList("opendistro_security.protected_indices.roles", "a", "b")
                // System index settings
                .put("opendistro_security.system_indices.enabled", false)
                .putList("opendistro_security.system_indices.indices", "a", "b")
                
                .putList("opendistro_security.authcz.admin_dn", "a", "b")
                .put("opendistro_security.config_index_name", "test")
                
                .put("opendistro_security.authcz.impersonation_dn.1.value", "value 1")
                .put("opendistro_security.authcz.impersonation_dn.2.value", "value 2")
                
                .put("opendistro_security.cert.oid", "test")
                .put("opendistro_security.cert.intercluster_request_evaluator_class", "test")
                .putList("opendistro_security.nodes_dn", "a", "b")
                .put("opendistro_security.nodes_dn_dynamic_config_enabled", false)
                .put("opendistro_security.enable_snapshot_restore_privilege", false)
                .put("opendistro_security.check_snapshot_restore_write_privileges", false)
                .put("opendistro_security.disabled", false)
                .put("opendistro_security.cache.ttl_minutes", 12)
                //security
                .put("opendistro_security.advanced_modules_enabled", false)
                .put("opendistro_security.allow_unsafe_democertificates", false)
                .put("opendistro_security.allow_default_init_securityindex", false)
                .put("opendistro_security.background_init_if_securityindex_not_exist", false)
                
                .put("opendistro_security.authcz.rest_impersonation_user.1.value", "value 1")
                .put("opendistro_security.authcz.rest_impersonation_user.2.value", "value 2")
                
                .put("opendistro_security.roles_mapping_resolution", "test")
                .put("opendistro_security.disable_envvar_replacement", false)
                //Security - Audit
                .put("opendistro_security.audit.type", "test")
                
                .put("opendistro_security.audit.routes.1.value", "value 1")
                .put("opendistro_security.audit.routes.2.value", "value 2")
                
                .put("opendistro_security.audit.endpoints.1.value", "value 1")
                .put("opendistro_security.audit.endpoints.2.value", "value 2")
                
                .put("opendistro_security.audit.threadpool.size", 12)
                .put("opendistro_security.audit.threadpool.max_queue_len", 12)
                .put("opendistro_security.audit.log_request_body", false)
                .put("opendistro_security.audit.resolve_indices", false)
                .put("opendistro_security.audit.enable_rest", false)
                .put("opendistro_security.audit.enable_transport", false)
                .putList("opendistro_security.audit.config.disabled_transport_categories", "a", "b")
                .putList("opendistro_security.audit.config.disabled_rest_categories", "a", "b")
                .putList("opendistro_security.audit.ignore_users", "a", "b")
                .putList("opendistro_security.audit.ignore_requests", "a", "b")
                .put("opendistro_security.audit.resolve_bulk_requests", false)
                .put("opendistro_security.audit.exclude_sensitive_headers", false)
                // Security - Audit - Sink
                .put("opendistro_security.audit.config.index", "test")
                .put("opendistro_security.audit.config.type", "test")
                // External OpenSearch
                .putList("opendistro_security.audit.config.http_endpoints", "a", "b")
                .put("opendistro_security.audit.config.username", "test")
                .put("opendistro_security.audit.config.password", "test")
                .put("opendistro_security.audit.config.enable_ssl", false)
                .put("opendistro_security.audit.config.verify_hostnames", false)
                .put("opendistro_security.audit.config.enable_ssl_client_auth", false)
                .put("opendistro_security.audit.config.pemcert_content", "test")
                .put("opendistro_security.audit.config.pemcert_filepath", "test")
                .put("opendistro_security.audit.config.pemkey_content", "test")
                .put("opendistro_security.audit.config.pemkey_filepath", "test")
                .put("opendistro_security.audit.config.pemkey_password", "test")
                .put("opendistro_security.audit.config.pemtrustedcas_content", "test")
                .put("opendistro_security.audit.config.pemtrustedcas_filepath", "test")
                .put("opendistro_security.audit.config.cert_alias", "test")
                .putList("opendistro_security.audit.config.enabled_ssl_ciphers", "a", "b")
                .putList("opendistro_security.audit.config.enabled_ssl_protocols", "a", "b")
                // Webhooks
                .put("opendistro_security.audit.config.webhook.url", "test")
                .put("opendistro_security.audit.config.webhook.format", "test")
                .put("opendistro_security.audit.config.webhook.ssl.verify", false)
                .put("opendistro_security.audit.config.webhook.ssl.pemtrustedcas_filepath", "test")
                .put("opendistro_security.audit.config.webhook.ssl.pemtrustedcas_content", "test")
                // Log4j
                .put("opendistro_security.audit.config.log4j.logger_name", "test")
                .put("opendistro_security.audit.config.log4j.level", "test")
                // Kerberos
                .put("opendistro_security.kerberos.krb5_filepath", "test")
                .put("opendistro_security.kerberos.acceptor_keytab_filepath", "test")
                .put("opendistro_security.kerberos.acceptor_principal", "test")
                // Open Distro Security - REST API
                .putList("opendistro_security.restapi.roles_enabled", "a", "b")
                
                .put("opendistro_security.restapi.endpoints_disabled.1.value", "value 1")
                .put("opendistro_security.restapi.endpoints_disabled.2.value", "value 2")
                
                .put("opendistro_security.restapi.password_validation_regex", "test")
                .put("opendistro_security.restapi.password_validation_error_message", "test")
                // Compliance
                .putList("opendistro_security.compliance.history.write.watched_indices", "a", "b")
                .putList("opendistro_security.compliance.history.read.watched_fields", "a", "b")
                .put("opendistro_security.compliance.history.write.metadata_only", false)
                .put("opendistro_security.compliance.history.read.metadata_only", false)
                .put("opendistro_security.compliance.history.write.log_diffs", false)
                .put("opendistro_security.compliance.history.external_config_enabled", false)
                .putList("opendistro_security.compliance.history.read.ignore_users", "a", "b")
                .putList("opendistro_security.compliance.history.write.ignore_users", "a", "b")
                .put("opendistro_security.compliance.disable_anonymous_authentication", false)
                .putList("opendistro_security.compliance.immutable_indices", "a", "b")
                .put("opendistro_security.compliance.salt", "test")
                .put("opendistro_security.compliance.history.internal_config_enabled", false)
                .put("opendistro_security.filter_securityindex_from_all_requests", false)
                //compat
                .put("opendistro_security.unsupported.disable_intertransport_auth_initially", false)
                .put("opendistro_security.unsupported.disable_rest_auth_initially", false)
                // system integration
                .put("opendistro_security.unsupported.restore.securityindex.enabled", false)
                .put("opendistro_security.unsupported.inject_user.enabled", false)
                .put("opendistro_security.unsupported.inject_user.admin.enabled", false)
                .put("opendistro_security.unsupported.allow_now_in_dls", false)
                .put("opendistro_security.unsupported.restapi.allow_securityconfig_modification", false)
                .put("opendistro_security.unsupported.load_static_resources", false)
                .put("opendistro_security.ssl_cert_reload_enabled", false)
                .put("opendistro_security.unsupported.accept_invalid_config", false)
        .build();

        Map<String, Settings> asMap;
        Assert.assertEquals(SecuritySettings.SECURITY_SSL_ONLY.get(settings), false);
        Assert.assertEquals(SecuritySettings.SSL_DUAL_MODE_SETTING.get(settings), false);
        // Protected index settings
        Assert.assertEquals(SecuritySettings.SECURITY_PROTECTED_INDICES_ENABLED_KEY.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_PROTECTED_INDICES_KEY.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SecuritySettings.SECURITY_PROTECTED_INDICES_ROLES_KEY.get(settings), Lists.newArrayList("a", "b"));

        // System index settings
        Assert.assertEquals(SecuritySettings.SECURITY_SYSTEM_INDICES_ENABLED_KEY.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_SYSTEM_INDICES_KEY.get(settings), Lists.newArrayList("a", "b"));

        Assert.assertEquals(SecuritySettings.SECURITY_AUTHCZ_ADMIN_DN.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SecuritySettings.SECURITY_CONFIG_INDEX_NAME.get(settings), "test");
        asMap = SecuritySettings.SECURITY_AUTHCZ_IMPERSONATION_DN.get(settings).getAsGroups();
        Assert.assertEquals(2, asMap.size());
        Assert.assertEquals(asMap.get("1").get("value"), "value 1");
        Assert.assertEquals(asMap.get("2").get("value"), "value 2");
        Assert.assertEquals(SecuritySettings.SECURITY_CERT_OID.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_CERT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_NODES_DN.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SecuritySettings.SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_DISABLED.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_CACHE_TTL_MINUTES.get(settings), Integer.valueOf(12));

        //Security
        Assert.assertEquals(SecuritySettings.SECURITY_ADVANCED_MODULES_ENABLED.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_ALLOW_UNSAFE_DEMOCERTIFICATES.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST.get(settings), false);
        asMap = SecuritySettings.SECURITY_AUTHCZ_REST_IMPERSONATION_USERS.get(settings).getAsGroups();
        Assert.assertEquals(2, asMap.size());
        Assert.assertEquals(asMap.get("1").get("value"), "value 1");
        Assert.assertEquals(asMap.get("2").get("value"), "value 2");
        Assert.assertEquals(SecuritySettings.SECURITY_ROLES_MAPPING_RESOLUTION.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_DISABLE_ENVVAR_REPLACEMENT.get(settings), false);

        // Security - Audit
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_TYPE_DEFAULT.get(settings), "test");
        asMap = SecuritySettings.SECURITY_AUDIT_CONFIG_ROUTES.get(settings).getAsGroups();
        Assert.assertEquals(2, asMap.size());
        Assert.assertEquals(asMap.get("1").get("value"), "value 1");
        Assert.assertEquals(asMap.get("2").get("value"), "value 2");
        asMap = SecuritySettings.SECURITY_AUDIT_CONFIG_ENDPOINTS.get(settings).getAsGroups();
        Assert.assertEquals(2, asMap.size());
        Assert.assertEquals(asMap.get("1").get("value"), "value 1");
        Assert.assertEquals(asMap.get("2").get("value"), "value 2");
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_THREADPOOL_SIZE.get(settings), Integer.valueOf(12));
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_THREADPOOL_MAX_QUEUE_LEN.get(settings), Integer.valueOf(12));
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_LOG_REQUEST_BODY.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_RESOLVE_INDICES.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_ENABLE_REST.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_ENABLE_TRANSPORT.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_IGNORE_USERS.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_IGNORE_REQUESTS.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_RESOLVE_BULK_REQUESTS.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS.get(settings), false);

        // Security - Audit - Sink
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_OPENSEARCH_INDEX.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_OPENSEARCH_TYPE.get(settings), "test");

        // External OpenSearch
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_HTTP_ENDPOINTS.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_USERNAME.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PASSWORD.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_VERIFY_HOSTNAMES.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL_CLIENT_AUTH.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_CONTENT.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_FILEPATH.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_CONTENT.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_FILEPATH.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_PASSWORD.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_CONTENT.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_FILEPATH.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_JKS_CERT_ALIAS.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_CIPHERS.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_PROTOCOLS.get(settings), Lists.newArrayList("a", "b"));

        // Webhooks
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_WEBHOOK_URL.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_WEBHOOK_FORMAT.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_WEBHOOK_SSL_VERIFY.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_FILEPATH.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_CONTENT.get(settings), "test");

        // Log4j
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_LOG4J_LOGGER_NAME.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_AUDIT_LOG4J_LEVEL.get(settings), "test");

        // Kerberos
        Assert.assertEquals(SecuritySettings.SECURITY_KERBEROS_KRB5_FILEPATH.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_KERBEROS_ACCEPTOR_KEYTAB_FILEPATH.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_KERBEROS_ACCEPTOR_PRINCIPAL.get(settings), "test");

        // Open Distro Security - REST API
        Assert.assertEquals(SecuritySettings.SECURITY_RESTAPI_ROLES_ENABLED.get(settings), Lists.newArrayList("a", "b"));
        asMap = SecuritySettings.SECURITY_RESTAPI_ENDPOINTS_DISABLED.get(settings).getAsGroups();
        Assert.assertEquals(2, asMap.size());
        Assert.assertEquals(asMap.get("1").get("value"), "value 1");
        Assert.assertEquals(asMap.get("2").get("value"), "value 2");
        Assert.assertEquals(SecuritySettings.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE.get(settings), "test");

        // Compliance
        Assert.assertEquals(SecuritySettings.SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SecuritySettings.SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SecuritySettings.SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SecuritySettings.SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SecuritySettings.SECURITY_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_COMPLIANCE_IMMUTABLE_INDICES.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SecuritySettings.SECURITY_COMPLIANCE_SALT.get(settings), "test");
        Assert.assertEquals(SecuritySettings.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_FILTER_SECURITYINDEX_FROM_ALL_REQUESTS.get(settings), false);
        
        //compat
        Assert.assertEquals(SecuritySettings.SECURITY_UNSUPPORTED_DISABLE_INTERTRANSPORT_AUTH_INITIALLY.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_UNSUPPORTED_DISABLE_REST_AUTH_INITIALLY.get(settings), false);

        // system integration
        Assert.assertEquals(SecuritySettings.SECURITY_UNSUPPORTED_RESTORE_SECURITYINDEX_ENABLED.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_UNSUPPORTED_INJECT_ADMIN_USER_ENABLED.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_UNSUPPORTED_ALLOW_NOW_IN_DLS.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_UNSUPPORTED_LOAD_STATIC_RESOURCES.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_SSL_CERT_RELOAD_ENABLED.get(settings), false);
        Assert.assertEquals(SecuritySettings.SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG.get(settings), false);
    }
    @Test
    public void testSSLSettingsGetValueWithLegacyFallback() {
        Settings settings = Settings.builder()
                .put("opendistro_security.ssl.http.clientauth_mode", "test")
                .put("opendistro_security.ssl.http.keystore_alias", "test")
                .put("opendistro_security.ssl.http.keystore_filepath", "test")
                .put("opendistro_security.ssl.http.keystore_password", "test")
                .put("opendistro_security.ssl.http.keystore_keypassword", "test")
                .put("opendistro_security.ssl.http.keystore_type", "test")
                .put("opendistro_security.ssl.http.truststore_alias", "test")
                .put("opendistro_security.ssl.http.truststore_filepath", "test")
                .put("opendistro_security.ssl.http.truststore_password", "test")
                .put("opendistro_security.ssl.http.truststore_type", "test")
                .put("opendistro_security.ssl.http.enable_openssl_if_available", false)
                .put("opendistro_security.ssl.http.enabled", false)
                .put("opendistro_security.ssl.transport.enable_openssl_if_available", false)
                .put("opendistro_security.ssl.transport.enabled", false)
                .put("opendistro_security.ssl.transport.enforce_hostname_verification", false)
                .put("opendistro_security.ssl.transport.resolve_hostname", false)
                .put("opendistro_security.ssl.transport.keystore_filepath", "test")
                .put("opendistro_security.ssl.transport.keystore_password", "test")
                .put("opendistro_security.ssl.transport.keystore_type", "test")
                .put("opendistro_security.ssl.transport.truststore_filepath", "test")
                .put("opendistro_security.ssl.transport.truststore_password", "test")
                .put("opendistro_security.ssl.transport.truststore_type", "test")
                .putList("opendistro_security.ssl.http.enabled_ciphers", "a", "b")
                .putList("opendistro_security.ssl.http.enabled_protocols", "a", "b")
                .putList("opendistro_security.ssl.transport.enabled_ciphers", "a", "b")
                .putList("opendistro_security.ssl.transport.enabled_protocols", "a", "b")
                .put("opendistro_security.ssl.client.external_context_id", "test")
                .put("opendistro_security.ssl.transport.principal_extractor_class", "test")
                .put("opendistro_security.ssl.transport.extended_key_usage_enabled", false)
                .put("opendistro_security.ssl.transport.server.keystore_alias", "test")
                .put("opendistro_security.ssl.transport.server.truststore_alias", "test")
                .put("opendistro_security.ssl.transport.server.keystore_keypassword", "test")
                .put("opendistro_security.ssl.transport.client.keystore_alias", "test")
                .put("opendistro_security.ssl.transport.client.truststore_alias", "test")
                .put("opendistro_security.ssl.transport.client.keystore_keypassword", "test")
                .put("opendistro_security.ssl.transport.server.pemcert_filepath", "test")
                .put("opendistro_security.ssl.transport.server.pemkey_filepath", "test")
                .put("opendistro_security.ssl.transport.server.pemkey_password", "test")
                .put("opendistro_security.ssl.transport.server.pemtrustedcas_filepath", "test")
                .put("opendistro_security.ssl.transport.client.pemcert_filepath", "test")
                .put("opendistro_security.ssl.transport.client.pemkey_filepath", "test")
                .put("opendistro_security.ssl.transport.client.pemkey_password", "test")
                .put("opendistro_security.ssl.transport.client.pemtrustedcas_filepath", "test")
                .put("opendistro_security.ssl.transport.keystore_alias", "test")
                .put("opendistro_security.ssl.transport.truststore_alias", "test")
                .put("opendistro_security.ssl.transport.keystore_keypassword", "test")
                .put("opendistro_security.ssl.transport.pemcert_filepath", "test")
                .put("opendistro_security.ssl.transport.pemkey_filepath", "test")
                .put("opendistro_security.ssl.transport.pemkey_password", "test")
                .put("opendistro_security.ssl.transport.pemtrustedcas_filepath", "test")
                .put("opendistro_security.ssl.http.pemcert_filepath", "test")
                .put("opendistro_security.ssl.http.pemkey_filepath", "test")
                .put("opendistro_security.ssl.http.pemkey_password", "test")
                .put("opendistro_security.ssl.http.pemtrustedcas_filepath", "test")
                .put("opendistro_security.ssl.http.crl.file_path", "test")
                .put("opendistro_security.ssl.http.crl.validate", false)
                .put("opendistro_security.ssl.http.crl.prefer_crlfile_over_ocsp", false)
                .put("opendistro_security.ssl.http.crl.check_only_end_entities", false)
                .put("opendistro_security.ssl.http.crl.disable_crldp", false)
                .put("opendistro_security.ssl.http.crl.disable_ocsp", false)
                .put("opendistro_security.ssl.http.crl.validation_date", 1)
                .build();
        
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_CLIENTAUTH_MODE.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_KEYSTORE_ALIAS.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_KEYSTORE_FILEPATH.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_KEYSTORE_PASSWORD.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_KEYSTORE_KEYPASSWORD.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_KEYSTORE_TYPE.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_TRUSTSTORE_ALIAS.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_TRUSTSTORE_FILEPATH.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_TRUSTSTORE_PASSWORD.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_TRUSTSTORE_TYPE.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE.get(settings), false);
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_ENABLED.get(settings), false);
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE.get(settings), false);
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_ENABLED.get(settings), false);
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION.get(settings), false);
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME.get(settings), false);
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_KEYSTORE_FILEPATH.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_KEYSTORE_PASSWORD.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_KEYSTORE_TYPE.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_TRUSTSTORE_FILEPATH.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_TRUSTSTORE_PASSWORD.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_TRUSTSTORE_TYPE.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_ENABLED_CIPHERS.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_ENABLED_PROTOCOLS.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_ENABLED_CIPHERS.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_ENABLED_PROTOCOLS.get(settings), Lists.newArrayList("a", "b"));
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_CLIENT_EXTERNAL_CONTEXT_ID.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_PRINCIPAL_EXTRACTOR_CLASS.get(settings), "test");

        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_EXTENDED_KEY_USAGE_ENABLED.get(settings), false);

        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_ALIAS.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_SERVER_TRUSTSTORE_ALIAS.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_SERVER_KEYSTORE_KEYPASSWORD.get(settings), "test");

        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_ALIAS.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_CLIENT_TRUSTSTORE_ALIAS.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_CLIENT_KEYSTORE_KEYPASSWORD.get(settings), "test");

        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_SERVER_PEMCERT_FILEPATH.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_FILEPATH.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_SERVER_PEMKEY_PASSWORD.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_SERVER_PEMTRUSTEDCAS_FILEPATH.get(settings), "test");

        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_CLIENT_PEMCERT_FILEPATH.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_FILEPATH.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_CLIENT_PEMKEY_PASSWORD.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_CLIENT_PEMTRUSTEDCAS_FILEPATH.get(settings), "test");

        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_KEYSTORE_ALIAS.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_TRUSTSTORE_ALIAS.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_KEYSTORE_KEYPASSWORD.get(settings), "test");

        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_PEMKEY_PASSWORD.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH.get(settings), "test");

        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_PEMCERT_FILEPATH.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_PEMKEY_FILEPATH.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_PEMKEY_PASSWORD.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH.get(settings), "test");

        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_CRL_FILE.get(settings), "test");
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_CRL_VALIDATE.get(settings), false);
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_CRL_PREFER_CRLFILE_OVER_OCSP.get(settings), false);
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_CRL_CHECK_ONLY_END_ENTITIES.get(settings), false);
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_CRL_DISABLE_CRLDP.get(settings), false);
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_CRL_DISABLE_OCSP.get(settings), false);
        Assert.assertEquals(SSLSecuritySettings.SECURITY_SSL_HTTP_CRL_VALIDATION_DATE.get(settings), Long.valueOf(1));
    }
}
