/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

package org.opensearch.security.support;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.auditlog.impl.AuditCategory;

import com.password4j.types.Hmac;

public class ConfigConstants {

    public static final String OPENDISTRO_SECURITY_CONFIG_PREFIX = "_opendistro_security_";
    public static final String SECURITY_SETTINGS_PREFIX = "plugins.security.";

    public static final String OPENSEARCH_SECURITY_DISABLED = SECURITY_SETTINGS_PREFIX + "disabled";
    public static final boolean OPENSEARCH_SECURITY_DISABLED_DEFAULT = false;

    public static final String OPENDISTRO_SECURITY_CHANNEL_TYPE = OPENDISTRO_SECURITY_CONFIG_PREFIX + "channel_type";

    public static final String OPENDISTRO_SECURITY_ORIGIN = OPENDISTRO_SECURITY_CONFIG_PREFIX + "origin";
    public static final String OPENDISTRO_SECURITY_ORIGIN_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX + "origin_header";

    public static final String OPENDISTRO_SECURITY_DLS_QUERY_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX + "dls_query";

    public static final String OPENDISTRO_SECURITY_DLS_FILTER_LEVEL_QUERY_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX
        + "dls_filter_level_query";
    public static final String OPENDISTRO_SECURITY_DLS_FILTER_LEVEL_QUERY_TRANSIENT = OPENDISTRO_SECURITY_CONFIG_PREFIX
        + "dls_filter_level_query_t";

    public static final String OPENDISTRO_SECURITY_DLS_MODE_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX + "dls_mode";
    public static final String OPENDISTRO_SECURITY_DLS_MODE_TRANSIENT = OPENDISTRO_SECURITY_CONFIG_PREFIX + "dls_mode_t";

    public static final String OPENDISTRO_SECURITY_FLS_FIELDS_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX + "fls_fields";

    public static final String OPENDISTRO_SECURITY_MASKED_FIELD_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX + "masked_fields";

    public static final String OPENDISTRO_SECURITY_DOC_ALLOWLIST_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX + "doc_allowlist";
    public static final String OPENDISTRO_SECURITY_DOC_ALLOWLIST_TRANSIENT = OPENDISTRO_SECURITY_CONFIG_PREFIX + "doc_allowlist_t";

    public static final String OPENDISTRO_SECURITY_FILTER_LEVEL_DLS_DONE = OPENDISTRO_SECURITY_CONFIG_PREFIX + "filter_level_dls_done";
    public static final String OPENDISTRO_SECURITY_CONTAIN_PARENT_CHILD_QUERY = OPENDISTRO_SECURITY_CONFIG_PREFIX + "is_parent_child_query";

    public static final String OPENDISTRO_SECURITY_DLS_QUERY_CCS = OPENDISTRO_SECURITY_CONFIG_PREFIX + "dls_query_ccs";

    public static final String OPENDISTRO_SECURITY_FLS_FIELDS_CCS = OPENDISTRO_SECURITY_CONFIG_PREFIX + "fls_fields_ccs";

    public static final String OPENDISTRO_SECURITY_MASKED_FIELD_CCS = OPENDISTRO_SECURITY_CONFIG_PREFIX + "masked_fields_ccs";

    public static final String OPENDISTRO_SECURITY_CONF_REQUEST_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX + "conf_request";

    public static final String OPENDISTRO_SECURITY_REMOTE_ADDRESS = OPENDISTRO_SECURITY_CONFIG_PREFIX + "remote_address";
    public static final String OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX + "remote_address_header";

    public static final String OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX
        + "initial_action_class_header";

    /**
     * Set by SSL plugin for https requests only
     */
    public static final String OPENDISTRO_SECURITY_SSL_PEER_CERTIFICATES = OPENDISTRO_SECURITY_CONFIG_PREFIX + "ssl_peer_certificates";

    /**
     * Set by SSL plugin for https requests only
     */
    public static final String OPENDISTRO_SECURITY_SSL_PRINCIPAL = OPENDISTRO_SECURITY_CONFIG_PREFIX + "ssl_principal";

    /**
     * If this is set to TRUE then the request comes from a Server Node (fully trust)
     * Its expected that there is a _opendistro_security_user attached as header
     */
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_INTERCLUSTER_REQUEST = OPENDISTRO_SECURITY_CONFIG_PREFIX
        + "ssl_transport_intercluster_request";

    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTED_CLUSTER_REQUEST = OPENDISTRO_SECURITY_CONFIG_PREFIX
        + "ssl_transport_trustedcluster_request";

    // CS-SUPPRESS-SINGLE: RegexpSingleline Extensions manager used to allow/disallow TLS connections to extensions
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_EXTENSION_REQUEST = OPENDISTRO_SECURITY_CONFIG_PREFIX
        + "ssl_transport_extension_request";
    // CS-ENFORCE-SINGLE

    /**
     * Set by the SSL plugin, this is the peer node certificate on the transport layer
     */
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_PRINCIPAL = OPENDISTRO_SECURITY_CONFIG_PREFIX + "ssl_transport_principal";

    public static final String OPENDISTRO_SECURITY_USER = OPENDISTRO_SECURITY_CONFIG_PREFIX + "user";
    public static final String OPENDISTRO_SECURITY_USER_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX + "user_header";

    // persistent header. This header is set once and cannot be stashed
    public static final String OPENDISTRO_SECURITY_AUTHENTICATED_USER = OPENDISTRO_SECURITY_CONFIG_PREFIX + "authenticated_user";

    public static final String OPENDISTRO_SECURITY_USER_INFO_THREAD_CONTEXT = OPENDISTRO_SECURITY_CONFIG_PREFIX + "user_info";

    public static final String OPENDISTRO_SECURITY_INITIATING_USER = OPENDISTRO_SECURITY_CONFIG_PREFIX + "_initiating_user";

    public static final String OPENDISTRO_SECURITY_INJECTED_USER = "injected_user";
    public static final String OPENDISTRO_SECURITY_INJECTED_USER_HEADER = "injected_user_header";

    public static final String OPENDISTRO_SECURITY_XFF_DONE = OPENDISTRO_SECURITY_CONFIG_PREFIX + "xff_done";

    public static final String SSO_LOGOUT_URL = OPENDISTRO_SECURITY_CONFIG_PREFIX + "sso_logout_url";

    public static final String OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX = ".opendistro_security";

    public static final String OPENSEARCH_SECURITY_DEFAULT_CONFIG_VERSIONS_INDEX = ".opensearch_security_config_versions";

    public static final String SECURITY_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE = SECURITY_SETTINGS_PREFIX + "enable_snapshot_restore_privilege";
    public static final boolean SECURITY_DEFAULT_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE = true;

    public static final String SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES = SECURITY_SETTINGS_PREFIX
        + "check_snapshot_restore_write_privileges";
    public static final boolean SECURITY_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES = true;
    public static final Set<String> SECURITY_SNAPSHOT_RESTORE_NEEDED_WRITE_PRIVILEGES = Collections.unmodifiableSet(
        new HashSet<String>(Arrays.asList("indices:admin/create", "indices:data/write/index"
        // "indices:data/write/bulk"
        ))
    );

    public static final String SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS = SECURITY_SETTINGS_PREFIX
        + "cert.intercluster_request_evaluator_class";
    public static final String OPENDISTRO_SECURITY_ACTION_NAME = OPENDISTRO_SECURITY_CONFIG_PREFIX + "action_name";

    public static final String SECURITY_AUTHCZ_ADMIN_DN = SECURITY_SETTINGS_PREFIX + "authcz.admin_dn";
    public static final String SECURITY_CONFIG_INDEX_NAME = SECURITY_SETTINGS_PREFIX + "config_index_name";
    public static final String SECURITY_CONFIG_VERSIONS_INDEX_NAME = SECURITY_SETTINGS_PREFIX + "config_versions_index_name";
    public static final String SECURITY_AUTHCZ_IMPERSONATION_DN = SECURITY_SETTINGS_PREFIX + "authcz.impersonation_dn";
    public static final String SECURITY_AUTHCZ_REST_IMPERSONATION_USERS = SECURITY_SETTINGS_PREFIX + "authcz.rest_impersonation_user";

    public static final String SECURITY_PERFORM_PERMISSION_CHECK_PARAM = "perform_permission_check";

    public static final String BCRYPT = "bcrypt";
    public static final String PBKDF2 = "pbkdf2";
    public static final String ARGON2 = "argon2";

    public static final String SECURITY_PASSWORD_HASHING_BCRYPT_ROUNDS = SECURITY_SETTINGS_PREFIX + "password.hashing.bcrypt.rounds";
    public static final int SECURITY_PASSWORD_HASHING_BCRYPT_ROUNDS_DEFAULT = 12;
    public static final String SECURITY_PASSWORD_HASHING_BCRYPT_MINOR = SECURITY_SETTINGS_PREFIX + "password.hashing.bcrypt.minor";
    public static final String SECURITY_PASSWORD_HASHING_BCRYPT_MINOR_DEFAULT = "Y";

    public static final String SECURITY_PASSWORD_HASHING_ALGORITHM = SECURITY_SETTINGS_PREFIX + "password.hashing.algorithm";
    public static final String SECURITY_PASSWORD_HASHING_ALGORITHM_DEFAULT = BCRYPT;

    // PBKDF2 password hashing parameters
    public static final String SECURITY_PASSWORD_HASHING_PBKDF2_ITERATIONS = SECURITY_SETTINGS_PREFIX
        + "password.hashing.pbkdf2.iterations";
    public static final int SECURITY_PASSWORD_HASHING_PBKDF2_ITERATIONS_DEFAULT = 600_000;
    public static final String SECURITY_PASSWORD_HASHING_PBKDF2_LENGTH = SECURITY_SETTINGS_PREFIX + "password.hashing.pbkdf2.length";
    public static final int SECURITY_PASSWORD_HASHING_PBKDF2_LENGTH_DEFAULT = 256;
    public static final String SECURITY_PASSWORD_HASHING_PBKDF2_FUNCTION = SECURITY_SETTINGS_PREFIX + "password.hashing.pbkdf2.function";
    public static final String SECURITY_PASSWORD_HASHING_PBKDF2_FUNCTION_DEFAULT = Hmac.SHA256.name();

    // Argon2 password hashing parameters
    public static final String SECURITY_PASSWORD_HASHING_ARGON2_ITERATIONS = SECURITY_SETTINGS_PREFIX
        + "password.hashing.argon2.iterations";
    public static final int SECURITY_PASSWORD_HASHING_ARGON2_ITERATIONS_DEFAULT = 3;
    public static final String SECURITY_PASSWORD_HASHING_ARGON2_MEMORY = SECURITY_SETTINGS_PREFIX + "password.hashing.argon2.memory";
    public static final int SECURITY_PASSWORD_HASHING_ARGON2_MEMORY_DEFAULT = 65536;
    public static final String SECURITY_PASSWORD_HASHING_ARGON2_PARALLELISM = SECURITY_SETTINGS_PREFIX
        + "password.hashing.argon2.parallelism";
    public static final int SECURITY_PASSWORD_HASHING_ARGON2_PARALLELISM_DEFAULT = 1;
    public static final String SECURITY_PASSWORD_HASHING_ARGON2_LENGTH = SECURITY_SETTINGS_PREFIX + "password.hashing.argon2.length";
    public static final int SECURITY_PASSWORD_HASHING_ARGON2_LENGTH_DEFAULT = 32;
    public static final String SECURITY_PASSWORD_HASHING_ARGON2_TYPE = SECURITY_SETTINGS_PREFIX + "password.hashing.argon2.type";
    public static final String SECURITY_PASSWORD_HASHING_ARGON2_TYPE_DEFAULT = "argon2id";
    public static final String SECURITY_PASSWORD_HASHING_ARGON2_VERSION = SECURITY_SETTINGS_PREFIX + "password.hashing.argon2.version";
    public static final int SECURITY_PASSWORD_HASHING_ARGON2_VERSION_DEFAULT = 19;

    public static final String SECURITY_AUDIT_TYPE_DEFAULT = SECURITY_SETTINGS_PREFIX + "audit.type";
    public static final String SECURITY_AUDIT_CONFIG_DEFAULT = SECURITY_SETTINGS_PREFIX + "audit.config";
    public static final String SECURITY_AUDIT_CONFIG_ROUTES = SECURITY_SETTINGS_PREFIX + "audit.routes";
    public static final String SECURITY_AUDIT_CONFIG_ENDPOINTS = SECURITY_SETTINGS_PREFIX + "audit.endpoints";
    public static final String SECURITY_AUDIT_THREADPOOL_SIZE = SECURITY_SETTINGS_PREFIX + "audit.threadpool.size";
    public static final String SECURITY_AUDIT_THREADPOOL_MAX_QUEUE_LEN = SECURITY_SETTINGS_PREFIX + "audit.threadpool.max_queue_len";
    public static final String OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY = "opendistro_security.audit.log_request_body";
    public static final String OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES = "opendistro_security.audit.resolve_indices";
    public static final String OPENDISTRO_SECURITY_AUDIT_ENABLE_REST = "opendistro_security.audit.enable_rest";
    public static final String OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT = "opendistro_security.audit.enable_transport";
    public static final String OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES =
        "opendistro_security.audit.config.disabled_transport_categories";
    public static final String OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES =
        "opendistro_security.audit.config.disabled_rest_categories";
    public static final List<String> OPENDISTRO_SECURITY_AUDIT_DISABLED_CATEGORIES_DEFAULT = ImmutableList.of(
        AuditCategory.AUTHENTICATED.toString(),
        AuditCategory.GRANTED_PRIVILEGES.toString()
    );
    public static final String OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS = "opendistro_security.audit.ignore_users";
    public static final String OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS = "opendistro_security.audit.ignore_requests";
    public static final String SECURITY_AUDIT_IGNORE_HEADERS = SECURITY_SETTINGS_PREFIX + "audit.ignore_headers";
    public static final String OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS = "opendistro_security.audit.resolve_bulk_requests";
    public static final boolean OPENDISTRO_SECURITY_AUDIT_SSL_VERIFY_HOSTNAMES_DEFAULT = true;
    public static final boolean OPENDISTRO_SECURITY_AUDIT_SSL_ENABLE_SSL_CLIENT_AUTH_DEFAULT = false;
    public static final String OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS = "opendistro_security.audit.exclude_sensitive_headers";

    public static final String SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX = SECURITY_SETTINGS_PREFIX + "audit.config.";

    // Internal Opensearch data_stream
    public static final String SECURITY_AUDIT_OPENSEARCH_DATASTREAM_NAME = "data_stream.name";
    public static final String SECURITY_AUDIT_OPENSEARCH_DATASTREAM_TEMPLATE_MANAGE = "data_stream.template.manage";
    public static final String SECURITY_AUDIT_OPENSEARCH_DATASTREAM_TEMPLATE_NAME = "data_stream.template.name";
    public static final String SECURITY_AUDIT_OPENSEARCH_DATASTREAM_TEMPLATE_NUMBER_OF_REPLICAS = "data_stream.template.number_of_replicas";
    public static final String SECURITY_AUDIT_OPENSEARCH_DATASTREAM_TEMPLATE_NUMBER_OF_SHARDS = "data_stream.template.number_of_shards";

    // Internal / External OpenSearch
    public static final String SECURITY_AUDIT_OPENSEARCH_INDEX = "index";
    public static final String SECURITY_AUDIT_OPENSEARCH_TYPE = "type";

    // External OpenSearch
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_HTTP_ENDPOINTS = "http_endpoints";
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_USERNAME = "username";
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PASSWORD = "password";
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL = "enable_ssl";
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_VERIFY_HOSTNAMES = "verify_hostnames";
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL_CLIENT_AUTH = "enable_ssl_client_auth";
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_FILEPATH = "pemkey_filepath";
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_CONTENT = "pemkey_content";
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_PASSWORD = "pemkey_password";
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_FILEPATH = "pemcert_filepath";
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_CONTENT = "pemcert_content";
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_FILEPATH = "pemtrustedcas_filepath";
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_CONTENT = "pemtrustedcas_content";
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_JKS_CERT_ALIAS = "cert_alias";
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_CIPHERS = "enabled_ssl_ciphers";
    public static final String SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_PROTOCOLS = "enabled_ssl_protocols";

    // Webhooks
    public static final String SECURITY_AUDIT_WEBHOOK_URL = "webhook.url";
    public static final String SECURITY_AUDIT_WEBHOOK_FORMAT = "webhook.format";
    public static final String SECURITY_AUDIT_WEBHOOK_SSL_VERIFY = "webhook.ssl.verify";
    public static final String SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_FILEPATH = "webhook.ssl.pemtrustedcas_filepath";
    public static final String SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_CONTENT = "webhook.ssl.pemtrustedcas_content";

    // Log4j
    public static final String SECURITY_AUDIT_LOG4J_LOGGER_NAME = "log4j.logger_name";
    public static final String SECURITY_AUDIT_LOG4J_LEVEL = "log4j.level";

    // retry
    public static final String SECURITY_AUDIT_RETRY_COUNT = SECURITY_SETTINGS_PREFIX + "audit.config.retry_count";
    public static final String SECURITY_AUDIT_RETRY_DELAY_MS = SECURITY_SETTINGS_PREFIX + "audit.config.retry_delay_ms";

    public static final String SECURITY_KERBEROS_KRB5_FILEPATH = SECURITY_SETTINGS_PREFIX + "kerberos.krb5_filepath";
    public static final String SECURITY_KERBEROS_ACCEPTOR_KEYTAB_FILEPATH = SECURITY_SETTINGS_PREFIX + "kerberos.acceptor_keytab_filepath";
    public static final String SECURITY_KERBEROS_ACCEPTOR_PRINCIPAL = SECURITY_SETTINGS_PREFIX + "kerberos.acceptor_principal";
    public static final String SECURITY_CERT_OID = SECURITY_SETTINGS_PREFIX + "cert.oid";
    public static final String SECURITY_CERT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS = SECURITY_SETTINGS_PREFIX
        + "cert.intercluster_request_evaluator_class";
    public static final String SECURITY_ADVANCED_MODULES_ENABLED = SECURITY_SETTINGS_PREFIX + "advanced_modules_enabled";
    public static final String SECURITY_NODES_DN = SECURITY_SETTINGS_PREFIX + "nodes_dn";
    public static final String SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED = SECURITY_SETTINGS_PREFIX + "nodes_dn_dynamic_config_enabled";
    public static final String SECURITY_DISABLED = SECURITY_SETTINGS_PREFIX + "disabled";

    public static final String SECURITY_CACHE_TTL_MINUTES = SECURITY_SETTINGS_PREFIX + "cache.ttl_minutes";
    public static final String SECURITY_ALLOW_UNSAFE_DEMOCERTIFICATES = SECURITY_SETTINGS_PREFIX + "allow_unsafe_democertificates";
    public static final String SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX = SECURITY_SETTINGS_PREFIX + "allow_default_init_securityindex";

    public static final String SECURITY_ALLOW_DEFAULT_INIT_USE_CLUSTER_STATE = SECURITY_SETTINGS_PREFIX
        + "allow_default_init_securityindex.use_cluster_state";

    public static final String SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST = SECURITY_SETTINGS_PREFIX
        + "background_init_if_securityindex_not_exist";

    public static final String SECURITY_ROLES_MAPPING_RESOLUTION = SECURITY_SETTINGS_PREFIX + "roles_mapping_resolution";

    public static final String OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY =
        "opendistro_security.compliance.history.write.metadata_only";
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY =
        "opendistro_security.compliance.history.read.metadata_only";
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS =
        "opendistro_security.compliance.history.read.watched_fields";
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES =
        "opendistro_security.compliance.history.write.watched_indices";
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS =
        "opendistro_security.compliance.history.write.log_diffs";
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS =
        "opendistro_security.compliance.history.read.ignore_users";
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS =
        "opendistro_security.compliance.history.write.ignore_users";
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED =
        "opendistro_security.compliance.history.external_config_enabled";
    public static final String OPENDISTRO_SECURITY_SOURCE_FIELD_CONTEXT = OPENDISTRO_SECURITY_CONFIG_PREFIX + "source_field_context";
    public static final String SECURITY_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION = SECURITY_SETTINGS_PREFIX
        + "compliance.disable_anonymous_authentication";
    public static final String SECURITY_COMPLIANCE_IMMUTABLE_INDICES = SECURITY_SETTINGS_PREFIX + "compliance.immutable_indices";
    public static final String SECURITY_COMPLIANCE_SALT = SECURITY_SETTINGS_PREFIX + "compliance.salt";
    public static final String SECURITY_COMPLIANCE_SALT_DEFAULT = "e1ukloTsQlOgPquJ";// 16 chars
    public static final String SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED =
        "opendistro_security.compliance.history.internal_config_enabled";
    public static final String SECURITY_SSL_ONLY = SECURITY_SETTINGS_PREFIX + "ssl_only";
    public static final String SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED = "plugins.security_config.ssl_dual_mode_enabled";
    public static final String SECURITY_SSL_DUAL_MODE_SKIP_SECURITY = OPENDISTRO_SECURITY_CONFIG_PREFIX + "passive_security";
    public static final String LEGACY_OPENDISTRO_SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED = "opendistro_security_config.ssl_dual_mode_enabled";
    public static final String SECURITY_SSL_CERT_RELOAD_ENABLED = SECURITY_SETTINGS_PREFIX + "ssl_cert_reload_enabled";
    public static final String SECURITY_SSL_CERTIFICATES_HOT_RELOAD_ENABLED = SECURITY_SETTINGS_PREFIX
        + "ssl.certificates_hot_reload.enabled";
    public static final String SECURITY_DISABLE_ENVVAR_REPLACEMENT = SECURITY_SETTINGS_PREFIX + "disable_envvar_replacement";
    public static final String SECURITY_DFM_EMPTY_OVERRIDES_ALL = SECURITY_SETTINGS_PREFIX + "dfm_empty_overrides_all";

    public enum RolesMappingResolution {
        MAPPING_ONLY,
        BACKENDROLES_ONLY,
        BOTH
    }

    public static final String SECURITY_FILTER_SECURITYINDEX_FROM_ALL_REQUESTS = SECURITY_SETTINGS_PREFIX
        + "filter_securityindex_from_all_requests";
    public static final String SECURITY_DLS_MODE = SECURITY_SETTINGS_PREFIX + "dls.mode";
    // REST API
    public static final String SECURITY_RESTAPI_ROLES_ENABLED = SECURITY_SETTINGS_PREFIX + "restapi.roles_enabled";
    public static final String SECURITY_RESTAPI_ADMIN_ENABLED = SECURITY_SETTINGS_PREFIX + "restapi.admin.enabled";
    public static final String SECURITY_RESTAPI_ENDPOINTS_DISABLED = SECURITY_SETTINGS_PREFIX + "restapi.endpoints_disabled";
    public static final String SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX = SECURITY_SETTINGS_PREFIX + "restapi.password_validation_regex";
    public static final String SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE = SECURITY_SETTINGS_PREFIX
        + "restapi.password_validation_error_message";
    public static final String SECURITY_RESTAPI_PASSWORD_MIN_LENGTH = SECURITY_SETTINGS_PREFIX + "restapi.password_min_length";
    public static final String SECURITY_RESTAPI_PASSWORD_SCORE_BASED_VALIDATION_STRENGTH = SECURITY_SETTINGS_PREFIX
        + "restapi.password_score_based_validation_strength";
    // Illegal Opcodes from here on
    public static final String SECURITY_UNSUPPORTED_DISABLE_REST_AUTH_INITIALLY = SECURITY_SETTINGS_PREFIX
        + "unsupported.disable_rest_auth_initially";
    public static final String SECURITY_UNSUPPORTED_DELAY_INITIALIZATION_SECONDS = SECURITY_SETTINGS_PREFIX
        + "unsupported.delay_initialization_seconds";
    public static final String SECURITY_UNSUPPORTED_DISABLE_INTERTRANSPORT_AUTH_INITIALLY = SECURITY_SETTINGS_PREFIX
        + "unsupported.disable_intertransport_auth_initially";
    public static final String SECURITY_UNSUPPORTED_PASSIVE_INTERTRANSPORT_AUTH_INITIALLY = SECURITY_SETTINGS_PREFIX
        + "unsupported.passive_intertransport_auth_initially";
    public static final String SECURITY_UNSUPPORTED_RESTORE_SECURITYINDEX_ENABLED = SECURITY_SETTINGS_PREFIX
        + "unsupported.restore.securityindex.enabled";
    public static final String SECURITY_UNSUPPORTED_INJECT_USER_ENABLED = SECURITY_SETTINGS_PREFIX + "unsupported.inject_user.enabled";
    public static final String SECURITY_UNSUPPORTED_INJECT_ADMIN_USER_ENABLED = SECURITY_SETTINGS_PREFIX
        + "unsupported.inject_user.admin.enabled";
    public static final String SECURITY_UNSUPPORTED_ALLOW_NOW_IN_DLS = SECURITY_SETTINGS_PREFIX + "unsupported.allow_now_in_dls";

    public static final String SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION = SECURITY_SETTINGS_PREFIX
        + "unsupported.restapi.allow_securityconfig_modification";
    public static final String SECURITY_UNSUPPORTED_LOAD_STATIC_RESOURCES = SECURITY_SETTINGS_PREFIX + "unsupported.load_static_resources";
    public static final String SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG = SECURITY_SETTINGS_PREFIX + "unsupported.accept_invalid_config";

    public static final String SECURITY_PROTECTED_INDICES_ENABLED_KEY = SECURITY_SETTINGS_PREFIX + "protected_indices.enabled";
    public static final Boolean SECURITY_PROTECTED_INDICES_ENABLED_DEFAULT = false;
    public static final String SECURITY_PROTECTED_INDICES_KEY = SECURITY_SETTINGS_PREFIX + "protected_indices.indices";
    public static final List<String> SECURITY_PROTECTED_INDICES_DEFAULT = Collections.emptyList();
    public static final String SECURITY_PROTECTED_INDICES_ROLES_KEY = SECURITY_SETTINGS_PREFIX + "protected_indices.roles";
    public static final List<String> SECURITY_PROTECTED_INDICES_ROLES_DEFAULT = Collections.emptyList();

    // Roles injection for plugins
    public static final String OPENDISTRO_SECURITY_INJECTED_ROLES = "opendistro_security_injected_roles";
    public static final String OPENDISTRO_SECURITY_INJECTED_ROLES_HEADER = "opendistro_security_injected_roles_header";

    // Roles validation for the plugins
    public static final String OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION = "opendistro_security_injected_roles_validation";
    public static final String OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION_HEADER =
        "opendistro_security_injected_roles_validation_header";

    // System indices settings
    public static final String SYSTEM_INDEX_PERMISSION = "system:admin/system_index";
    public static final String SECURITY_SYSTEM_INDICES_ENABLED_KEY = SECURITY_SETTINGS_PREFIX + "system_indices.enabled";
    public static final Boolean SECURITY_SYSTEM_INDICES_ENABLED_DEFAULT = false;
    public static final String SECURITY_SYSTEM_INDICES_PERMISSIONS_ENABLED_KEY = SECURITY_SETTINGS_PREFIX
        + "system_indices.permission.enabled";
    public static final Boolean SECURITY_SYSTEM_INDICES_PERMISSIONS_DEFAULT = false;
    public static final String SECURITY_SYSTEM_INDICES_KEY = SECURITY_SETTINGS_PREFIX + "system_indices.indices";
    public static final List<String> SECURITY_SYSTEM_INDICES_DEFAULT = Collections.emptyList();
    public static final String SECURITY_MASKED_FIELDS_ALGORITHM_DEFAULT = SECURITY_SETTINGS_PREFIX + "masked_fields.algorithm.default";

    public static final String TENANCY_PRIVATE_TENANT_NAME = "private";
    public static final String TENANCY_GLOBAL_TENANT_NAME = "global";
    public static final String TENANCY_GLOBAL_TENANT_DEFAULT_NAME = "";

    // Security Config Version Index feature flag
    public static final String EXPERIMENTAL_SECURITY_CONFIGURATIONS_VERSIONS_ENABLED = SECURITY_SETTINGS_PREFIX
        + "configurations_versions.enabled";
    public static final boolean EXPERIMENTAL_SECURITY_CONFIGURATIONS_VERSIONS_ENABLED_DEFAULT = false;

    public static final String SECURITY_CONFIG_VERSION_RETENTION_COUNT = SECURITY_SETTINGS_PREFIX + "config_version.retention_count";
    public static final int SECURITY_CONFIG_VERSION_RETENTION_COUNT_DEFAULT = 10;

    // On-behalf-of endpoints settings
    // CS-SUPPRESS-SINGLE: RegexpSingleline get Extensions Settings
    public static final String EXTENSIONS_BWC_PLUGIN_MODE = "bwcPluginMode";
    public static final boolean EXTENSIONS_BWC_PLUGIN_MODE_DEFAULT = false;
    // CS-ENFORCE-SINGLE

    // Variable for initial admin password support
    public static final String OPENSEARCH_INITIAL_ADMIN_PASSWORD = "OPENSEARCH_INITIAL_ADMIN_PASSWORD";

    public static Set<String> getSettingAsSet(
        final Settings settings,
        final String key,
        final List<String> defaultList,
        final boolean ignoreCaseForNone
    ) {
        final List<String> list = settings.getAsList(key, defaultList);
        if (list.size() == 1 && "NONE".equals(ignoreCaseForNone ? list.get(0).toUpperCase() : list.get(0))) {
            return Collections.emptySet();
        }
        return ImmutableSet.copyOf(list);
    }
}
