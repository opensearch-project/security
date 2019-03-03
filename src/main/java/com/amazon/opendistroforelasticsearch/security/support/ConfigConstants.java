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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.support;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ConfigConstants {


    public static final String OPENDISTRO_SECURITY_CONFIG_PREFIX = "_opendistro_security_";

    public static final String OPENDISTRO_SECURITY_CHANNEL_TYPE = OPENDISTRO_SECURITY_CONFIG_PREFIX+"channel_type";

    public static final String OPENDISTRO_SECURITY_ORIGIN = OPENDISTRO_SECURITY_CONFIG_PREFIX+"origin";
    public static final String OPENDISTRO_SECURITY_ORIGIN_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX+"origin_header";

    public static final String OPENDISTRO_SECURITY_DLS_QUERY_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX+"dls_query";

    public static final String OPENDISTRO_SECURITY_FLS_FIELDS_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX+"fls_fields";
    
    public static final String OPENDISTRO_SECURITY_MASKED_FIELD_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX+"masked_fields";

    public static final String OPENDISTRO_SECURITY_CONF_REQUEST_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX+"conf_request";

    public static final String OPENDISTRO_SECURITY_REMOTE_ADDRESS = OPENDISTRO_SECURITY_CONFIG_PREFIX+"remote_address";
    public static final String OPENDISTRO_SECURITY_REMOTE_ADDRESS_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX+"remote_address_header";
    
    public static final String OPENDISTRO_SECURITY_INITIAL_ACTION_CLASS_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX+"initial_action_class_header";

    /**
     * Set by SSL plugin for https requests only
     */
    public static final String OPENDISTRO_SECURITY_SSL_PEER_CERTIFICATES = OPENDISTRO_SECURITY_CONFIG_PREFIX+"ssl_peer_certificates";

    /**
     * Set by SSL plugin for https requests only
     */
    public static final String OPENDISTRO_SECURITY_SSL_PRINCIPAL = OPENDISTRO_SECURITY_CONFIG_PREFIX+"ssl_principal";

    /**
     * If this is set to TRUE then the request comes from a Server Node (fully trust)
     * Its expected that there is a _opendistro_security_user attached as header
     */
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_INTERCLUSTER_REQUEST = OPENDISTRO_SECURITY_CONFIG_PREFIX+"ssl_transport_intercluster_request";

    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_TRUSTED_CLUSTER_REQUEST = OPENDISTRO_SECURITY_CONFIG_PREFIX+"ssl_transport_trustedcluster_request";


    /**
     * Set by the SSL plugin, this is the peer node certificate on the transport layer
     */
    public static final String OPENDISTRO_SECURITY_SSL_TRANSPORT_PRINCIPAL = OPENDISTRO_SECURITY_CONFIG_PREFIX+"ssl_transport_principal";

    public static final String OPENDISTRO_SECURITY_USER = OPENDISTRO_SECURITY_CONFIG_PREFIX+"user";
    public static final String OPENDISTRO_SECURITY_USER_HEADER = OPENDISTRO_SECURITY_CONFIG_PREFIX+"user_header";

    public static final String OPENDISTRO_SECURITY_INJECTED_USER = "injected_user";
    
    public static final String OPENDISTRO_SECURITY_XFF_DONE = OPENDISTRO_SECURITY_CONFIG_PREFIX+"xff_done";

    public static final String SSO_LOGOUT_URL = OPENDISTRO_SECURITY_CONFIG_PREFIX+"sso_logout_url";

    
    public static final String OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX = ".opendistro_security";

    public static final String OPENDISTRO_SECURITY_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE = "opendistro_security.enable_snapshot_restore_privilege";
    public static final boolean OPENDISTRO_SECURITY_DEFAULT_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE = false;

    public static final String OPENDISTRO_SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES = "opendistro_security.check_snapshot_restore_write_privileges";
    public static final boolean OPENDISTRO_SECURITY_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES = true;
    public static final Set<String> OPENDISTRO_SECURITY_SNAPSHOT_RESTORE_NEEDED_WRITE_PRIVILEGES = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList(
                    "indices:admin/create",
                    "indices:data/write/index"
                    // "indices:data/write/bulk"
              )));

    public final static String CONFIGNAME_ROLES = "roles";
    public final static String CONFIGNAME_ROLES_MAPPING = "rolesmapping";
    public final static String CONFIGNAME_ACTION_GROUPS = "actiongroups";
    public final static String CONFIGNAME_INTERNAL_USERS = "internalusers";
    public final static String CONFIGNAME_CONFIG = "config";
    public final static String CONFIGKEY_ACTION_GROUPS_PERMISSIONS = "permissions";
    public final static String CONFIGKEY_READONLY = "readonly";
    public final static String CONFIGKEY_HIDDEN = "hidden";

    public final static List<String> CONFIG_NAMES = Collections.unmodifiableList(Arrays.asList(new String[] {CONFIGNAME_ROLES, CONFIGNAME_ROLES_MAPPING,
            CONFIGNAME_ACTION_GROUPS, CONFIGNAME_INTERNAL_USERS, CONFIGNAME_CONFIG}));
    public static final String OPENDISTRO_SECURITY_INTERCLUSTER_REQUEST_EVALUATOR_CLASS = "opendistro_security.cert.intercluster_request_evaluator_class";
    public static final String OPENDISTRO_SECURITY_ACTION_NAME = OPENDISTRO_SECURITY_CONFIG_PREFIX+"action_name";


    public static final String OPENDISTRO_SECURITY_AUTHCZ_ADMIN_DN = "opendistro_security.authcz.admin_dn";
    public static final String OPENDISTRO_SECURITY_CONFIG_INDEX_NAME = "opendistro_security.config_index_name";
    public static final String OPENDISTRO_SECURITY_AUTHCZ_IMPERSONATION_DN = "opendistro_security.authcz.impersonation_dn";
    public static final String OPENDISTRO_SECURITY_AUTHCZ_REST_IMPERSONATION_USERS="opendistro_security.authcz.rest_impersonation_user";
    
    public static final String OPENDISTRO_SECURITY_AUDIT_TYPE_DEFAULT = "opendistro_security.audit.type";
    public static final String OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT = "opendistro_security.audit.config";
    public static final String OPENDISTRO_SECURITY_AUDIT_CONFIG_ROUTES = "opendistro_security.audit.routes";
    public static final String OPENDISTRO_SECURITY_AUDIT_CONFIG_ENDPOINTS = "opendistro_security.audit.endpoints";
    public static final String OPENDISTRO_SECURITY_AUDIT_THREADPOOL_SIZE = "opendistro_security.audit.threadpool.size";
    public static final String OPENDISTRO_SECURITY_AUDIT_THREADPOOL_MAX_QUEUE_LEN = "opendistro_security.audit.threadpool.max_queue_len";
    public static final String OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY = "opendistro_security.audit.log_request_body";
    public static final String OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES = "opendistro_security.audit.resolve_indices";
    public static final String OPENDISTRO_SECURITY_AUDIT_ENABLE_REST = "opendistro_security.audit.enable_rest";
    public static final String OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT = "opendistro_security.audit.enable_transport";
    public static final String OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES = "opendistro_security.audit.config.disabled_transport_categories";
    public static final String OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES = "opendistro_security.audit.config.disabled_rest_categories";
    public static final String OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS = "opendistro_security.audit.ignore_users";
    public static final String OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS = "opendistro_security.audit.ignore_requests";
    public static final String OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS = "opendistro_security.audit.resolve_bulk_requests";
    public static final boolean OPENDISTRO_SECURITY_AUDIT_SSL_VERIFY_HOSTNAMES_DEFAULT = true;
    public static final boolean OPENDISTRO_SECURITY_AUDIT_SSL_ENABLE_SSL_CLIENT_AUTH_DEFAULT = false;
    public static final String OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS = "opendistro_security.audit.exclude_sensitive_headers";
    
    public static final String OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX = "opendistro_security.audit.config.";

    // Internal / External ES
    public static final String OPENDISTRO_SECURITY_AUDIT_ES_INDEX = "index";
    public static final String OPENDISTRO_SECURITY_AUDIT_ES_TYPE = "type";
    
    // External ES
    public static final String OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_HTTP_ENDPOINTS = "http_endpoints";
    public static final String OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_USERNAME = "username";
    public static final String OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PASSWORD = "password";
    public static final String OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_ENABLE_SSL = "enable_ssl";
    public static final String OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_VERIFY_HOSTNAMES = "verify_hostnames";
    public static final String OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_ENABLE_SSL_CLIENT_AUTH = "enable_ssl_client_auth";
    public static final String OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMKEY_FILEPATH = "pemkey_filepath";
    public static final String OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMKEY_CONTENT = "pemkey_content";
    public static final String OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMKEY_PASSWORD = "pemkey_password";
    public static final String OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMCERT_FILEPATH = "pemcert_filepath";
    public static final String OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMCERT_CONTENT = "pemcert_content";
    public static final String OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMTRUSTEDCAS_FILEPATH = "pemtrustedcas_filepath";
    public static final String OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_PEMTRUSTEDCAS_CONTENT = "pemtrustedcas_content";
    public static final String OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_JKS_CERT_ALIAS = "cert_alias";
    public static final String OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_ENABLED_SSL_CIPHERS = "enabled_ssl_ciphers";
    public static final String OPENDISTRO_SECURITY_AUDIT_EXTERNAL_ES_ENABLED_SSL_PROTOCOLS = "enabled_ssl_protocols";

    // Webhooks    
    public static final String OPENDISTRO_SECURITY_AUDIT_WEBHOOK_URL = "webhook.url";
    public static final String OPENDISTRO_SECURITY_AUDIT_WEBHOOK_FORMAT = "webhook.format";
    public static final String OPENDISTRO_SECURITY_AUDIT_WEBHOOK_SSL_VERIFY = "webhook.ssl.verify";
    public static final String OPENDISTRO_SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_FILEPATH = "webhook.ssl.pemtrustedcas_filepath";
    public static final String OPENDISTRO_SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_CONTENT = "webhook.ssl.pemtrustedcas_content";
    
    // Log4j
    public static final String OPENDISTRO_SECURITY_AUDIT_LOG4J_LOGGER_NAME = "log4j.logger_name";
    public static final String OPENDISTRO_SECURITY_AUDIT_LOG4J_LEVEL = "log4j.level";
    
    //retry
    public static final String OPENDISTRO_SECURITY_AUDIT_RETRY_COUNT = "opendistro_security.audit.config.retry_count";
    public static final String OPENDISTRO_SECURITY_AUDIT_RETRY_DELAY_MS = "opendistro_security.audit.config.retry_delay_ms";

        
    public static final String OPENDISTRO_SECURITY_KERBEROS_KRB5_FILEPATH = "opendistro_security.kerberos.krb5_filepath";
    public static final String OPENDISTRO_SECURITY_KERBEROS_ACCEPTOR_KEYTAB_FILEPATH = "opendistro_security.kerberos.acceptor_keytab_filepath";
    public static final String OPENDISTRO_SECURITY_KERBEROS_ACCEPTOR_PRINCIPAL = "opendistro_security.kerberos.acceptor_principal";
    public static final String OPENDISTRO_SECURITY_CERT_OID = "opendistro_security.cert.oid";
    public static final String OPENDISTRO_SECURITY_CERT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS = "opendistro_security.cert.intercluster_request_evaluator_class";
    public static final String OPENDISTRO_SECURITY_ENTERPRISE_MODULES_ENABLED = "opendistro_security.enterprise_modules_enabled";
    public static final String OPENDISTRO_SECURITY_NODES_DN = "opendistro_security.nodes_dn";
    public static final String OPENDISTRO_SECURITY_DISABLED = "opendistro_security.disabled";
    public static final String OPENDISTRO_SECURITY_CACHE_TTL_MINUTES = "opendistro_security.cache.ttl_minutes";
    public static final String OPENDISTRO_SECURITY_ALLOW_UNSAFE_DEMOCERTIFICATES = "opendistro_security.allow_unsafe_democertificates";
    public static final String OPENDISTRO_SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX = "opendistro_security.allow_default_init_securityindex";

    public static final String OPENDISTRO_SECURITY_ROLES_MAPPING_RESOLUTION = "opendistro_security.roles_mapping_resolution";

    public static final String OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY = "opendistro_security.compliance.history.write.metadata_only";
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY = "opendistro_security.compliance.history.read.metadata_only";
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS = "opendistro_security.compliance.history.read.watched_fields";
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES = "opendistro_security.compliance.history.write.watched_indices";
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS = "opendistro_security.compliance.history.write.log_diffs";
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS = "opendistro_security.compliance.history.read.ignore_users";
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS = "opendistro_security.compliance.history.write.ignore_users";
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED  = "opendistro_security.compliance.history.external_config_enabled";
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION  = "opendistro_security.compliance.disable_anonymous_authentication";
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_IMMUTABLE_INDICES = "opendistro_security.compliance.immutable_indices";
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_SALT = "opendistro_security.compliance.salt";
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_SALT_DEFAULT = "e1ukloTsQlOgPquJ";//16 chars
    public static final String OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED  = "opendistro_security.compliance.history.internal_config_enabled";

    public static final String OPENDISTRO_SECURITY_SSL_ONLY = "opendistro_security.ssl_only";
    
    public enum RolesMappingResolution {
        MAPPING_ONLY,
        BACKENDROLES_ONLY,
        BOTH
    }


    //public static final String OPENDISTRO_SECURITY_TRIBE_CLUSTERNAME = "opendistro_security.tribe.clustername";
    //public static final String OPENDISTRO_SECURITY_DISABLE_TYPE_SECURITY = "opendistro_security.disable_type_security";

    // REST API
    public static final String OPENDISTRO_SECURITY_RESTAPI_ROLES_ENABLED = "opendistro_security.restapi.roles_enabled";
    public static final String OPENDISTRO_SECURITY_RESTAPI_ENDPOINTS_DISABLED = "opendistro_security.restapi.endpoints_disabled";
    public static final String OPENDISTRO_SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX = "opendistro_security.restapi.password_validation_regex";
    public static final String OPENDISTRO_SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE = "opendistro_security.restapi.password_validation_error_message";


    // Illegal Opcodes from here on
    public static final String OPENDISTRO_SECURITY_UNSUPPORTED_DISABLE_REST_AUTH_INITIALLY = "opendistro_security.unsupported.disable_rest_auth_initially";
    public static final String OPENDISTRO_SECURITY_UNSUPPORTED_DISABLE_INTERTRANSPORT_AUTH_INITIALLY = "opendistro_security.unsupported.disable_intertransport_auth_initially";
    public static final String OPENDISTRO_SECURITY_UNSUPPORTED_RESTORE_SECURITYINDEX_ENABLED = "opendistro_security.unsupported.restore.securityindex.enabled";
    public static final String OPENDISTRO_SECURITY_UNSUPPORTED_INJECT_USER_ENABLED = "opendistro_security.unsupported.inject_user.enabled";
    public static final String OPENDISTRO_SECURITY_UNSUPPORTED_INJECT_ADMIN_USER_ENABLED = "opendistro_security.unsupported.inject_user.admin.enabled";
}
