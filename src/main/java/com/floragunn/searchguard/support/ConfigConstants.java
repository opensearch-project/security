/*
 * Copyright 2015-2017 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.floragunn.searchguard.support;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ConfigConstants {


    public static final String SG_CONFIG_PREFIX = "_sg_";

    public static final String SG_CHANNEL_TYPE = SG_CONFIG_PREFIX+"channel_type";

    public static final String SG_ORIGIN = SG_CONFIG_PREFIX+"origin";
    public static final String SG_ORIGIN_HEADER = SG_CONFIG_PREFIX+"origin_header";

    public static final String SG_DLS_QUERY_HEADER = SG_CONFIG_PREFIX+"dls_query";

    public static final String SG_FLS_FIELDS_HEADER = SG_CONFIG_PREFIX+"fls_fields";
    
    public static final String SG_MASKED_FIELD_HEADER = SG_CONFIG_PREFIX+"masked_fields";

    public static final String SG_CONF_REQUEST_HEADER = SG_CONFIG_PREFIX+"conf_request";

    public static final String SG_REMOTE_ADDRESS = SG_CONFIG_PREFIX+"remote_address";
    public static final String SG_REMOTE_ADDRESS_HEADER = SG_CONFIG_PREFIX+"remote_address_header";
    
    public static final String SG_INITIAL_ACTION_CLASS_HEADER = SG_CONFIG_PREFIX+"initial_action_class_header";

    /**
     * Set by SSL plugin for https requests only
     */
    public static final String SG_SSL_PEER_CERTIFICATES = SG_CONFIG_PREFIX+"ssl_peer_certificates";

    /**
     * Set by SSL plugin for https requests only
     */
    public static final String SG_SSL_PRINCIPAL = SG_CONFIG_PREFIX+"ssl_principal";

    /**
     * If this is set to TRUE then the request comes from a Server Node (fully trust)
     * Its expected that there is a _sg_user attached as header
     */
    public static final String SG_SSL_TRANSPORT_INTERCLUSTER_REQUEST = SG_CONFIG_PREFIX+"ssl_transport_intercluster_request";

    public static final String SG_SSL_TRANSPORT_TRUSTED_CLUSTER_REQUEST = SG_CONFIG_PREFIX+"ssl_transport_trustedcluster_request";


    /**
     * Set by the SSL plugin, this is the peer node certificate on the transport layer
     */
    public static final String SG_SSL_TRANSPORT_PRINCIPAL = SG_CONFIG_PREFIX+"ssl_transport_principal";

    public static final String SG_USER = SG_CONFIG_PREFIX+"user";
    public static final String SG_USER_HEADER = SG_CONFIG_PREFIX+"user_header";

    public static final String SG_INJECTED_USER = "injected_user";
    
    public static final String SG_XFF_DONE = SG_CONFIG_PREFIX+"xff_done";

    public static final String SSO_LOGOUT_URL = SG_CONFIG_PREFIX+"sso_logout_url";

    
    public static final String SG_DEFAULT_CONFIG_INDEX = "searchguard";

    public static final String SEARCHGUARD_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE = "searchguard.enable_snapshot_restore_privilege";
    public static final boolean SG_DEFAULT_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE = false;

    public static final String SEARCHGUARD_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES = "searchguard.check_snapshot_restore_write_privileges";
    public static final boolean SG_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES = true;
    public static final Set<String> SG_SNAPSHOT_RESTORE_NEEDED_WRITE_PRIVILEGES = Collections.unmodifiableSet(
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
    public static final String SG_INTERCLUSTER_REQUEST_EVALUATOR_CLASS = "searchguard.cert.intercluster_request_evaluator_class";
    public static final String SG_ACTION_NAME = SG_CONFIG_PREFIX+"action_name";


    public static final String SEARCHGUARD_AUTHCZ_ADMIN_DN = "searchguard.authcz.admin_dn";
    public static final String SEARCHGUARD_CONFIG_INDEX_NAME = "searchguard.config_index_name";
    public static final String SEARCHGUARD_AUTHCZ_IMPERSONATION_DN = "searchguard.authcz.impersonation_dn";
    public static final String SEARCHGUARD_AUTHCZ_REST_IMPERSONATION_USERS="searchguard.authcz.rest_impersonation_user";
    
    public static final String SEARCHGUARD_AUDIT_TYPE_DEFAULT = "searchguard.audit.type";    
    public static final String SEARCHGUARD_AUDIT_CONFIG_DEFAULT = "searchguard.audit.config";
    public static final String SEARCHGUARD_AUDIT_CONFIG_ROUTES = "searchguard.audit.routes";
    public static final String SEARCHGUARD_AUDIT_CONFIG_ENDPOINTS = "searchguard.audit.endpoints";
    public static final String SEARCHGUARD_AUDIT_THREADPOOL_SIZE = "searchguard.audit.threadpool.size";
    public static final String SEARCHGUARD_AUDIT_THREADPOOL_MAX_QUEUE_LEN = "searchguard.audit.threadpool.max_queue_len";
    public static final String SEARCHGUARD_AUDIT_LOG_REQUEST_BODY = "searchguard.audit.log_request_body";
    public static final String SEARCHGUARD_AUDIT_RESOLVE_INDICES = "searchguard.audit.resolve_indices";
    public static final String SEARCHGUARD_AUDIT_ENABLE_REST = "searchguard.audit.enable_rest";
    public static final String SEARCHGUARD_AUDIT_ENABLE_TRANSPORT = "searchguard.audit.enable_transport";
    public static final String SEARCHGUARD_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES = "searchguard.audit.config.disabled_transport_categories";
    public static final String SEARCHGUARD_AUDIT_CONFIG_DISABLED_REST_CATEGORIES = "searchguard.audit.config.disabled_rest_categories";
    public static final String SEARCHGUARD_AUDIT_IGNORE_USERS = "searchguard.audit.ignore_users";
    public static final String SEARCHGUARD_AUDIT_IGNORE_REQUESTS = "searchguard.audit.ignore_requests";
    public static final String SEARCHGUARD_AUDIT_RESOLVE_BULK_REQUESTS = "searchguard.audit.resolve_bulk_requests";
    public static final boolean SEARCHGUARD_AUDIT_SSL_VERIFY_HOSTNAMES_DEFAULT = true;
    public static final boolean SEARCHGUARD_AUDIT_SSL_ENABLE_SSL_CLIENT_AUTH_DEFAULT = false;
    public static final String SEARCHGUARD_AUDIT_EXCLUDE_SENSITIVE_HEADERS = "searchguard.audit.exclude_sensitive_headers";
    
    public static final String SEARCHGUARD_AUDIT_CONFIG_DEFAULT_PREFIX = "searchguard.audit.config.";

    // Internal / External ES
    public static final String SEARCHGUARD_AUDIT_ES_INDEX = "index";
    public static final String SEARCHGUARD_AUDIT_ES_TYPE = "type";    
    
    // External ES
    public static final String SEARCHGUARD_AUDIT_EXTERNAL_ES_HTTP_ENDPOINTS = "http_endpoints";
    public static final String SEARCHGUARD_AUDIT_EXTERNAL_ES_USERNAME = "username";
    public static final String SEARCHGUARD_AUDIT_EXTERNAL_ES_PASSWORD = "password";
    public static final String SEARCHGUARD_AUDIT_EXTERNAL_ES_ENABLE_SSL = "enable_ssl";
    public static final String SEARCHGUARD_AUDIT_EXTERNAL_ES_VERIFY_HOSTNAMES = "verify_hostnames";    
    public static final String SEARCHGUARD_AUDIT_EXTERNAL_ES_ENABLE_SSL_CLIENT_AUTH = "enable_ssl_client_auth";    
    public static final String SEARCHGUARD_AUDIT_EXTERNAL_ES_PEMKEY_FILEPATH = "pemkey_filepath";
    public static final String SEARCHGUARD_AUDIT_EXTERNAL_ES_PEMKEY_CONTENT = "pemkey_content";
    public static final String SEARCHGUARD_AUDIT_EXTERNAL_ES_PEMKEY_PASSWORD = "pemkey_password";
    public static final String SEARCHGUARD_AUDIT_EXTERNAL_ES_PEMCERT_FILEPATH = "pemcert_filepath";
    public static final String SEARCHGUARD_AUDIT_EXTERNAL_ES_PEMCERT_CONTENT = "pemcert_content";
    public static final String SEARCHGUARD_AUDIT_EXTERNAL_ES_PEMTRUSTEDCAS_FILEPATH = "pemtrustedcas_filepath";
    public static final String SEARCHGUARD_AUDIT_EXTERNAL_ES_PEMTRUSTEDCAS_CONTENT = "pemtrustedcas_content";
    public static final String SEARCHGUARD_AUDIT_EXTERNAL_ES_JKS_CERT_ALIAS = "cert_alias";
    public static final String SEARCHGUARD_AUDIT_EXTERNAL_ES_ENABLED_SSL_CIPHERS = "enabled_ssl_ciphers";
    public static final String SEARCHGUARD_AUDIT_EXTERNAL_ES_ENABLED_SSL_PROTOCOLS = "enabled_ssl_protocols";

    // Webhooks    
    public static final String SEARCHGUARD_AUDIT_WEBHOOK_URL = "webhook.url";
    public static final String SEARCHGUARD_AUDIT_WEBHOOK_FORMAT = "webhook.format";
    public static final String SEARCHGUARD_AUDIT_WEBHOOK_SSL_VERIFY = "webhook.ssl.verify";
    public static final String SEARCHGUARD_AUDIT_WEBHOOK_PEMTRUSTEDCAS_FILEPATH = "webhook.ssl.pemtrustedcas_filepath";
    public static final String SEARCHGUARD_AUDIT_WEBHOOK_PEMTRUSTEDCAS_CONTENT = "webhook.ssl.pemtrustedcas_content";
    
    // Log4j
    public static final String SEARCHGUARD_AUDIT_LOG4J_LOGGER_NAME = "log4j.logger_name";
    public static final String SEARCHGUARD_AUDIT_LOG4J_LEVEL = "log4j.level";

        
    public static final String SEARCHGUARD_KERBEROS_KRB5_FILEPATH = "searchguard.kerberos.krb5_filepath";
    public static final String SEARCHGUARD_KERBEROS_ACCEPTOR_KEYTAB_FILEPATH = "searchguard.kerberos.acceptor_keytab_filepath";
    public static final String SEARCHGUARD_KERBEROS_ACCEPTOR_PRINCIPAL = "searchguard.kerberos.acceptor_principal";
    public static final String SEARCHGUARD_CERT_OID = "searchguard.cert.oid";
    public static final String SEARCHGUARD_CERT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS = "searchguard.cert.intercluster_request_evaluator_class";
    public static final String SEARCHGUARD_ENTERPRISE_MODULES_ENABLED = "searchguard.enterprise_modules_enabled";
    public static final String SEARCHGUARD_NODES_DN = "searchguard.nodes_dn";
    public static final String SEARCHGUARD_DISABLED = "searchguard.disabled";
    public static final String SEARCHGUARD_CACHE_TTL_MINUTES = "searchguard.cache.ttl_minutes";
    public static final String SEARCHGUARD_ALLOW_UNSAFE_DEMOCERTIFICATES = "searchguard.allow_unsafe_democertificates";
    public static final String SEARCHGUARD_ALLOW_DEFAULT_INIT_SGINDEX = "searchguard.allow_default_init_sgindex";

    public static final String SEARCHGUARD_ROLES_MAPPING_RESOLUTION = "searchguard.roles_mapping_resolution";

    public static final String SEARCHGUARD_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY = "searchguard.compliance.history.write.metadata_only";
    public static final String SEARCHGUARD_COMPLIANCE_HISTORY_READ_METADATA_ONLY = "searchguard.compliance.history.read.metadata_only";
    public static final String SEARCHGUARD_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS = "searchguard.compliance.history.read.watched_fields";
    public static final String SEARCHGUARD_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES = "searchguard.compliance.history.write.watched_indices";
    public static final String SEARCHGUARD_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS = "searchguard.compliance.history.write.log_diffs";
    public static final String SEARCHGUARD_COMPLIANCE_HISTORY_READ_IGNORE_USERS = "searchguard.compliance.history.read.ignore_users";
    public static final String SEARCHGUARD_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS = "searchguard.compliance.history.write.ignore_users";
    public static final String SEARCHGUARD_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED  = "searchguard.compliance.history.external_config_enabled";
    public static final String SEARCHGUARD_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION  = "searchguard.compliance.disable_anonymous_authentication";
    public static final String SEARCHGUARD_COMPLIANCE_IMMUTABLE_INDICES = "searchguard.compliance.immutable_indices";
    public static final String SEARCHGUARD_COMPLIANCE_SALT = "searchguard.compliance.salt";
    public static final String SEARCHGUARD_COMPLIANCE_SALT_DEFAULT = "e1ukloTsQlOgPquJ";//16 chars
    public static final String SEARCHGUARD_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED  = "searchguard.compliance.history.internal_config_enabled";

    public static final String SEARCHGUARD_SSL_ONLY = "searchguard.ssl_only";
    
    public enum RolesMappingResolution {
        MAPPING_ONLY,
        BACKENDROLES_ONLY,
        BOTH
    }


    //public static final String SEARCHGUARD_TRIBE_CLUSTERNAME = "searchguard.tribe.clustername";
    //public static final String SEARCHGUARD_DISABLE_TYPE_SECURITY = "searchguard.disable_type_security";

    // REST API
    public static final String SEARCHGUARD_RESTAPI_ROLES_ENABLED = "searchguard.restapi.roles_enabled";
    public static final String SEARCHGUARD_RESTAPI_ENDPOINTS_DISABLED = "searchguard.restapi.endpoints_disabled";
    public static final String SEARCHGUARD_RESTAPI_PASSWORD_VALIDATION_REGEX = "searchguard.restapi.password_validation_regex";
    public static final String SEARCHGUARD_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE = "searchguard.restapi.password_validation_error_message";


    // Illegal Opcodes from here on
    public static final String SEARCHGUARD_UNSUPPORTED_RESTAPI_ACCEPT_INVALID_LICENSE = "searchguard.unsupported.restapi.accept_invalid_license";
    public static final String SEARCHGUARD_UNSUPPORTED_DISABLE_REST_AUTH_INITIALLY = "searchguard.unsupported.disable_rest_auth_initially";
    public static final String SEARCHGUARD_UNSUPPORTED_DISABLE_INTERTRANSPORT_AUTH_INITIALLY = "searchguard.unsupported.disable_intertransport_auth_initially";
    public static final String SEARCHGUARD_UNSUPPORTED_RESTORE_SGINDEX_ENABLED = "searchguard.unsupported.restore.sgindex.enabled";
    public static final String SEARCHGUARD_UNSUPPORTED_INJECT_USER_ENABLED = "searchguard.unsupported.inject_user.enabled";
    public static final String SEARCHGUARD_UNSUPPORTED_INJECT_ADMIN_USER_ENABLED = "searchguard.unsupported.inject_user.admin.enabled";
}
