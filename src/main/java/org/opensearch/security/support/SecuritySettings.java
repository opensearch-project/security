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

/*
 *   Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
 */

package org.opensearch.security.support;

import com.google.common.collect.Lists;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;

import java.util.Collections;
import java.util.List;
import java.util.function.Function;

public class SecuritySettings {
    public static final Setting<Boolean> SECURITY_SSL_ONLY = Setting.boolSetting(ConfigConstants.SECURITY_SSL_ONLY, LegacyOpenDistroSecuritySettings.SECURITY_SSL_ONLY, Setting.Property.NodeScope, Setting.Property.Filtered);

    // Protected index settings
    public static final Setting<Boolean> SECURITY_PROTECTED_INDICES_ENABLED_KEY = Setting.boolSetting(ConfigConstants.SECURITY_PROTECTED_INDICES_ENABLED_KEY, LegacyOpenDistroSecuritySettings.SECURITY_PROTECTED_INDICES_ENABLED_KEY, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Final);
    public static final Setting<List<String>> SECURITY_PROTECTED_INDICES_KEY = Setting.listSetting(ConfigConstants.SECURITY_PROTECTED_INDICES_KEY, LegacyOpenDistroSecuritySettings.SECURITY_PROTECTED_INDICES_KEY, Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Final);
    public static final Setting<List<String>> SECURITY_PROTECTED_INDICES_ROLES_KEY = Setting.listSetting(ConfigConstants.SECURITY_PROTECTED_INDICES_ROLES_KEY, LegacyOpenDistroSecuritySettings.SECURITY_PROTECTED_INDICES_ROLES_KEY, Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Final);

    // System index settings
    public static final Setting<Boolean> SECURITY_SYSTEM_INDICES_ENABLED_KEY = Setting.boolSetting(ConfigConstants.SECURITY_SYSTEM_INDICES_ENABLED_KEY, LegacyOpenDistroSecuritySettings.SECURITY_SYSTEM_INDICES_ENABLED_KEY, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Final);
    public static final Setting<List<String>> SECURITY_SYSTEM_INDICES_KEY = Setting.listSetting(ConfigConstants.SECURITY_SYSTEM_INDICES_KEY, LegacyOpenDistroSecuritySettings.SECURITY_SYSTEM_INDICES_KEY, Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Final);

    public static final Setting<List<String>> SECURITY_AUTHCZ_ADMIN_DN = Setting.listSetting(ConfigConstants.SECURITY_AUTHCZ_ADMIN_DN, LegacyOpenDistroSecuritySettings.SECURITY_AUTHCZ_ADMIN_DN, Function.identity(), Setting.Property.NodeScope); //not filtered here
    public static final Setting<String> SECURITY_CONFIG_INDEX_NAME = Setting.simpleString(ConfigConstants.SECURITY_CONFIG_INDEX_NAME, LegacyOpenDistroSecuritySettings.SECURITY_CONFIG_INDEX_NAME, Setting.Property.NodeScope); //not filtered here
    public static final Setting<Settings> SECURITY_AUTHCZ_IMPERSONATION_DN = Setting.groupSetting(ConfigConstants.SECURITY_AUTHCZ_IMPERSONATION_DN+".", LegacyOpenDistroSecuritySettings.SECURITY_AUTHCZ_IMPERSONATION_DN, Setting.Property.NodeScope);
    public static final Setting<String> SECURITY_CERT_OID = Setting.simpleString(ConfigConstants.SECURITY_CERT_OID, LegacyOpenDistroSecuritySettings.SECURITY_CERT_OID, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_CERT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS = Setting.simpleString(ConfigConstants.SECURITY_CERT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS, LegacyOpenDistroSecuritySettings.SECURITY_CERT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<List<String>> SECURITY_NODES_DN = Setting.listSetting(ConfigConstants.SECURITY_NODES_DN, LegacyOpenDistroSecuritySettings.SECURITY_NODES_DN, Function.identity(), Setting.Property.NodeScope); //not filtered here
    public static final Setting<Boolean> SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED = Setting.boolSetting(ConfigConstants.SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED, LegacyOpenDistroSecuritySettings.SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED, Setting.Property.NodeScope); //not filtered here
    public static final Setting<Boolean> SECURITY_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE = Setting.boolSetting(ConfigConstants.SECURITY_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE, LegacyOpenDistroSecuritySettings.SECURITY_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES = Setting.boolSetting(ConfigConstants.SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES, LegacyOpenDistroSecuritySettings.SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_DISABLED = Setting.boolSetting(ConfigConstants.SECURITY_DISABLED, LegacyOpenDistroSecuritySettings.SECURITY_DISABLED, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Integer> SECURITY_CACHE_TTL_MINUTES = Setting.intSetting(ConfigConstants.SECURITY_CACHE_TTL_MINUTES, LegacyOpenDistroSecuritySettings.SECURITY_CACHE_TTL_MINUTES, Setting.Property.NodeScope, Setting.Property.Filtered);

    //Security
    public static final Setting<Boolean> SECURITY_ADVANCED_MODULES_ENABLED = Setting.boolSetting(ConfigConstants.SECURITY_ADVANCED_MODULES_ENABLED, LegacyOpenDistroSecuritySettings.SECURITY_ADVANCED_MODULES_ENABLED, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_ALLOW_UNSAFE_DEMOCERTIFICATES = Setting.boolSetting(ConfigConstants.SECURITY_ALLOW_UNSAFE_DEMOCERTIFICATES, LegacyOpenDistroSecuritySettings.SECURITY_ALLOW_UNSAFE_DEMOCERTIFICATES, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX = Setting.boolSetting(ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, LegacyOpenDistroSecuritySettings.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST = Setting.boolSetting(ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, LegacyOpenDistroSecuritySettings.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Settings> SECURITY_AUTHCZ_REST_IMPERSONATION_USERS = Setting.groupSetting(ConfigConstants.SECURITY_AUTHCZ_REST_IMPERSONATION_USERS+".", LegacyOpenDistroSecuritySettings.SECURITY_AUTHCZ_REST_IMPERSONATION_USERS, Setting.Property.NodeScope); //not filtered here
    public static final Setting<String> SECURITY_ROLES_MAPPING_RESOLUTION = Setting.simpleString(ConfigConstants.SECURITY_ROLES_MAPPING_RESOLUTION, LegacyOpenDistroSecuritySettings.SECURITY_ROLES_MAPPING_RESOLUTION, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_DISABLE_ENVVAR_REPLACEMENT = Setting.boolSetting(ConfigConstants.SECURITY_DISABLE_ENVVAR_REPLACEMENT, LegacyOpenDistroSecuritySettings.SECURITY_DISABLE_ENVVAR_REPLACEMENT, Setting.Property.NodeScope, Setting.Property.Filtered);

    // Security - Audit
    public static final Setting<String> SECURITY_AUDIT_TYPE_DEFAULT = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_TYPE_DEFAULT, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_TYPE_DEFAULT, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Settings> SECURITY_AUDIT_CONFIG_ROUTES = Setting.groupSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_ROUTES + ".", LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_CONFIG_ROUTES, Setting.Property.NodeScope);
    public static final Setting<Settings> SECURITY_AUDIT_CONFIG_ENDPOINTS = Setting.groupSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_ENDPOINTS + ".", LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_CONFIG_ENDPOINTS, Setting.Property.NodeScope);
    public static final Setting<Integer> SECURITY_AUDIT_THREADPOOL_SIZE = Setting.intSetting(ConfigConstants.SECURITY_AUDIT_THREADPOOL_SIZE, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_THREADPOOL_SIZE, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Integer> SECURITY_AUDIT_THREADPOOL_MAX_QUEUE_LEN = Setting.intSetting(ConfigConstants.SECURITY_AUDIT_THREADPOOL_MAX_QUEUE_LEN, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_THREADPOOL_MAX_QUEUE_LEN, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_AUDIT_LOG_REQUEST_BODY = Setting.boolSetting(ConfigConstants.SECURITY_AUDIT_LOG_REQUEST_BODY, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_LOG_REQUEST_BODY, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_AUDIT_RESOLVE_INDICES = Setting.boolSetting(ConfigConstants.SECURITY_AUDIT_RESOLVE_INDICES, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_RESOLVE_INDICES, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_AUDIT_ENABLE_REST = Setting.boolSetting(ConfigConstants.SECURITY_AUDIT_ENABLE_REST, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_ENABLE_REST, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_AUDIT_ENABLE_TRANSPORT = Setting.boolSetting(ConfigConstants.SECURITY_AUDIT_ENABLE_TRANSPORT, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_ENABLE_TRANSPORT, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<List<String>> SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES = Setting.listSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, Function.identity(), Setting.Property.NodeScope); //not filtered here
    public static final Setting<List<String>> SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES = Setting.listSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, Function.identity(), Setting.Property.NodeScope); //not filtered here
    public static final Setting<List<String>> SECURITY_AUDIT_IGNORE_USERS = Setting.listSetting(ConfigConstants.SECURITY_AUDIT_IGNORE_USERS, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_IGNORE_USERS, Function.identity(), Setting.Property.NodeScope); //not filtered here
    public static final Setting<List<String>> SECURITY_AUDIT_IGNORE_REQUESTS = Setting.listSetting(ConfigConstants.SECURITY_AUDIT_IGNORE_REQUESTS, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_IGNORE_REQUESTS, Function.identity(), Setting.Property.NodeScope); //not filtered here
    public static final Setting<Boolean> SECURITY_AUDIT_RESOLVE_BULK_REQUESTS = Setting.boolSetting(ConfigConstants.SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS = Setting.boolSetting(ConfigConstants.SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS, Setting.Property.NodeScope, Setting.Property.Filtered);

    // Security - Audit - Sink
    public static final Setting<String> SECURITY_AUDIT_OPENSEARCH_INDEX = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_OPENSEARCH_INDEX, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_OPENSEARCH_INDEX, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_AUDIT_OPENSEARCH_TYPE = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_OPENSEARCH_TYPE, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_OPENSEARCH_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered);

    // External OpenSearch
    public static final Setting<List<String>> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_HTTP_ENDPOINTS = Setting.listSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_HTTP_ENDPOINTS, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_HTTP_ENDPOINTS, Function.identity(), Setting.Property.NodeScope); //not filtered here
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_USERNAME = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_USERNAME, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_USERNAME, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PASSWORD = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PASSWORD, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL = Setting.boolSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_VERIFY_HOSTNAMES = Setting.boolSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_VERIFY_HOSTNAMES, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_VERIFY_HOSTNAMES, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL_CLIENT_AUTH = Setting.boolSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL_CLIENT_AUTH, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL_CLIENT_AUTH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_CONTENT = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_CONTENT, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_CONTENT, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_FILEPATH = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_FILEPATH, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_CONTENT = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_CONTENT, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_CONTENT, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_FILEPATH = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_FILEPATH, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_PASSWORD = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_PASSWORD, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_CONTENT = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_CONTENT, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_CONTENT, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_FILEPATH = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_FILEPATH, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_JKS_CERT_ALIAS = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_JKS_CERT_ALIAS, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_JKS_CERT_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<List<String>> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_CIPHERS = Setting.listSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_CIPHERS, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_CIPHERS, Function.identity(), Setting.Property.NodeScope); //not filtered here
    public static final Setting<List<String>> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_PROTOCOLS = Setting.listSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_PROTOCOLS, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_PROTOCOLS, Function.identity(), Setting.Property.NodeScope); //not filtered here

    // Webhooks
    public static final Setting<String> SECURITY_AUDIT_WEBHOOK_URL = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_WEBHOOK_URL, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_WEBHOOK_URL, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_AUDIT_WEBHOOK_FORMAT = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_WEBHOOK_FORMAT, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_WEBHOOK_FORMAT, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_AUDIT_WEBHOOK_SSL_VERIFY = Setting.boolSetting(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_WEBHOOK_SSL_VERIFY, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_WEBHOOK_SSL_VERIFY, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_FILEPATH = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_FILEPATH, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_CONTENT = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_CONTENT, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_CONTENT, Setting.Property.NodeScope, Setting.Property.Filtered);

    // Log4j
    public static final Setting<String> SECURITY_AUDIT_LOG4J_LOGGER_NAME = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_LOG4J_LOGGER_NAME, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_LOG4J_LOGGER_NAME, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_AUDIT_LOG4J_LEVEL = Setting.simpleString(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_LOG4J_LEVEL, LegacyOpenDistroSecuritySettings.SECURITY_AUDIT_LOG4J_LEVEL, Setting.Property.NodeScope, Setting.Property.Filtered);

    // Kerberos
    public static final Setting<String> SECURITY_KERBEROS_KRB5_FILEPATH = Setting.simpleString(ConfigConstants.SECURITY_KERBEROS_KRB5_FILEPATH, LegacyOpenDistroSecuritySettings.SECURITY_KERBEROS_KRB5_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_KERBEROS_ACCEPTOR_KEYTAB_FILEPATH = Setting.simpleString(ConfigConstants.SECURITY_KERBEROS_ACCEPTOR_KEYTAB_FILEPATH, LegacyOpenDistroSecuritySettings.SECURITY_KERBEROS_ACCEPTOR_KEYTAB_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_KERBEROS_ACCEPTOR_PRINCIPAL = Setting.simpleString(ConfigConstants.SECURITY_KERBEROS_ACCEPTOR_PRINCIPAL, LegacyOpenDistroSecuritySettings.SECURITY_KERBEROS_ACCEPTOR_PRINCIPAL, Setting.Property.NodeScope, Setting.Property.Filtered);

    // Open Distro Security - REST API
    public static final Setting<List<String>> SECURITY_RESTAPI_ROLES_ENABLED = Setting.listSetting(ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED, LegacyOpenDistroSecuritySettings.SECURITY_RESTAPI_ROLES_ENABLED, Function.identity(), Setting.Property.NodeScope); //not filtered here
    public static final Setting<Settings> SECURITY_RESTAPI_ENDPOINTS_DISABLED = Setting.groupSetting(ConfigConstants.SECURITY_RESTAPI_ENDPOINTS_DISABLED + ".", LegacyOpenDistroSecuritySettings.SECURITY_RESTAPI_ENDPOINTS_DISABLED, Setting.Property.NodeScope);
    public static final Setting<String> SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX = Setting.simpleString(ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX, LegacyOpenDistroSecuritySettings.SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<String> SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE = Setting.simpleString(ConfigConstants.SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE, LegacyOpenDistroSecuritySettings.SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE, Setting.Property.NodeScope, Setting.Property.Filtered);

    // Compliance
    public static final Setting<List<String>> SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES = Setting.listSetting(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, LegacyOpenDistroSecuritySettings.SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, Function.identity(), Setting.Property.NodeScope); //not filtered here
    public static final Setting<List<String>> SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS = Setting.listSetting(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS, LegacyOpenDistroSecuritySettings.SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS, Function.identity(), Setting.Property.NodeScope); //not filtered here
    public static final Setting<Boolean> SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY = Setting.boolSetting(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY, LegacyOpenDistroSecuritySettings.SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY = Setting.boolSetting(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY, LegacyOpenDistroSecuritySettings.SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS = Setting.boolSetting(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, LegacyOpenDistroSecuritySettings.SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED = Setting.boolSetting(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, LegacyOpenDistroSecuritySettings.SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<List<String>> SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS = Setting.listSetting(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS, LegacyOpenDistroSecuritySettings.SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS, Function.identity(), Setting.Property.NodeScope); //not filtered here
    public static final Setting<List<String>> SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS = Setting.listSetting(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS, LegacyOpenDistroSecuritySettings.SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS, Function.identity(), Setting.Property.NodeScope); //not filtered here
    public static final Setting<Boolean> SECURITY_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION = Setting.boolSetting(ConfigConstants.SECURITY_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION, LegacyOpenDistroSecuritySettings.SECURITY_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<List<String>> SECURITY_COMPLIANCE_IMMUTABLE_INDICES = Setting.listSetting(ConfigConstants.SECURITY_COMPLIANCE_IMMUTABLE_INDICES, LegacyOpenDistroSecuritySettings.SECURITY_COMPLIANCE_IMMUTABLE_INDICES, Function.identity(), Setting.Property.NodeScope); //not filtered here
    public static final Setting<String> SECURITY_COMPLIANCE_SALT = Setting.simpleString(ConfigConstants.SECURITY_COMPLIANCE_SALT, LegacyOpenDistroSecuritySettings.SECURITY_COMPLIANCE_SALT, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED = Setting.boolSetting(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, LegacyOpenDistroSecuritySettings.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_FILTER_SECURITYINDEX_FROM_ALL_REQUESTS = Setting.boolSetting(ConfigConstants.SECURITY_FILTER_SECURITYINDEX_FROM_ALL_REQUESTS, LegacyOpenDistroSecuritySettings.SECURITY_FILTER_SECURITYINDEX_FROM_ALL_REQUESTS, Setting.Property.NodeScope, Setting.Property.Filtered);

    //compat
    public static final Setting<Boolean> SECURITY_UNSUPPORTED_DISABLE_INTERTRANSPORT_AUTH_INITIALLY = Setting.boolSetting(ConfigConstants.SECURITY_UNSUPPORTED_DISABLE_INTERTRANSPORT_AUTH_INITIALLY, LegacyOpenDistroSecuritySettings.SECURITY_UNSUPPORTED_DISABLE_INTERTRANSPORT_AUTH_INITIALLY, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_UNSUPPORTED_DISABLE_REST_AUTH_INITIALLY = Setting.boolSetting(ConfigConstants.SECURITY_UNSUPPORTED_DISABLE_REST_AUTH_INITIALLY, LegacyOpenDistroSecuritySettings.SECURITY_UNSUPPORTED_DISABLE_REST_AUTH_INITIALLY, Setting.Property.NodeScope, Setting.Property.Filtered);

    // system integration
    public static final Setting<Boolean> SECURITY_UNSUPPORTED_RESTORE_SECURITYINDEX_ENABLED = Setting.boolSetting(ConfigConstants.SECURITY_UNSUPPORTED_RESTORE_SECURITYINDEX_ENABLED, LegacyOpenDistroSecuritySettings.SECURITY_UNSUPPORTED_RESTORE_SECURITYINDEX_ENABLED, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_UNSUPPORTED_INJECT_USER_ENABLED = Setting.boolSetting(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, LegacyOpenDistroSecuritySettings.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_UNSUPPORTED_INJECT_ADMIN_USER_ENABLED = Setting.boolSetting(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_ADMIN_USER_ENABLED, LegacyOpenDistroSecuritySettings.SECURITY_UNSUPPORTED_INJECT_ADMIN_USER_ENABLED, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_UNSUPPORTED_ALLOW_NOW_IN_DLS = Setting.boolSetting(ConfigConstants.SECURITY_UNSUPPORTED_ALLOW_NOW_IN_DLS, LegacyOpenDistroSecuritySettings.SECURITY_UNSUPPORTED_ALLOW_NOW_IN_DLS, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION = Setting.boolSetting(ConfigConstants.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, LegacyOpenDistroSecuritySettings.SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_UNSUPPORTED_LOAD_STATIC_RESOURCES = Setting.boolSetting(ConfigConstants.SECURITY_UNSUPPORTED_LOAD_STATIC_RESOURCES, LegacyOpenDistroSecuritySettings.SECURITY_UNSUPPORTED_LOAD_STATIC_RESOURCES, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_SSL_CERT_RELOAD_ENABLED = Setting.boolSetting(ConfigConstants.SECURITY_SSL_CERT_RELOAD_ENABLED, LegacyOpenDistroSecuritySettings.SECURITY_SSL_CERT_RELOAD_ENABLED, Setting.Property.NodeScope, Setting.Property.Filtered);
    public static final Setting<Boolean> SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG = Setting.boolSetting(ConfigConstants.SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG, LegacyOpenDistroSecuritySettings.SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG, Setting.Property.NodeScope, Setting.Property.Filtered);
}
