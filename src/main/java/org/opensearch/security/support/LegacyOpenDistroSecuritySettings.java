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

public class LegacyOpenDistroSecuritySettings {
    public static final Setting<Boolean> SECURITY_SSL_ONLY = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_SSL_ONLY, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);

    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_SSL_ONLY, false, Setting.Property.NodeScope, Setting.Property.Filtered));

    // currently dual mode is supported only when ssl_only is enabled, but this stance would change in future
    //settings.add(OpenDistroSSLConfig.SSL_DUAL_MODE_SETTING);

    // Protected index settings
    public static final Setting<Boolean> SECURITY_PROTECTED_INDICES_ENABLED_KEY = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ENABLED_KEY, LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ENABLED_DEFAULT, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Final, Setting.Property.Deprecated);
    public static final Setting<List<String>> SECURITY_PROTECTED_INDICES_KEY = Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_KEY, LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_DEFAULT, Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Final, Setting.Property.Deprecated);
    public static final Setting<List<String>> SECURITY_PROTECTED_INDICES_ROLES_KEY = Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ROLES_KEY, LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ROLES_DEFAULT, Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Final, Setting.Property.Deprecated);

    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ENABLED_KEY, ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ENABLED_DEFAULT, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Final));
    //settings.add(Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_KEY, ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_DEFAULT, Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Final));
    //settings.add(Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ROLES_KEY, ConfigConstants.OPENDISTRO_SECURITY_PROTECTED_INDICES_ROLES_DEFAULT, Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Final));

    // System index settings
    public static final Setting<Boolean> SECURITY_SYSTEM_INDICES_ENABLED_KEY = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_SYSTEM_INDICES_ENABLED_KEY, LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_SYSTEM_INDICES_ENABLED_DEFAULT, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Final, Setting.Property.Deprecated);
    public static final Setting<List<String>> SECURITY_SYSTEM_INDICES_KEY = Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_SYSTEM_INDICES_KEY, LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_SYSTEM_INDICES_DEFAULT, Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Final, Setting.Property.Deprecated);

    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_SYSTEM_INDICES_ENABLED_KEY, ConfigConstants.OPENDISTRO_SECURITY_SYSTEM_INDICES_ENABLED_DEFAULT, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Final));
    //settings.add(Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_SYSTEM_INDICES_KEY, ConfigConstants.OPENDISTRO_SECURITY_SYSTEM_INDICES_DEFAULT, Function.identity(), Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Final));

    //if(!openDistroSSLConfig.isSslOnlyMode()) {
    public static final Setting<List<String>> SECURITY_AUTHCZ_ADMIN_DN = Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUTHCZ_ADMIN_DN, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<String> SECURITY_CONFIG_INDEX_NAME = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<Settings> SECURITY_AUTHCZ_IMPERSONATION_DN = Setting.groupSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUTHCZ_IMPERSONATION_DN+".", Setting.Property.NodeScope, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_CERT_OID = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_CERT_OID, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_CERT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_CERT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<List<String>> SECURITY_NODES_DN = Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_NODES_DN, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<Boolean> SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<Boolean> SECURITY_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE, LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_DEFAULT_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES, LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_DISABLED = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_DISABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Integer> SECURITY_CACHE_TTL_MINUTES = Setting.intSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_CACHE_TTL_MINUTES, 60, 0, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);

    //settings.add(Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUTHCZ_ADMIN_DN, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope)); //not filtered here

    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.groupSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUTHCZ_IMPERSONATION_DN+".", Setting.Property.NodeScope)); //not filtered here

    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_CERT_OID, Setting.Property.NodeScope, Setting.Property.Filtered));

    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_CERT_INTERCLUSTER_REQUEST_EVALUATOR_CLASS, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_NODES_DN, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope));//not filtered here

    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED, false, Setting.Property.NodeScope));//not filtered here

    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE,
    //        Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES,
    //        Setting.Property.NodeScope, Setting.Property.Filtered));

    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_DISABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));

    //settings.add(Setting.intSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_CACHE_TTL_MINUTES, 60, 0, Setting.Property.NodeScope, Setting.Property.Filtered));

    //Security
    public static final Setting<Boolean> SECURITY_ADVANCED_MODULES_ENABLED = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_ADVANCED_MODULES_ENABLED, true, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_ALLOW_UNSAFE_DEMOCERTIFICATES = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_ALLOW_UNSAFE_DEMOCERTIFICATES, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, true, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Settings> SECURITY_AUTHCZ_REST_IMPERSONATION_USERS = Setting.groupSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUTHCZ_REST_IMPERSONATION_USERS+".", Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<String> SECURITY_ROLES_MAPPING_RESOLUTION = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_ROLES_MAPPING_RESOLUTION, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_DISABLE_ENVVAR_REPLACEMENT = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_DISABLE_ENVVAR_REPLACEMENT, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);

    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_ADVANCED_MODULES_ENABLED, true, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_ALLOW_UNSAFE_DEMOCERTIFICATES, false, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, false, Setting.Property.NodeScope, Setting.Property.Filtered));
    //ettings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST, true, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.groupSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUTHCZ_REST_IMPERSONATION_USERS+".", Setting.Property.NodeScope)); //not filtered here

    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_ROLES_MAPPING_RESOLUTION, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_DISABLE_ENVVAR_REPLACEMENT, false, Setting.Property.NodeScope, Setting.Property.Filtered));

    // Security - Audit
    public static final Setting<String> SECURITY_AUDIT_TYPE_DEFAULT = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_TYPE_DEFAULT, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Settings> SECURITY_AUDIT_CONFIG_ROUTES = Setting.groupSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_ROUTES + ".", Setting.Property.NodeScope, Setting.Property.Deprecated);
    public static final Setting<Settings> SECURITY_AUDIT_CONFIG_ENDPOINTS = Setting.groupSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_ENDPOINTS + ".",  Setting.Property.NodeScope, Setting.Property.Deprecated);
    public static final Setting<Integer> SECURITY_AUDIT_THREADPOOL_SIZE = Setting.intSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_THREADPOOL_SIZE, 10, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Integer> SECURITY_AUDIT_THREADPOOL_MAX_QUEUE_LEN = Setting.intSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_THREADPOOL_MAX_QUEUE_LEN, 100*1000, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_AUDIT_LOG_REQUEST_BODY = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, true, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_AUDIT_RESOLVE_INDICES = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, true, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_AUDIT_ENABLE_REST = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_AUDIT_ENABLE_TRANSPORT = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_TYPE_DEFAULT, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.groupSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_ROUTES + ".", Setting.Property.NodeScope));
    //settings.add(Setting.groupSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_ENDPOINTS + ".",  Setting.Property.NodeScope));
    //settings.add(Setting.intSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_THREADPOOL_SIZE, 10, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.intSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_THREADPOOL_MAX_QUEUE_LEN, 100*1000, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, true, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, true, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true, Setting.Property.NodeScope, Setting.Property.Filtered));
    //private static final List<String> disabledCategories = Stream.of("AUTHENTICATED", "GRANTED_PRIVILEGES").collect(Collectors.toCollection(ArrayList<String>::new));
    //disabledCategories.add("AUTHENTICATED");
    //disabledCategories.add("GRANTED_PRIVILEGES");
    public static final Setting<List<String>> SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES = Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, Lists.newArrayList("AUTHENTICATED", "GRANTED_PRIVILEGES"), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<List<String>> SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES = Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, Lists.newArrayList("AUTHENTICATED", "GRANTED_PRIVILEGES"), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    //settings.add(Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, disabledCategories, Function.identity(), Setting.Property.NodeScope)); //not filtered here
    //settings.add(Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, disabledCategories, Function.identity(), Setting.Property.NodeScope)); //not filtered here
    //private static final List<String> ignoredUsers = Stream.of("kibanaserver").collect(Collectors.toCollection(ArrayList<String>::new));
    //ignoredUsers.add("kibanaserver");
    public static final Setting<List<String>> SECURITY_AUDIT_IGNORE_USERS = Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, Lists.newArrayList("kibanaserver"), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<List<String>> SECURITY_AUDIT_IGNORE_REQUESTS = Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<Boolean> SECURITY_AUDIT_RESOLVE_BULK_REQUESTS = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS, true, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    //settings.add(Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, ignoredUsers, Function.identity(), Setting.Property.NodeScope)); //not filtered here
    //settings.add(Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope)); //not filtered here
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS, true, Setting.Property.NodeScope, Setting.Property.Filtered));


    // Security - Audit - Sink
    public static final Setting<String> SECURITY_AUDIT_OPENSEARCH_INDEX = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_OPENSEARCH_INDEX, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_AUDIT_OPENSEARCH_TYPE = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_OPENSEARCH_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_OPENSEARCH_INDEX, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_OPENSEARCH_TYPE, Setting.Property.NodeScope, Setting.Property.Filtered));

    // External OpenSearch
    public static final Setting<List<String>> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_HTTP_ENDPOINTS = Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_HTTP_ENDPOINTS, Lists.newArrayList("localhost:9200"), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_USERNAME = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_USERNAME, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PASSWORD = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_VERIFY_HOSTNAMES = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_VERIFY_HOSTNAMES, true, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL_CLIENT_AUTH = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL_CLIENT_AUTH, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_CONTENT = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_CONTENT, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_FILEPATH = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_CONTENT = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_CONTENT, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_FILEPATH = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_PASSWORD = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_CONTENT = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_CONTENT, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_FILEPATH = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_JKS_CERT_ALIAS = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_JKS_CERT_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<List<String>> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_CIPHERS = Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_CIPHERS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<List<String>> SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_PROTOCOLS = Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_PROTOCOLS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here

    //settings.add(Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_HTTP_ENDPOINTS, Lists.newArrayList("localhost:9200"), Function.identity(), Setting.Property.NodeScope)); //not filtered here
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_USERNAME, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL, false, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_VERIFY_HOSTNAMES, true, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLE_SSL_CLIENT_AUTH, false, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_CONTENT, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMCERT_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_CONTENT, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMKEY_PASSWORD, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_CONTENT, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_PEMTRUSTEDCAS_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_JKS_CERT_ALIAS, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_CIPHERS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope));//not filtered here
    //settings.add(Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXTERNAL_OPENSEARCH_ENABLED_SSL_PROTOCOLS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope));//not filtered here

    // Webhooks
    public static final Setting<String> SECURITY_AUDIT_WEBHOOK_URL = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_WEBHOOK_URL, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_AUDIT_WEBHOOK_FORMAT = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_WEBHOOK_FORMAT, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_AUDIT_WEBHOOK_SSL_VERIFY = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_WEBHOOK_SSL_VERIFY, true, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_FILEPATH = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_CONTENT = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_CONTENT, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);

    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_WEBHOOK_URL, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_WEBHOOK_FORMAT, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_WEBHOOK_SSL_VERIFY, true, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_WEBHOOK_PEMTRUSTEDCAS_CONTENT, Setting.Property.NodeScope, Setting.Property.Filtered));

    // Log4j
    public static final Setting<String> SECURITY_AUDIT_LOG4J_LOGGER_NAME = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG4J_LOGGER_NAME, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_AUDIT_LOG4J_LEVEL = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG4J_LEVEL, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);

    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG4J_LOGGER_NAME, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG4J_LEVEL, Setting.Property.NodeScope, Setting.Property.Filtered));


    // Kerberos
    public static final Setting<String> SECURITY_KERBEROS_KRB5_FILEPATH = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_KERBEROS_KRB5_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_KERBEROS_ACCEPTOR_KEYTAB_FILEPATH = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_KERBEROS_ACCEPTOR_KEYTAB_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_KERBEROS_ACCEPTOR_PRINCIPAL = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_KERBEROS_ACCEPTOR_PRINCIPAL, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);

    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_KERBEROS_KRB5_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_KERBEROS_ACCEPTOR_KEYTAB_FILEPATH, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_KERBEROS_ACCEPTOR_PRINCIPAL, Setting.Property.NodeScope, Setting.Property.Filtered));


    // Open Distro Security - REST API
    public static final Setting<List<String>> SECURITY_RESTAPI_ROLES_ENABLED = Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_RESTAPI_ROLES_ENABLED, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<Settings> SECURITY_RESTAPI_ENDPOINTS_DISABLED = Setting.groupSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_RESTAPI_ENDPOINTS_DISABLED + ".", Setting.Property.NodeScope, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<String> SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    //settings.add(Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_RESTAPI_ROLES_ENABLED, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope)); //not filtered here
    //settings.add(Setting.groupSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_RESTAPI_ENDPOINTS_DISABLED + ".", Setting.Property.NodeScope));

    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_RESTAPI_PASSWORD_VALIDATION_REGEX, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_RESTAPI_PASSWORD_VALIDATION_ERROR_MESSAGE, Setting.Property.NodeScope, Setting.Property.Filtered));


    // Compliance
    public static final Setting<List<String>> SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES = Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<List<String>> SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS = Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<Boolean> SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<List<String>> SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS = Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<List<String>> SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS = Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<Boolean> SECURITY_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<List<String>> SECURITY_COMPLIANCE_IMMUTABLE_INDICES = Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_IMMUTABLE_INDICES, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope, Setting.Property.Deprecated); //not filtered here
    public static final Setting<String> SECURITY_COMPLIANCE_SALT = Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_FILTER_SECURITYINDEX_FROM_ALL_REQUESTS = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_FILTER_SECURITYINDEX_FROM_ALL_REQUESTS, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    //settings.add(Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope)); //not filtered here
    //settings.add(Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope)); //not filtered here
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY, false, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY, false, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, false, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope)); //not filtered here
    //settings.add(Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope)); //not filtered here
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_DISABLE_ANONYMOUS_AUTHENTICATION, false, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.listSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_IMMUTABLE_INDICES, Collections.emptyList(), Function.identity(), Setting.Property.NodeScope)); //not filtered here
    //settings.add(Setting.simpleString(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));

    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_FILTER_SECURITYINDEX_FROM_ALL_REQUESTS, false, Setting.Property.NodeScope,
    //        Setting.Property.Filtered));

    //compat
    public static final Setting<Boolean> SECURITY_UNSUPPORTED_DISABLE_INTERTRANSPORT_AUTH_INITIALLY = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_DISABLE_INTERTRANSPORT_AUTH_INITIALLY, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_UNSUPPORTED_DISABLE_REST_AUTH_INITIALLY = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_DISABLE_REST_AUTH_INITIALLY, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_DISABLE_INTERTRANSPORT_AUTH_INITIALLY, false, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_DISABLE_REST_AUTH_INITIALLY, false, Setting.Property.NodeScope, Setting.Property.Filtered));

    // system integration
    public static final Setting<Boolean> SECURITY_UNSUPPORTED_RESTORE_SECURITYINDEX_ENABLED = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_RESTORE_SECURITYINDEX_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_UNSUPPORTED_INJECT_USER_ENABLED = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_UNSUPPORTED_INJECT_ADMIN_USER_ENABLED = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_INJECT_ADMIN_USER_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_UNSUPPORTED_ALLOW_NOW_IN_DLS = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_ALLOW_NOW_IN_DLS, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_UNSUPPORTED_LOAD_STATIC_RESOURCES = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_LOAD_STATIC_RESOURCES, true, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_SSL_CERT_RELOAD_ENABLED = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_SSL_CERT_RELOAD_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    public static final Setting<Boolean> SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG = Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG, false, Setting.Property.NodeScope, Setting.Property.Filtered, Setting.Property.Deprecated);
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_RESTORE_SECURITYINDEX_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_INJECT_ADMIN_USER_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_ALLOW_NOW_IN_DLS, false, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_RESTAPI_ALLOW_SECURITYCONFIG_MODIFICATION, false, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_LOAD_STATIC_RESOURCES, true, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_SSL_CERT_RELOAD_ENABLED, false, Setting.Property.NodeScope, Setting.Property.Filtered));
    //settings.add(Setting.boolSetting(LegacyOpenDistroConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG, false, Setting.Property.NodeScope, Setting.Property.Filtered));
    //}
}
