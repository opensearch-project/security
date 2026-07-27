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

import java.util.Collections;
import java.util.List;
import java.util.function.Function;

import org.opensearch.common.settings.Setting;
import org.opensearch.security.auditlog.config.AuditConfig;

public class SecuritySettings {
    public static final Setting<Boolean> LEGACY_OPENDISTRO_SSL_DUAL_MODE_SETTING = Setting.boolSetting(
        ConfigConstants.LEGACY_OPENDISTRO_SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED,
        false,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Deprecated
    ); // Not filtered
    public static final Setting<Boolean> SSL_DUAL_MODE_SETTING = Setting.boolSetting(
        ConfigConstants.SECURITY_CONFIG_SSL_DUAL_MODE_ENABLED,
        LEGACY_OPENDISTRO_SSL_DUAL_MODE_SETTING,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    ); // Not filtered

    public static final Setting<Integer> CACHE_TTL_SETTING = Setting.intSetting(
        ConfigConstants.SECURITY_CACHE_TTL_MINUTES,
        60,
        0,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    ); // Not filtered

    public static final Setting<Boolean> USER_ATTRIBUTE_SERIALIZATION_ENABLED_SETTING = Setting.boolSetting(
        ConfigConstants.USER_ATTRIBUTE_SERIALIZATION_ENABLED,
        ConfigConstants.USER_ATTRIBUTE_SERIALIZATION_ENABLED_DEFAULT,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    ); // Not filtered

    public static final Setting<Boolean> DLS_WRITE_BLOCKED = Setting.boolSetting(
        ConfigConstants.SECURITY_DLS_WRITE_BLOCKED,
        false,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic
    );

    public static final Setting<Boolean> DFM_EMPTY_OVERRIDES_ALL_SETTING = Setting.boolSetting(
        ConfigConstants.SECURITY_DFM_EMPTY_OVERRIDES_ALL,
        false,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<Boolean> AUDIT_ENABLED_SETTING = Setting.boolSetting(
        ConfigConstants.SECURITY_AUDIT_ENABLED,
        true,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    // Dynamic audit filter settings
    private static final String AUDIT_CONFIG_PREFIX = "plugins.security.audit.config.";

    public static final Setting<Boolean> AUDIT_LOG_REQUEST_BODY = Setting.boolSetting(
        AUDIT_CONFIG_PREFIX + "log_request_body",
        true,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<Boolean> AUDIT_RESOLVE_BULK_REQUESTS = Setting.boolSetting(
        AUDIT_CONFIG_PREFIX + "resolve_bulk_requests",
        false,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<Boolean> AUDIT_RESOLVE_INDICES = Setting.boolSetting(
        AUDIT_CONFIG_PREFIX + "resolve_indices",
        true,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<Boolean> AUDIT_EXCLUDE_SENSITIVE_HEADERS = Setting.boolSetting(
        AUDIT_CONFIG_PREFIX + "exclude_sensitive_headers",
        true,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<Boolean> AUDIT_ENABLE_REST = Setting.boolSetting(
        AUDIT_CONFIG_PREFIX + "enable_rest",
        true,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<Boolean> AUDIT_ENABLE_TRANSPORT = Setting.boolSetting(
        AUDIT_CONFIG_PREFIX + "enable_transport",
        true,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<List<String>> AUDIT_DISABLED_CATEGORIES = Setting.listSetting(
        AUDIT_CONFIG_PREFIX + "disabled_categories",
        Collections.emptyList(),
        Function.identity(),
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<List<String>> AUDIT_DISABLED_REST_CATEGORIES = Setting.listSetting(
        AUDIT_CONFIG_PREFIX + "disabled_rest_categories",
        List.of("AUTHENTICATED", "GRANTED_PRIVILEGES"),
        Function.identity(),
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<List<String>> AUDIT_DISABLED_TRANSPORT_CATEGORIES = Setting.listSetting(
        AUDIT_CONFIG_PREFIX + "disabled_transport_categories",
        List.of("AUTHENTICATED", "GRANTED_PRIVILEGES"),
        Function.identity(),
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<List<String>> AUDIT_IGNORE_USERS = Setting.listSetting(
        AUDIT_CONFIG_PREFIX + "ignore_users",
        List.of("kibanaserver"),
        Function.identity(),
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<List<String>> AUDIT_IGNORE_REQUESTS = Setting.listSetting(
        AUDIT_CONFIG_PREFIX + "ignore_requests",
        Collections.emptyList(),
        Function.identity(),
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<List<String>> AUDIT_IGNORE_HEADERS = Setting.listSetting(
        AUDIT_CONFIG_PREFIX + "ignore_headers",
        Collections.emptyList(),
        Function.identity(),
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    // Dynamic compliance settings
    private static final String COMPLIANCE_PREFIX = "plugins.security.audit.compliance.";

    public static final Setting<Boolean> COMPLIANCE_ENABLED = Setting.boolSetting(
        COMPLIANCE_PREFIX + "enabled",
        true,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<List<String>> COMPLIANCE_WRITE_WATCHED_INDICES = Setting.listSetting(
        COMPLIANCE_PREFIX + "write_watched_indices",
        Collections.emptyList(),
        Function.identity(),
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<Boolean> COMPLIANCE_WRITE_METADATA_ONLY = Setting.boolSetting(
        COMPLIANCE_PREFIX + "write_metadata_only",
        false,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<Boolean> COMPLIANCE_WRITE_LOG_DIFFS = Setting.boolSetting(
        COMPLIANCE_PREFIX + "write_log_diffs",
        false,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<Boolean> COMPLIANCE_EXTERNAL_CONFIG_ENABLED = Setting.boolSetting(
        COMPLIANCE_PREFIX + "external_config",
        false,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<Boolean> COMPLIANCE_INTERNAL_CONFIG_ENABLED = Setting.boolSetting(
        COMPLIANCE_PREFIX + "internal_config",
        false,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<Boolean> COMPLIANCE_READ_METADATA_ONLY = Setting.boolSetting(
        COMPLIANCE_PREFIX + "read_metadata_only",
        false,
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<List<String>> COMPLIANCE_READ_WATCHED_FIELDS = Setting.listSetting(
        COMPLIANCE_PREFIX + "read_watched_fields",
        Collections.emptyList(),
        Function.identity(),
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<List<String>> COMPLIANCE_READ_IGNORE_USERS = Setting.listSetting(
        COMPLIANCE_PREFIX + "read_ignore_users",
        AuditConfig.DEFAULT_IGNORED_USERS,
        Function.identity(),
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );

    public static final Setting<List<String>> COMPLIANCE_WRITE_IGNORE_USERS = Setting.listSetting(
        COMPLIANCE_PREFIX + "write_ignore_users",
        AuditConfig.DEFAULT_IGNORED_USERS,
        Function.identity(),
        Setting.Property.NodeScope,
        Setting.Property.Dynamic,
        Setting.Property.Sensitive
    );
}
