package com.amazon.opendistroforelasticsearch.security.auditlog;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import org.elasticsearch.common.settings.Settings;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;

public class AuditConfig {
    private final boolean restAuditingEnabled;
    private final boolean transportAuditingEnabled;
    private final boolean resolveBulkRequests;
    private final boolean logRequestBody;
    private final boolean resolveIndices;
    private final boolean excludeSensitiveHeaders;
    private final List<String> ignoredAuditUsers;
    private final List<String> ignoredComplianceUsersForRead;
    private final List<String> ignoredComplianceUsersForWrite;
    private final List<String> ignoreAuditRequests;
    private final EnumSet<AuditCategory> disabledRestCategories;
    private final EnumSet<AuditCategory> disabledTransportCategories;

    public AuditConfig(final boolean restAuditingEnabled,
                       final boolean transportAuditingEnabled,
                       final boolean resolveBulkRequests,
                       final boolean logRequestBody,
                       final boolean resolveIndices,
                       final boolean excludeSensitiveHeaders,
                       final List<String> ignoredAuditUsers,
                       final List<String> ignoredComplianceUsersForRead,
                       final List<String> ignoredComplianceUsersForWrite,
                       final List<String> ignoreAuditRequests,
                       final EnumSet<AuditCategory> disabledRestCategories,
                       final EnumSet<AuditCategory> disabledTransportCategories) {
        this.restAuditingEnabled = restAuditingEnabled;
        this.transportAuditingEnabled = transportAuditingEnabled;
        this.resolveBulkRequests = resolveBulkRequests;
        this.logRequestBody = logRequestBody;
        this.resolveIndices = resolveIndices;
        this.excludeSensitiveHeaders = excludeSensitiveHeaders;
        this.ignoredAuditUsers = ignoredAuditUsers;
        this.ignoredComplianceUsersForRead = ignoredComplianceUsersForRead;
        this.ignoredComplianceUsersForWrite = ignoredComplianceUsersForWrite;
        this.ignoreAuditRequests = ignoreAuditRequests;
        this.disabledRestCategories = disabledRestCategories;
        this.disabledTransportCategories = disabledTransportCategories;
    }

    public static AuditConfig getConfig(Settings settings) {
        boolean restAuditingEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true);
        boolean transportAuditingEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true);
        boolean resolveBulkRequests = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false);
        boolean logRequestBody = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, true);
        boolean resolveIndices = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, true);
        boolean excludeSensitiveHeaders = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS, true);

        final List<String> defaultDisabledCategories = Arrays.asList(AuditCategory.AUTHENTICATED.toString(), AuditCategory.GRANTED_PRIVILEGES.toString());

        EnumSet<AuditCategory> disabledRestCategories = AuditCategory.parse(getConfigList(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES,
                defaultDisabledCategories));

        EnumSet<AuditCategory> disabledTransportCategories = AuditCategory.parse(getConfigList(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES,
                defaultDisabledCategories));
        final List<String> defaultIgnoredUsers = Arrays.asList("kibanaserver");

        List<String> ignoredAuditUsers = getConfigList(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS,
                defaultIgnoredUsers);

        List<String> ignoredComplianceUsersForRead = getConfigList(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS,
                defaultIgnoredUsers);

        List<String> ignoredComplianceUsersForWrite = getConfigList(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS,
                defaultIgnoredUsers);

        List<String> ignoreAuditRequests = getConfigList(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS,
                Collections.emptyList());

        return new AuditConfig(
                restAuditingEnabled,
                transportAuditingEnabled,
                resolveBulkRequests,
                logRequestBody,
                resolveIndices,
                excludeSensitiveHeaders,
                ignoredAuditUsers,
                ignoredComplianceUsersForRead,
                ignoredComplianceUsersForWrite,
                ignoreAuditRequests,
                disabledRestCategories,
                disabledTransportCategories);
    }

    private static List<String> getConfigList(final Settings settings,
                                              final String key,
                                              final List<String> defaultList) {
        List<String> list = new ArrayList<>(settings.getAsList(key, defaultList));
        if (list.size() == 1 && "NONE".equals(list.get(0))) {
            list.clear();
        }
        return list;
    }

    public boolean isRestAuditingEnabled() {
        return restAuditingEnabled;
    }

    public boolean isTransportAuditingEnabled() {
        return transportAuditingEnabled;
    }

    public boolean shouldResolveBulkRequests() {
        return resolveBulkRequests;
    }

    public boolean shouldLogRequestBody() {
        return logRequestBody;
    }

    public boolean shouldResolveIndices() {
        return resolveIndices;
    }

    public boolean shouldExcludeSensitiveHeaders() {
        return excludeSensitiveHeaders;
    }

    public List<String> getIgnoredAuditUsers() {
        return ignoredAuditUsers;
    }

    public List<String> getIgnoredComplianceUsersForRead() {
        return ignoredComplianceUsersForRead;
    }

    public List<String> getIgnoredComplianceUsersForWrite() {
        return ignoredComplianceUsersForWrite;
    }

    public List<String> getIgnoreAuditRequests() {
        return ignoreAuditRequests;
    }

    public EnumSet<AuditCategory> getDisabledRestCategories() {
        return disabledRestCategories;
    }

    public EnumSet<AuditCategory> getDisabledTransportCategories() {
        return disabledTransportCategories;
    }
}
