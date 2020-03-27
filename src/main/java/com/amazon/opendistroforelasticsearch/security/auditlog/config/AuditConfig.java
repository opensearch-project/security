package com.amazon.opendistroforelasticsearch.security.auditlog.config;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.google.common.collect.ImmutableSet;
import org.elasticsearch.common.settings.Settings;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class AuditConfig {
    private static final List<String> DEFAULT_IGNORED_USERS = Collections.singletonList("kibanaserver");
    private static final List<String> DEFAULT_DISABLED_CATEGORIES =
            Arrays.asList(AuditCategory.AUTHENTICATED.toString(),
                    AuditCategory.GRANTED_PRIVILEGES.toString());

    private final boolean isRestApiAuditEnabled;
    private final boolean isTransportAuditEnabled;
    private final boolean resolveBulkRequests;
    private final boolean logRequestBody;
    private final boolean resolveIndices;
    private final boolean excludeSensitiveHeaders;
    private final Set<String> ignoredAuditUsers;
    private final Set<String> ignoredComplianceUsersForRead;
    private final Set<String> ignoredComplianceUsersForWrite;
    private final Set<String> ignoreAuditRequests;
    private final EnumSet<AuditCategory> disabledRestCategories;
    private final EnumSet<AuditCategory> disabledTransportCategories;
    private final String opendistrosecurityIndex;

    private AuditConfig(final boolean isRestApiAuditEnabled,
                        final boolean isTransportAuditEnabled,
                        final boolean resolveBulkRequests,
                        final boolean logRequestBody,
                        final boolean resolveIndices,
                        final boolean excludeSensitiveHeaders,
                        final Set<String> ignoredAuditUsers,
                        final Set<String> ignoredComplianceUsersForRead,
                        final Set<String> ignoredComplianceUsersForWrite,
                        final Set<String> ignoredAuditRequests,
                        final EnumSet<AuditCategory> disabledRestCategories,
                        final EnumSet<AuditCategory> disabledTransportCategories,
                        final String opendistrosecurityIndex) {
        this.isRestApiAuditEnabled = isRestApiAuditEnabled;
        this.isTransportAuditEnabled = isTransportAuditEnabled;
        this.resolveBulkRequests = resolveBulkRequests;
        this.logRequestBody = logRequestBody;
        this.resolveIndices = resolveIndices;
        this.excludeSensitiveHeaders = excludeSensitiveHeaders;
        this.ignoredAuditUsers = ignoredAuditUsers;
        this.ignoredComplianceUsersForRead = ignoredComplianceUsersForRead;
        this.ignoredComplianceUsersForWrite = ignoredComplianceUsersForWrite;
        this.ignoreAuditRequests = ignoredAuditRequests;
        this.disabledRestCategories = disabledRestCategories;
        this.disabledTransportCategories = disabledTransportCategories;
        this.opendistrosecurityIndex = opendistrosecurityIndex;
    }

    public static AuditConfig getConfig(Settings settings) {
        final boolean isRestApiAuditEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true);
        final boolean isTransportAuditEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true);
        final boolean resolveBulkRequests = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false);
        final boolean logRequestBody = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, true);
        final boolean resolveIndices = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, true);
        final boolean excludeSensitiveHeaders = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS, true);
        final String opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);

        final EnumSet<AuditCategory> disabledRestCategories;
        final List<String> disabledRestCategoriesList = settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES, DEFAULT_DISABLED_CATEGORIES);
        if (disabledRestCategoriesList.isEmpty() || (disabledRestCategoriesList.size() == 1 && "NONE".equalsIgnoreCase(disabledRestCategoriesList.get(0)))) {
            disabledRestCategories = EnumSet.noneOf(AuditCategory.class);
        } else {
            disabledRestCategories = AuditCategory.parse(disabledRestCategoriesList);
        }

        final EnumSet<AuditCategory> disabledTransportCategories;
        final List<String> disabledTransportCategoriesList = settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES, DEFAULT_DISABLED_CATEGORIES);
        if (disabledTransportCategoriesList.isEmpty() || (disabledTransportCategoriesList.size() == 1 && "NONE".equalsIgnoreCase(disabledTransportCategoriesList.get(0)))) {
            disabledTransportCategories = EnumSet.noneOf(AuditCategory.class);
        } else {
            disabledTransportCategories = AuditCategory.parse(disabledTransportCategoriesList);
        }

        final List<String> ignoredAuditUsers = new ArrayList<>(settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS, DEFAULT_IGNORED_USERS));
        if (ignoredAuditUsers.size() == 1 && "NONE".equals(ignoredAuditUsers.get(0))) {
            ignoredAuditUsers.clear();
        }

        final List<String> ignoredComplianceUsersForRead = new ArrayList<>(settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS, DEFAULT_IGNORED_USERS));
        if (ignoredComplianceUsersForRead.size() == 1 && "NONE".equals(ignoredComplianceUsersForRead.get(0))) {
            ignoredComplianceUsersForRead.clear();
        }

        final List<String> ignoredComplianceUsersForWrite = new ArrayList<>(settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS, DEFAULT_IGNORED_USERS));
        if (ignoredComplianceUsersForWrite.size() == 1 && "NONE".equals(ignoredComplianceUsersForWrite.get(0))) {
            ignoredComplianceUsersForWrite.clear();
        }

        final List<String> ignoreAuditRequests = settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS, Collections.emptyList());

        return new AuditConfig(isRestApiAuditEnabled,
                isTransportAuditEnabled,
                resolveBulkRequests,
                logRequestBody,
                resolveIndices,
                excludeSensitiveHeaders,
                ImmutableSet.copyOf(ignoredAuditUsers),
                ImmutableSet.copyOf(ignoredComplianceUsersForRead),
                ImmutableSet.copyOf(ignoredComplianceUsersForWrite),
                ImmutableSet.copyOf(ignoreAuditRequests),
                disabledRestCategories,
                disabledTransportCategories,
                opendistrosecurityIndex);
    }

    private static List<String> getSettingAsList(final Settings settings, final String key, final List<String> defaultList) {
        final List<String> list = settings.getAsList(key, defaultList);
        if (list.size() == 1 && "NONE".equals(list.get(0))) {
            return Collections.emptyList();
        }
        return list;
    }

    public boolean isRestAuditingEnabled() {
        return isRestApiAuditEnabled;
    }

    public boolean isTransportAuditingEnabled() {
        return isTransportAuditEnabled;
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

    public Set<String> getIgnoredAuditUsers() {
        return ignoredAuditUsers;
    }

    public Set<String> getIgnoredComplianceUsersForRead() {
        return ignoredComplianceUsersForRead;
    }

    public Set<String> getIgnoredComplianceUsersForWrite() {
        return ignoredComplianceUsersForWrite;
    }

    public Set<String> getIgnoredAuditRequests() {
        return ignoreAuditRequests;
    }

    public EnumSet<AuditCategory> getDisabledRestCategories() {
        return disabledRestCategories;
    }

    public EnumSet<AuditCategory> getDisabledTransportCategories() {
        return disabledTransportCategories;
    }

    public String getOpendistrosecurityIndex() {
        return opendistrosecurityIndex;
    }

    @Override
    public String toString() {
        return "AuditConfig{" +
                "isRestApiAuditEnabled=" + isRestApiAuditEnabled +
                ", isTransportAuditEnabled=" + isTransportAuditEnabled +
                ", resolveBulkRequests=" + resolveBulkRequests +
                ", logRequestBody=" + logRequestBody +
                ", resolveIndices=" + resolveIndices +
                ", excludeSensitiveHeaders=" + excludeSensitiveHeaders +
                ", ignoredAuditUsers=" + ignoredAuditUsers +
                ", ignoredComplianceUsersForRead=" + ignoredComplianceUsersForRead +
                ", ignoredComplianceUsersForWrite=" + ignoredComplianceUsersForWrite +
                ", ignoreAuditRequests=" + ignoreAuditRequests +
                ", disabledRestCategories=" + disabledRestCategories +
                ", disabledTransportCategories=" + disabledTransportCategories +
                ", opendistrosecurityIndex='" + opendistrosecurityIndex + '\'' +
                '}';
    }
}
