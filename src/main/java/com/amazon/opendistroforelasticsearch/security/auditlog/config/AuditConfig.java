package com.amazon.opendistroforelasticsearch.security.auditlog.config;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

public class AuditConfig {
    private static final List<String> DEFAULT_IGNORED_USERS = Collections.singletonList("kibanaserver");
    private static final List<String> DEFAULT_DISABLED_CATEGORIES =
            Arrays.asList(AuditCategory.AUTHENTICATED.toString(),
                    AuditCategory.GRANTED_PRIVILEGES.toString());

    private final boolean isRestApiAuditEnabled;
    private final boolean isTransportApiAuditEnabled;
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
                        final boolean isTransportApiAuditEnabled,
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
        this.isTransportApiAuditEnabled = isTransportApiAuditEnabled;
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

    public static AuditConfig from(Settings settings) {
        final boolean isRestApiAuditEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true);
        final boolean isTransportAuditEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true);
        final boolean resolveBulkRequests = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false);
        final boolean logRequestBody = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, true);
        final boolean resolveIndices = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, true);
        final boolean excludeSensitiveHeaders = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS, true);
        final String opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);

        final EnumSet<AuditCategory> disabledRestCategories = AuditCategory.parse(getSettingAsList(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES,
                DEFAULT_DISABLED_CATEGORIES,
                true));

        final EnumSet<AuditCategory> disabledTransportCategories = AuditCategory.parse(getSettingAsList(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES,
                DEFAULT_DISABLED_CATEGORIES,
                true));

        final Set<String> ignoredAuditUsers = ImmutableSet.copyOf(getSettingAsList(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS,
                DEFAULT_IGNORED_USERS,
                false));

        final Set<String> ignoredComplianceUsersForRead = ImmutableSet.copyOf(getSettingAsList(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS,
                DEFAULT_IGNORED_USERS,
                false));

        final Set<String> ignoredComplianceUsersForWrite = ImmutableSet.copyOf(getSettingAsList(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS,
                DEFAULT_IGNORED_USERS,
                false));

        final Set<String> ignoreAuditRequests = ImmutableSet.copyOf(settings.getAsList(
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS,
                Collections.emptyList()));

        return new AuditConfig(isRestApiAuditEnabled,
                isTransportAuditEnabled,
                resolveBulkRequests,
                logRequestBody,
                resolveIndices,
                excludeSensitiveHeaders,
                ignoredAuditUsers,
                ignoredComplianceUsersForRead,
                ignoredComplianceUsersForWrite,
                ignoreAuditRequests,
                disabledRestCategories,
                disabledTransportCategories,
                opendistrosecurityIndex);
    }

    private static List<String> getSettingAsList(final Settings settings, final String key, final List<String> defaultList, final boolean ignoreCaseForNone) {
        final List<String> list = settings.getAsList(key, defaultList);
        if (list.size() == 1 && "NONE".equals(ignoreCaseForNone? list.get(0).toUpperCase() : list.get(0))) {
            return Collections.emptyList();
        }
        return list;
    }

    public boolean isRestApiAuditEnabled() {
        return isRestApiAuditEnabled;
    }

    public boolean isTransportApiAuditEnabled() {
        return isTransportApiAuditEnabled;
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

    public void log(Logger logger) {
        logger.info("Auditing on REST API is {}.", isRestApiAuditEnabled ? "enabled" : "disabled");
        logger.info("Auditing on Transport API is {}.", isTransportApiAuditEnabled ? "enabled" : "disabled");
        logger.info("Auditing of request body is {}.", logRequestBody ? "enabled" : "disabled");
        logger.info("Bulk requests resolution is {} during request auditing.", resolveBulkRequests ? "enabled" : "disabled");
        logger.info("Index resolution is {} during request auditing.", resolveIndices ? "enabled" : "disabled");
        logger.info("Sensitive headers auditing is {}.", excludeSensitiveHeaders ? "enabled" : "disabled");
        logger.info("Auditing requests from {} users is disabled.", ignoredAuditUsers);
        logger.info("Compliance read operation requests auditing from {} users is disabled.", ignoredComplianceUsersForRead);
        logger.info("Compliance write operation requests auditing from {} users is disabled.", ignoredComplianceUsersForWrite);
        logger.info("{} are excluded from REST API auditing.", disabledRestCategories);
        logger.info("{} are excluded from Transport API auditing.", disabledTransportCategories);
        logger.info("Open distro auditing uses {} index(alias?) to write auditing events.", opendistrosecurityIndex);
    }

    @Override
    public String toString() {
        return "AuditConfig{" +
                "isRestApiAuditEnabled=" + isRestApiAuditEnabled +
                ", isTransportAuditEnabled=" + isTransportApiAuditEnabled +
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
