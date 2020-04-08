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

/**
 * Class represents configuration for audit logging.
 */
public class AuditConfig {

    private AuditConfig() { }

    /**
     * Filter represents set of filtering configuration settings for audit logging.
     * Audit logger will use these settings to determine what audit logs are to be generated.
     */
    public static class Filter {
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

        private Filter(final boolean isRestApiAuditEnabled,
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
                       final EnumSet<AuditCategory> disabledTransportCategories) {
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
        }

        /**
         * Generate audit logging configuration from settings defined in elasticsearch.yml
         * @param settings settings
         * @return audit configuration filter
         */
        public static Filter from(Settings settings) {
            final boolean isRestApiAuditEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true);
            final boolean isTransportAuditEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true);
            final boolean resolveBulkRequests = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false);
            final boolean logRequestBody = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, true);
            final boolean resolveIndices = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, true);
            final boolean excludeSensitiveHeaders = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS, true);

            final EnumSet<AuditCategory> disabledRestCategories = AuditCategory.parse(getSettingAsSet(
                    settings,
                    ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES,
                    DEFAULT_DISABLED_CATEGORIES,
                    true));

            final EnumSet<AuditCategory> disabledTransportCategories = AuditCategory.parse(getSettingAsSet(
                    settings,
                    ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES,
                    DEFAULT_DISABLED_CATEGORIES,
                    true));

            final Set<String> ignoredAuditUsers = getSettingAsSet(
                    settings,
                    ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS,
                    DEFAULT_IGNORED_USERS,
                    false);

            final Set<String> ignoredComplianceUsersForRead = getSettingAsSet(
                    settings,
                    ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS,
                    DEFAULT_IGNORED_USERS,
                    false);

            final Set<String> ignoredComplianceUsersForWrite = getSettingAsSet(
                    settings,
                    ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS,
                    DEFAULT_IGNORED_USERS,
                    false);

            final Set<String> ignoreAuditRequests = ImmutableSet.copyOf(settings.getAsList(
                    ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS,
                    Collections.emptyList()));

            return new Filter(isRestApiAuditEnabled,
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
                    disabledTransportCategories);
        }

        private static Set<String> getSettingAsSet(final Settings settings, final String key, final List<String> defaultList, final boolean ignoreCaseForNone) {
            final List<String> list = settings.getAsList(key, defaultList);
            if (list.size() == 1 && "NONE".equals(ignoreCaseForNone? list.get(0).toUpperCase() : list.get(0))) {
                return Collections.emptySet();
            }
            return ImmutableSet.copyOf(list);
        }

        /**
         * Checks if auditing for REST API is enabled or disabled
         * @return true/false
         */
        public boolean isRestApiAuditEnabled() {
            return isRestApiAuditEnabled;
        }

        /**
         * Checks if auditing for Transport API is enabled or disabled
         * @return true/false
         */
        public boolean isTransportApiAuditEnabled() {
            return isTransportApiAuditEnabled;
        }

        /**
         * Checks if bulk requests must be resolved during auditing
         * @return true/false
         */
        public boolean shouldResolveBulkRequests() {
            return resolveBulkRequests;
        }

        /**
         * Checks if request body must be logged
         * @return true/false
         */
        public boolean shouldLogRequestBody() {
            return logRequestBody;
        }

        /**
         * Check if indices must be resolved during auditing
         * @return true/false
         */
        public boolean shouldResolveIndices() {
            return resolveIndices;
        }

        /**
         * Checks if sensitive headers eg: Authorization must be excluded in log messages
         * @return true/false
         */
        public boolean shouldExcludeSensitiveHeaders() {
            return excludeSensitiveHeaders;
        }

        /**
         * Set of users for whom auditing must be ignored.
         * @return set of users
         */
        public Set<String> getIgnoredAuditUsers() {
            return ignoredAuditUsers;
        }

        /**
         * Set of users for whom compliance read auditing must be ignored.
         * @return set of users
         */
        public Set<String> getIgnoredComplianceUsersForRead() {
            return ignoredComplianceUsersForRead;
        }

        /**
         * Set of users for whom compliance write auditing must be ignored.
         * @return set of users
         */
        public Set<String> getIgnoredComplianceUsersForWrite() {
            return ignoredComplianceUsersForWrite;
        }

        /**
         * Request patterns that must be ignored.
         * @return set of request patterns
         */
        public Set<String> getIgnoredAuditRequests() {
            return ignoreAuditRequests;
        }

        /**
         * Disabled categories for REST API auditing
         * @return set of categories
         */
        public EnumSet<AuditCategory> getDisabledRestCategories() {
            return disabledRestCategories;
        }

        /**
         * Disabled categories for Transport API auditing
         * @return set of categories
         */
        public EnumSet<AuditCategory> getDisabledTransportCategories() {
            return disabledTransportCategories;
        }

        public void log(Logger logger) {
            logger.info("Auditing on REST API is {}.", isRestApiAuditEnabled ? "enabled" : "disabled");
            logger.info("{} are excluded from REST API auditing.", disabledRestCategories);
            logger.info("Auditing on Transport API is {}.", isTransportApiAuditEnabled ? "enabled" : "disabled");
            logger.info("{} are excluded from Transport API auditing.", disabledTransportCategories);
            logger.info("Auditing of request body is {}.", logRequestBody ? "enabled" : "disabled");
            logger.info("Bulk requests resolution is {} during request auditing.", resolveBulkRequests ? "enabled" : "disabled");
            logger.info("Index resolution is {} during request auditing.", resolveIndices ? "enabled" : "disabled");
            logger.info("Sensitive headers auditing is {}.", excludeSensitiveHeaders ? "enabled" : "disabled");
            logger.info("Auditing requests from {} users is disabled.", ignoredAuditUsers);
            logger.info("Compliance read operation requests auditing from {} users is disabled.", ignoredComplianceUsersForRead);
            logger.info("Compliance write operation requests auditing from {} users is disabled.", ignoredComplianceUsersForWrite);
        }

        @Override
        public String toString() {
            return "Filter{" +
                    "isRestApiAuditEnabled=" + isRestApiAuditEnabled +
                    ", disabledRestCategories=" + disabledRestCategories +
                    ", isTransportApiAuditEnabled=" + isTransportApiAuditEnabled +
                    ", disabledTransportCategories=" + disabledTransportCategories +
                    ", resolveBulkRequests=" + resolveBulkRequests +
                    ", logRequestBody=" + logRequestBody +
                    ", resolveIndices=" + resolveIndices +
                    ", excludeSensitiveHeaders=" + excludeSensitiveHeaders +
                    ", ignoredAuditUsers=" + ignoredAuditUsers +
                    ", ignoredComplianceUsersForRead=" + ignoredComplianceUsersForRead +
                    ", ignoredComplianceUsersForWrite=" + ignoredComplianceUsersForWrite +
                    ", ignoreAuditRequests=" + ignoreAuditRequests +
                    '}';
        }
    }
}
