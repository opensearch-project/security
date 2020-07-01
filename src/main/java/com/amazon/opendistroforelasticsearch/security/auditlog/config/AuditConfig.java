package com.amazon.opendistroforelasticsearch.security.auditlog.config;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;

import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Class represents configuration for audit logging.
 * Expected class structure
 * {
 *   "enabled": true,
 *   "audit" : {
 *     "enable_rest" : true,
 *     "disabled_rest_categories" : [
 *       "GRANTED_PRIVILEGES",
 *       "SSL_EXCEPTION"
 *     ],
 *     "enable_transport" : true,
 *     "disabled_transport_categories" : [
 *       "GRANTED_PRIVILEGES",
 *       "AUTHENTICATED"
 *     ],
 *     "resolve_bulk_requests" : false,
 *     "log_request_body" : true,
 *     "resolve_indices" : true,
 *     "exclude_sensitive_headers" : true,
 *     "ignore_users" : [
 *       "kibanaserver"
 *     ],
 *     "ignore_requests" : [ ]
 *   },
 *   "compliance" : {
 *     "enabled": true,
 *     "internal_config" : true,
 *     "external_config" : true,
 *     "read_metadata_only" : true,
 *     "read_watched_fields" : { },
 *     "read_ignore_users" : [ ],
 *     "write_metadata_only" : true,
 *     "write_log_diffs" : false,
 *     "write_watched_indices" : [ ],
 *     "write_ignore_users" : [ ]
 *   }
 * }
 */
public class AuditConfig {

    public static final Set<String> DEFAULT_IGNORED_USERS_SET = Collections.singleton("kibanaserver");
    public static final List<String> DEFAULT_IGNORED_USERS_LIST = ImmutableList.copyOf(DEFAULT_IGNORED_USERS_SET);

    @JsonProperty(value = Key.ENABLED) private final boolean auditLogEnabled;
    @JsonProperty(value = Key.AUDIT) private final Filter filter;
    @JsonProperty(value = Key.COMPLIANCE) private final ComplianceConfig compliance;

    @JsonIgnore
    public boolean isEnabled() {
        return auditLogEnabled;
    }

    @JsonIgnore
    public Filter getFilter() {
        return filter;
    }

    @JsonIgnore
    public ComplianceConfig getCompliance() {
        return compliance;
    }

    @VisibleForTesting
    @JsonCreator
    public AuditConfig(@JsonProperty(value = Key.ENABLED) Boolean auditLogEnabled,
                       @JsonProperty(value = Key.AUDIT) final Filter filter,
                       @JsonProperty(value = Key.COMPLIANCE) final ComplianceConfig compliance) {
        this.auditLogEnabled = auditLogEnabled != null ? auditLogEnabled : true;
        this.filter = filter != null ? filter : Filter.from(Settings.EMPTY);
        this.compliance = compliance != null ? compliance : ComplianceConfig.from(Settings.EMPTY);
    }

    public static AuditConfig from(final Settings settings) {
        return new AuditConfig(true, Filter.from(settings), ComplianceConfig.from(settings));
    }

    public static class Key {
        public static final String ENABLED = "enabled";
        public static final String AUDIT = "audit";
        public static final String COMPLIANCE = "compliance";
    }

    /**
     * Filter represents set of filtering configuration settings for audit logging.
     * Audit logger will use these settings to determine what audit logs are to be generated.
     */
    public static class Filter {
        private static final List<String> DEFAULT_DISABLED_CATEGORIES_LIST = ImmutableList.of(
                AuditCategory.AUTHENTICATED.toString(), AuditCategory.GRANTED_PRIVILEGES.toString());
        private static final EnumSet<AuditCategory> DEFAULT_DISABLED_CATEGORIES_SET = AuditCategory.parse(DEFAULT_DISABLED_CATEGORIES_LIST);

        @JsonProperty(value = Key.ENABLE_REST) private final boolean isRestApiAuditEnabled;
        @JsonProperty(value = Key.DISABLED_REST_CATEGORIES) private final EnumSet<AuditCategory> disabledRestCategories;
        @JsonProperty(value = Key.ENABLE_TRANSPORT) private final boolean isTransportApiAuditEnabled;
        @JsonProperty(value = Key.DISABLED_TRANSPORT_CATEGORIES) private final EnumSet<AuditCategory> disabledTransportCategories;
        @JsonProperty(value = Key.RESOLVE_BULK_REQUESTS) private final boolean resolveBulkRequests;
        @JsonProperty(value = Key.LOG_REQUEST_BODY) private final boolean logRequestBody;
        @JsonProperty(value = Key.RESOLVE_INDICES) private final boolean resolveIndices;
        @JsonProperty(value = Key.EXCLUDE_SENSITIVE_HEADERS) private final boolean excludeSensitiveHeaders;
        @JsonProperty(value = Key.IGNORE_USERS) private final Set<String> ignoredAuditUsers;
        @JsonProperty(value = Key.IGNORE_REQUESTS) private final Set<String> ignoredAuditRequests;
        @JsonIgnore private final WildcardMatcher ignoredAuditUsersMatcher;
        @JsonIgnore private final WildcardMatcher ignoredAuditRequestsMatcher;

        @VisibleForTesting
        @JsonCreator
        public Filter(@JsonProperty(value = Key.ENABLE_REST) final Boolean isRestApiAuditEnabled,
                      @JsonProperty(value = Key.DISABLED_REST_CATEGORIES) final EnumSet<AuditCategory> disabledRestCategories,
                      @JsonProperty(value = Key.ENABLE_TRANSPORT)  Boolean isTransportApiAuditEnabled,
                      @JsonProperty(value = Key.DISABLED_TRANSPORT_CATEGORIES) final EnumSet<AuditCategory> disabledTransportCategories,
                      @JsonProperty(value = Key.RESOLVE_BULK_REQUESTS) final Boolean resolveBulkRequests,
                      @JsonProperty(value = Key.LOG_REQUEST_BODY) final Boolean logRequestBody,
                      @JsonProperty(value = Key.RESOLVE_INDICES) final Boolean resolveIndices,
                      @JsonProperty(value = Key.EXCLUDE_SENSITIVE_HEADERS) final Boolean excludeSensitiveHeaders,
                      @JsonProperty(value = Key.IGNORE_USERS) final Set<String> ignoredAuditUsers,
                      @JsonProperty(value = Key.IGNORE_REQUESTS) final Set<String> ignoredAuditRequests) {
            this.isRestApiAuditEnabled = isRestApiAuditEnabled != null ? isRestApiAuditEnabled : true;
            this.isTransportApiAuditEnabled = isTransportApiAuditEnabled != null ? isTransportApiAuditEnabled : true;
            this.resolveBulkRequests = resolveBulkRequests != null ? resolveBulkRequests : false;
            this.logRequestBody = logRequestBody != null ? logRequestBody : true;
            this.resolveIndices = resolveIndices != null ? resolveIndices : true;
            this.excludeSensitiveHeaders = excludeSensitiveHeaders != null ? excludeSensitiveHeaders : true;
            this.ignoredAuditUsers = ignoredAuditUsers != null ? ignoredAuditUsers : DEFAULT_IGNORED_USERS_SET;
            this.ignoredAuditUsersMatcher = WildcardMatcher.from(this.ignoredAuditUsers);
            this.ignoredAuditRequests = ignoredAuditRequests != null ? ignoredAuditRequests : Collections.emptySet();
            this.ignoredAuditRequestsMatcher = WildcardMatcher.from(this.ignoredAuditRequests);
            this.disabledRestCategories = disabledRestCategories != null ? disabledRestCategories : DEFAULT_DISABLED_CATEGORIES_SET;
            this.disabledTransportCategories = disabledTransportCategories != null ? disabledTransportCategories : DEFAULT_DISABLED_CATEGORIES_SET;
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
                    DEFAULT_DISABLED_CATEGORIES_LIST,
                    true));

            final EnumSet<AuditCategory> disabledTransportCategories = AuditCategory.parse(getSettingAsSet(
                    settings,
                    ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES,
                    DEFAULT_DISABLED_CATEGORIES_LIST,
                    true));

            final Set<String> ignoredAuditUsers = getSettingAsSet(
                    settings,
                    ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS,
                    DEFAULT_IGNORED_USERS_LIST,
                    false);

            final Set<String> ignoreAuditRequests = ImmutableSet.copyOf(settings.getAsList(
                    ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS,
                    Collections.emptyList()));

            return new Filter(isRestApiAuditEnabled,
                    disabledRestCategories,
                    isTransportAuditEnabled,
                    disabledTransportCategories,
                    resolveBulkRequests,
                    logRequestBody,
                    resolveIndices,
                    excludeSensitiveHeaders,
                    ignoredAuditUsers,
                    ignoreAuditRequests);
        }

        /**
         * Checks if auditing for REST API is enabled or disabled
         * @return true/false
         */
        @JsonIgnore
        public boolean isRestApiAuditEnabled() {
            return isRestApiAuditEnabled;
        }

        /**
         * Checks if auditing for Transport API is enabled or disabled
         * @return true/false
         */
        @JsonIgnore
        public boolean isTransportApiAuditEnabled() {
            return isTransportApiAuditEnabled;
        }

        /**
         * Checks if bulk requests must be resolved during auditing
         * @return true/false
         */
        @JsonIgnore
        public boolean shouldResolveBulkRequests() {
            return resolveBulkRequests;
        }

        /**
         * Checks if request body must be logged
         * @return true/false
         */
        @JsonIgnore
        public boolean shouldLogRequestBody() {
            return logRequestBody;
        }

        /**
         * Check if indices must be resolved during auditing
         * @return true/false
         */
        @JsonIgnore
        public boolean shouldResolveIndices() {
            return resolveIndices;
        }

        /**
         * Checks if sensitive headers eg: Authorization must be excluded in log messages
         * @return true/false
         */
        @JsonIgnore
        public boolean shouldExcludeSensitiveHeaders() {
            return excludeSensitiveHeaders;
        }

        @VisibleForTesting
        @JsonIgnore
        WildcardMatcher getIgnoredAuditUsersMatcher() {
            return ignoredAuditUsersMatcher;
        }

        /**
         * Check if user is excluded from audit.
         * @param user
         * @return true if user is excluded from audit logging
         */
        @JsonIgnore
        public boolean isAuditDisabled(String user) {
            return ignoredAuditUsersMatcher.test(user);
        }

        @VisibleForTesting
        @JsonIgnore
        WildcardMatcher getIgnoredAuditRequestsMatcher() {
            return ignoredAuditRequestsMatcher;
        }

        /**
         * Check if request is excluded from audit
         * @param action
         * @return true if request action is excluded from audit
         */
        @JsonIgnore
        public boolean isRequestAuditDisabled(String action) {
            return ignoredAuditRequestsMatcher.test(action);
        }

        /**
         * Disabled categories for REST API auditing
         * @return set of categories
         */
        @JsonIgnore
        public EnumSet<AuditCategory> getDisabledRestCategories() {
            return disabledRestCategories;
        }

        /**
         * Disabled categories for Transport API auditing
         * @return set of categories
         */
        @JsonIgnore
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
            logger.info("Auditing requests from {} users is disabled.", ignoredAuditUsersMatcher);
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
                    ", ignoredAuditUsers=" + ignoredAuditUsersMatcher +
                    ", ignoreAuditRequests=" + ignoredAuditRequestsMatcher +
                    '}';
        }

        private static class Key {
            public static final String ENABLE_REST = "enable_rest";
            public static final String DISABLED_REST_CATEGORIES = "disabled_rest_categories";
            public static final String ENABLE_TRANSPORT = "enable_transport";
            public static final String DISABLED_TRANSPORT_CATEGORIES = "disabled_transport_categories";
            public static final String RESOLVE_BULK_REQUESTS = "resolve_bulk_requests";
            public static final String LOG_REQUEST_BODY = "log_request_body";
            public static final String RESOLVE_INDICES = "resolve_indices";
            public static final String EXCLUDE_SENSITIVE_HEADERS = "exclude_sensitive_headers";
            public static final String IGNORE_USERS = "ignore_users";
            public static final String IGNORE_REQUESTS = "ignore_requests";
        }
    }

    public static Set<String> getSettingAsSet(final Settings settings, final String key, final List<String> defaultList, final boolean ignoreCaseForNone) {
        final List<String> list = settings.getAsList(key, defaultList);
        if (list.size() == 1 && "NONE".equals(ignoreCaseForNone? list.get(0).toUpperCase() : list.get(0))) {
            return Collections.emptySet();
        }
        return ImmutableSet.copyOf(list);
    }
}
