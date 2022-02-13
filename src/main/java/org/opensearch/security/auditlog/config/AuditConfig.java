/*
 * Copyright OpenSearch Contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package org.opensearch.security.auditlog.config;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.compliance.ComplianceConfig;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import org.slf4j.Logger;
import org.opensearch.common.settings.Settings;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.opensearch.security.DefaultObjectMapper.getOrDefault;

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
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuditConfig {

    public static final List<String> DEFAULT_IGNORED_USERS = Collections.singletonList("kibanaserver");
    private static Set<String> FIELDS = DefaultObjectMapper.getFields(AuditConfig.class);

    private AuditConfig() {
        this(true, null, null);
    }

    @JsonProperty("enabled")
    private final boolean auditLogEnabled;
    @JsonProperty("audit")
    private final Filter filter;

    private final ComplianceConfig compliance;

    public boolean isEnabled() {
        return auditLogEnabled;
    }

    public Filter getFilter() {
        return filter;
    }

    public ComplianceConfig getCompliance() {
        return compliance;
    }

    @VisibleForTesting
    public AuditConfig(
            final boolean auditLogEnabled,
            final Filter filter,
            final ComplianceConfig compliance) {
        this.auditLogEnabled = auditLogEnabled;
        this.filter = filter != null ? filter : Filter.DEFAULT;
        this.compliance = compliance != null ? compliance : ComplianceConfig.DEFAULT;
    }

    public static AuditConfig from(final Settings settings) {
        return new AuditConfig(true, Filter.from(settings), ComplianceConfig.from(settings));
    }

    /**
     * Filter represents set of filtering configuration settings for audit logging.
     * Audit logger will use these settings to determine what audit logs are to be generated.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Filter {
        @VisibleForTesting
        public static final Filter DEFAULT = Filter.from(Settings.EMPTY);
        private static Set<String> FIELDS = DefaultObjectMapper.getFields(Filter.class);

        private final boolean isRestApiAuditEnabled;
        private final boolean isTransportApiAuditEnabled;
        private final boolean resolveBulkRequests;
        private final boolean logRequestBody;
        private final boolean resolveIndices;
        private final boolean excludeSensitiveHeaders;
        @JsonProperty("ignore_users")
        private final Set<String> ignoredAuditUsers;
        @JsonProperty("ignore_requests")
        private final Set<String> ignoredAuditRequests;
        private final WildcardMatcher ignoredAuditUsersMatcher;
        private final WildcardMatcher ignoredAuditRequestsMatcher;
        private final Set<AuditCategory> disabledRestCategories;
        private final Set<AuditCategory> disabledTransportCategories;

        @VisibleForTesting
        Filter(final boolean isRestApiAuditEnabled,
                       final boolean isTransportApiAuditEnabled,
                       final boolean resolveBulkRequests,
                       final boolean logRequestBody,
                       final boolean resolveIndices,
                       final boolean excludeSensitiveHeaders,
                       final Set<String> ignoredAuditUsers,
                       final Set<String> ignoredAuditRequests,
                       final Set<AuditCategory> disabledRestCategories,
                       final Set<AuditCategory> disabledTransportCategories) {
            this.isRestApiAuditEnabled = isRestApiAuditEnabled;
            this.isTransportApiAuditEnabled = isTransportApiAuditEnabled;
            this.resolveBulkRequests = resolveBulkRequests;
            this.logRequestBody = logRequestBody;
            this.resolveIndices = resolveIndices;
            this.excludeSensitiveHeaders = excludeSensitiveHeaders;
            this.ignoredAuditUsers = ignoredAuditUsers;
            this.ignoredAuditUsersMatcher = WildcardMatcher.from(ignoredAuditUsers);
            this.ignoredAuditRequests = ignoredAuditRequests;
            this.ignoredAuditRequestsMatcher = WildcardMatcher.from(ignoredAuditRequests);
            this.disabledRestCategories = disabledRestCategories;
            this.disabledTransportCategories = disabledTransportCategories;
        }

        @JsonCreator
        @VisibleForTesting
        public static Filter from(Map<String, Object> properties) throws JsonProcessingException {
            if (!FIELDS.containsAll(properties.keySet())) {
                throw new UnrecognizedPropertyException(null, "Unrecognized field(s) present in the input data for audit filter config", null, Filter.class, null, null);
            }

            final boolean isRestApiAuditEnabled = getOrDefault(properties,"enable_rest", true);
            final boolean isTransportAuditEnabled = getOrDefault(properties,"enable_transport", true);
            final boolean resolveBulkRequests = getOrDefault(properties, "resolve_bulk_requests", false);
            final boolean logRequestBody = getOrDefault(properties, "log_request_body", true);
            final boolean resolveIndices = getOrDefault(properties, "resolve_indices", true);
            final boolean excludeSensitiveHeaders = getOrDefault(properties, "exclude_sensitive_headers", true);
            final Set<AuditCategory> disabledRestCategories = AuditCategory.parse(getOrDefault(properties,"disabled_rest_categories", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_DISABLED_CATEGORIES_DEFAULT));
            final Set<AuditCategory> disabledTransportCategories = AuditCategory.parse(getOrDefault(properties, "disabled_transport_categories", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_DISABLED_CATEGORIES_DEFAULT));
            final Set<String> ignoredAuditUsers = ImmutableSet.copyOf(getOrDefault(properties, "ignore_users", DEFAULT_IGNORED_USERS));
            final Set<String> ignoreAuditRequests = ImmutableSet.copyOf(getOrDefault(properties, "ignore_requests", Collections.emptyList()));

            return new Filter(
                    isRestApiAuditEnabled,
                    isTransportAuditEnabled,
                    resolveBulkRequests,
                    logRequestBody,
                    resolveIndices,
                    excludeSensitiveHeaders,
                    ignoredAuditUsers,
                    ignoreAuditRequests,
                    disabledRestCategories,
                    disabledTransportCategories);

        }

        /**
         * Generate audit logging configuration from settings defined in opensearch.yml
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
            final Set<AuditCategory> disabledRestCategories = AuditCategory.from(settings, ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES);
            final Set<AuditCategory> disabledTransportCategories = AuditCategory.from(settings, ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES);

            final Set<String> ignoredAuditUsers = ConfigConstants.getSettingAsSet(
                    settings,
                    ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS,
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
                    ignoreAuditRequests,
                    disabledRestCategories,
                    disabledTransportCategories);
        }

        /**
         * Checks if auditing for REST API is enabled or disabled
         * @return true/false
         */
        @JsonProperty("enable_rest")
        public boolean isRestApiAuditEnabled() {
            return isRestApiAuditEnabled;
        }

        /**
         * Checks if auditing for Transport API is enabled or disabled
         * @return true/false
         */
        @JsonProperty("enable_transport")
        public boolean isTransportApiAuditEnabled() {
            return isTransportApiAuditEnabled;
        }

        /**
         * Checks if bulk requests must be resolved during auditing
         * @return true/false
         */
        @JsonProperty("resolve_bulk_requests")
        public boolean shouldResolveBulkRequests() {
            return resolveBulkRequests;
        }

        /**
         * Checks if request body must be logged
         * @return true/false
         */
        @JsonProperty("log_request_body")
        public boolean shouldLogRequestBody() {
            return logRequestBody;
        }

        /**
         * Check if indices must be resolved during auditing
         * @return true/false
         */
        @JsonProperty("resolve_indices")
        public boolean shouldResolveIndices() {
            return resolveIndices;
        }

        /**
         * Checks if sensitive headers eg: Authorization must be excluded in log messages
         * @return true/false
         */
        @JsonProperty("exclude_sensitive_headers")
        public boolean shouldExcludeSensitiveHeaders() {
            return excludeSensitiveHeaders;
        }

        @VisibleForTesting
        WildcardMatcher getIgnoredAuditUsersMatcher() {
            return ignoredAuditUsersMatcher;
        }

        /**
         * Check if user is excluded from audit.
         * @param user
         * @return true if user is excluded from audit logging
         */
        public boolean isAuditDisabled(String user) {
            return ignoredAuditUsersMatcher.test(user);
        }

        @VisibleForTesting
        WildcardMatcher getIgnoredAuditRequestsMatcher() {
            return ignoredAuditRequestsMatcher;
        }

        /**
         * Check if request is excluded from audit
         * @param action
         * @return true if request action is excluded from audit
         */
        public boolean isRequestAuditDisabled(String action) {
            return ignoredAuditRequestsMatcher.test(action);
        }

        /**
         * Disabled categories for REST API auditing
         * @return set of categories
         */
        @JsonProperty("disabled_rest_categories")
        public Set<AuditCategory> getDisabledRestCategories() {
            return disabledRestCategories;
        }

        /**
         * Disabled categories for Transport API auditing
         * @return set of categories
         */
        @JsonProperty("disabled_transport_categories")
        public Set<AuditCategory> getDisabledTransportCategories() {
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
    }

    /**
     * List of keys that are deprecated
     */
    public static final List<String> DEPRECATED_KEYS = ImmutableList.of(
            ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST,
            ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES,
            ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT,
            ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES,
            ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY,
            ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES,
            ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS,
            ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS,
            ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS,
            ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS,
            ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED,
            ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED,
            ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY,
            ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS,
            ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS,
            ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY,
            ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS,
            ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS,
            ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES
    );

    public static Set<String> getDeprecatedKeys(final Settings settings) {
        return AuditConfig.DEPRECATED_KEYS
                .stream()
                .filter(settings::hasValue)
                .collect(Collectors.toSet());
    }

    public static final Set<String> FIELD_PATHS = Sets.union(
            Utils.generateFieldResourcePaths(AuditConfig.FIELDS, "/"),
            Sets.union(
                    Utils.generateFieldResourcePaths(Filter.FIELDS, "/audit/"),
                    Utils.generateFieldResourcePaths(ComplianceConfig.FIELDS, "/compliance/")
            )
    );
}
