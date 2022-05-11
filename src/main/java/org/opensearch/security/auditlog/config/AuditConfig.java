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
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Settings;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.opensearch.security.DefaultObjectMapper.getOrDefault;
import static org.opensearch.security.support.ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT;

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

        public enum FilterEntries {
            ENABLE_REST("enable_rest", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST),
            ENABLE_TRANSPORT("enable_transport", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT),
            RESOLVE_BULK_REQUESTS("resolve_bulk_requests", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS),
            LOG_REQUEST_BODY("log_request_body", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY),
            RESOLVE_INDICES("resolve_indices", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES),
            EXCLUDE_SENSITIVE_HEADERS("exclude_sensitive_headers", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS),
            DISABLE_REST_CATEGORIES("disabled_rest_categories", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES),
            DISABLE_TRANSPORT_CATEGORIES("disabled_transport_categories", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES),
            IGNORE_USERS("ignore_users", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS),
            IGNORE_REQUESTS("ignore_requests", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS);

            private final String key;
            private final String legacyKeyWithNamespace;
            private FilterEntries(final String entryKey, final String legacyKeyWithNamespace) {
                this.key = entryKey;
                this.legacyKeyWithNamespace = legacyKeyWithNamespace;
            }
            public String getKey() {
                return this.key;
            }
            public String getKeyWithNamespace() {
                return SECURITY_AUDIT_CONFIG_DEFAULT + "."+ this.key;
            }
            public String getLegacyKeyWithNamespace() {
                return this.legacyKeyWithNamespace;
            }
        }

        @JsonCreator
        @VisibleForTesting
        public static Filter from(Map<String, Object> properties) throws JsonProcessingException {
            if (!FIELDS.containsAll(properties.keySet())) {
                throw new UnrecognizedPropertyException(null, "Unrecognized field(s) present in the input data for audit filter config", null, Filter.class, null, null);
            }

            final boolean isRestApiAuditEnabled = getOrDefault(properties, FilterEntries.ENABLE_REST.getKey(), true);
            final boolean isTransportAuditEnabled = getOrDefault(properties, FilterEntries.ENABLE_TRANSPORT.getKey(), true);
            final boolean resolveBulkRequests = getOrDefault(properties, FilterEntries.RESOLVE_BULK_REQUESTS.getKey(), false);
            final boolean logRequestBody = getOrDefault(properties, FilterEntries.LOG_REQUEST_BODY.getKey(), true);
            final boolean resolveIndices = getOrDefault(properties, FilterEntries.RESOLVE_INDICES.getKey(), true);
            final boolean excludeSensitiveHeaders = getOrDefault(properties, FilterEntries.EXCLUDE_SENSITIVE_HEADERS.getKey(), true);
            final Set<AuditCategory> disabledRestCategories = AuditCategory.parse(getOrDefault(properties, FilterEntries.DISABLE_REST_CATEGORIES.getKey(), ConfigConstants.OPENDISTRO_SECURITY_AUDIT_DISABLED_CATEGORIES_DEFAULT));
            final Set<AuditCategory> disabledTransportCategories = AuditCategory.parse(getOrDefault(properties, FilterEntries.DISABLE_TRANSPORT_CATEGORIES.getKey(), ConfigConstants.OPENDISTRO_SECURITY_AUDIT_DISABLED_CATEGORIES_DEFAULT));
            final Set<String> ignoredAuditUsers = ImmutableSet.copyOf(getOrDefault(properties, FilterEntries.IGNORE_USERS.getKey(), DEFAULT_IGNORED_USERS));
            final Set<String> ignoreAuditRequests = ImmutableSet.copyOf(getOrDefault(properties, FilterEntries.IGNORE_REQUESTS.getKey(), Collections.emptyList()));

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

        private static boolean getFromSettingBoolean(final Settings settings, FilterEntries filterEntry, final boolean defaultValue) {
            return settings.getAsBoolean(filterEntry.getKeyWithNamespace(), settings.getAsBoolean(filterEntry.getLegacyKeyWithNamespace(), defaultValue));
        }

        private static Set<String> getFromSettingStringSet(final Settings settings, FilterEntries filterEntry, final List<String> defaultValue) {
            final List<String> defaultDetector = ImmutableList.of("__DEFAULT_DETECTION__");
            final Set<String> stringSetOfKey = ConfigConstants.getSettingAsSet(
                    settings,
                    filterEntry.getKeyWithNamespace(),
                    defaultDetector,
                    false);
            if (!defaultDetector.containsAll(stringSetOfKey)) {
                return stringSetOfKey; 
            }
            return ConfigConstants.getSettingAsSet(
                settings,
                filterEntry.getLegacyKeyWithNamespace(),
                defaultValue,
                false);
        }

        /**
         * Generate audit logging configuration from settings defined in opensearch.yml
         * @param settings settings
         * @return audit configuration filter
         */
        public static Filter from(Settings settings) {
            final boolean isRestApiAuditEnabled = getFromSettingBoolean(settings, FilterEntries.ENABLE_REST, true);
            final boolean isTransportAuditEnabled = getFromSettingBoolean(settings, FilterEntries.ENABLE_TRANSPORT, true);
            final boolean resolveBulkRequests = getFromSettingBoolean(settings, FilterEntries.RESOLVE_BULK_REQUESTS, false);
            final boolean logRequestBody = getFromSettingBoolean(settings, FilterEntries.LOG_REQUEST_BODY, true);
            final boolean resolveIndices = getFromSettingBoolean(settings, FilterEntries.RESOLVE_INDICES, true);
            final boolean excludeSensitiveHeaders = getFromSettingBoolean(settings, FilterEntries.EXCLUDE_SENSITIVE_HEADERS, true);
            final Set<AuditCategory> disabledRestCategories = AuditCategory.parse(getFromSettingStringSet(settings, FilterEntries.DISABLE_REST_CATEGORIES, ConfigConstants.OPENDISTRO_SECURITY_AUDIT_DISABLED_CATEGORIES_DEFAULT));
            final Set<AuditCategory> disabledTransportCategories = AuditCategory.parse(getFromSettingStringSet(settings, FilterEntries.DISABLE_TRANSPORT_CATEGORIES, ConfigConstants.OPENDISTRO_SECURITY_AUDIT_DISABLED_CATEGORIES_DEFAULT));
            final Set<String> ignoredAuditUsers = getFromSettingStringSet(settings, FilterEntries.IGNORE_USERS, DEFAULT_IGNORED_USERS);
            final Set<String> ignoreAuditRequests = getFromSettingStringSet(settings, FilterEntries.IGNORE_REQUESTS, Collections.emptyList());

            

            System.err.println("FROM Filter.from(Settings)\n\n");
            new RuntimeException().printStackTrace();
            System.err.println("settings? " + settings);
            System.err.println("raw rest audit enabled: " + settings.get(FilterEntries.ENABLE_REST.getKeyWithNamespace()));
            System.err.println("raw disabled rest: " + settings.get(FilterEntries.DISABLE_REST_CATEGORIES.getKeyWithNamespace()));
            System.err.println("disabledRestCategories: " + disabledRestCategories);
            System.err.println("disabledTransportCategories: " + disabledTransportCategories);
            System.err.println("ignoredAuditUsers: " + ignoredAuditUsers);


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
