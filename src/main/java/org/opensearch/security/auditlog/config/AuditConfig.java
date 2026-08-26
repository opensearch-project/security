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

package org.opensearch.security.auditlog.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.logging.DeprecationLogger;
import org.opensearch.common.settings.Settings;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.impl.AuditCategory;
import org.opensearch.security.compliance.ComplianceConfig;
import org.opensearch.security.dlic.rest.support.Utils;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;

import tools.jackson.databind.exc.UnrecognizedPropertyException;

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
 *       "AUTHENTICATED",
 *       "CLUSTER_SETTINGS_CHANGED",
 *       "INDEX_SETTINGS_CHANGED"
 *     ],
 *     "resolve_bulk_requests" : false,
 *     "log_request_body" : true,
 *     "resolve_indices" : true,
 *     "exclude_sensitive_headers" : true,
 *     "ignore_users" : [
 *       "kibanaserver"
 *     ],
 *     "ignore_requests" : [ ],
 *     "ignore_headers" : [ ],
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
    @JsonProperty("compliance")
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
    public AuditConfig(final boolean auditLogEnabled, final Filter filter, final ComplianceConfig compliance) {
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
        private static final Logger log = LogManager.getLogger(Filter.class);
        private static Set<String> FIELDS = DefaultObjectMapper.getFields(Filter.class);
        /** Settings key for body logging exclusions — defined here to avoid circular init with SecuritySettings.
         *  Must match {@code SecuritySettings.AUDIT_BODY_LOGGING_EXCLUSIONS}. */
        static final String BODY_LOGGING_EXCLUSIONS_KEY = "plugins.security.audit.config.body_logging_exclusions";
        /** Settings prefix for action groups — defined here to avoid circular init with SecuritySettings.
         *  Must match {@code SecuritySettings.AUDIT_ACTION_GROUPS}. */
        static final String ACTION_GROUPS_PREFIX = "plugins.security.audit.config.action_groups.";
        @VisibleForTesting
        public static final Filter DEFAULT = Filter.from(Settings.EMPTY);

        private volatile boolean isRestApiAuditEnabled;
        private volatile boolean isTransportApiAuditEnabled;
        private volatile boolean resolveBulkRequests;
        private volatile boolean logRequestBody;
        private volatile boolean resolveIndices;
        private volatile boolean excludeSensitiveHeaders;
        @JsonProperty("ignore_users")
        private volatile Set<String> ignoredAuditUsers;
        @JsonProperty("ignore_requests")
        private volatile Set<String> ignoredAuditRequests;
        @JsonProperty("ignore_headers")
        private final Set<String> ignoredCustomHeaders;
        @JsonProperty("ignore_url_params")
        private volatile Set<String> ignoredUrlParams;
        private volatile WildcardMatcher ignoredAuditUsersMatcher;
        private volatile WildcardMatcher ignoredAuditRequestsMatcher;
        private final WildcardMatcher ignoredCustomHeadersMatcher;
        private volatile WildcardMatcher ignoredUrlParamsMatcher;
        @JsonProperty("action_groups")
        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        private volatile Map<String, List<String>> actionGroups = Collections.emptyMap();
        private volatile WildcardMatcher bodyExclusionMatcher = WildcardMatcher.NONE;
        @JsonProperty("body_logging_exclusions")
        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        private volatile List<String> bodyLoggingExclusions = Collections.emptyList();
        @JsonProperty("disabled_categories")
        private volatile Set<AuditCategory> disabledCategories;
        @Deprecated
        private volatile Set<AuditCategory> disabledRestCategories;
        @Deprecated
        private volatile Set<AuditCategory> disabledTransportCategories;

        @VisibleForTesting
        Filter(
            final boolean isRestApiAuditEnabled,
            final boolean isTransportApiAuditEnabled,
            final boolean resolveBulkRequests,
            final boolean logRequestBody,
            final boolean resolveIndices,
            final boolean excludeSensitiveHeaders,
            final Set<String> ignoredAuditUsers,
            final Set<String> ignoredAuditRequests,
            final Set<String> ignoredCustomHeaders,
            final Set<String> ignoredUrlParams,
            final Set<AuditCategory> disabledRestCategories,
            final Set<AuditCategory> disabledTransportCategories,
            final Set<AuditCategory> disabledCategories
        ) {
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
            this.ignoredCustomHeaders = ignoredCustomHeaders;
            this.ignoredCustomHeadersMatcher = WildcardMatcher.from(ignoredCustomHeaders);
            this.ignoredUrlParams = ignoredUrlParams;
            this.ignoredUrlParamsMatcher = WildcardMatcher.from(ignoredUrlParams);
            this.disabledRestCategories = disabledRestCategories;
            this.disabledTransportCategories = disabledTransportCategories;
            this.disabledCategories = disabledCategories;
        }

        public enum FilterEntries {
            ENABLE_REST("enable_rest", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST),
            ENABLE_TRANSPORT("enable_transport", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT),
            RESOLVE_BULK_REQUESTS("resolve_bulk_requests", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS),
            LOG_REQUEST_BODY("log_request_body", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY),
            RESOLVE_INDICES("resolve_indices", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES),
            EXCLUDE_SENSITIVE_HEADERS("exclude_sensitive_headers", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS),
            DISABLE_CATEGORIES("disabled_categories", ConfigConstants.SECURITY_AUDIT_CONFIG_DISABLED_CATEGORIES),
            DISABLE_REST_CATEGORIES("disabled_rest_categories", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES),
            DISABLE_TRANSPORT_CATEGORIES(
                "disabled_transport_categories",
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES
            ),
            IGNORE_USERS("ignore_users", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS),
            IGNORE_REQUESTS("ignore_requests", ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS),
            IGNORE_HEADERS("ignore_headers", ConfigConstants.SECURITY_AUDIT_IGNORE_HEADERS);

            private final String key;
            private final String legacyKeyWithNamespace;

            FilterEntries(final String entryKey, final String legacyKeyWithNamespace) {
                this.key = entryKey;
                this.legacyKeyWithNamespace = legacyKeyWithNamespace;
            }

            public String getKey() {
                return this.key;
            }

            public String getKeyWithNamespace() {
                return SECURITY_AUDIT_CONFIG_DEFAULT + "." + this.key;
            }

            public String getLegacyKeyWithNamespace() {
                return this.legacyKeyWithNamespace;
            }
        }

        @JsonCreator
        @VisibleForTesting
        public static Filter from(Map<String, Object> properties) {
            if (!FIELDS.containsAll(properties.keySet())) {
                throw new UnrecognizedPropertyException(
                    null,
                    "Unrecognized field(s) present in the input data for audit filter config",
                    null,
                    Filter.class,
                    null,
                    null
                );
            }

            final boolean isRestApiAuditEnabled = getOrDefault(properties, FilterEntries.ENABLE_REST.getKey(), true);
            final boolean isTransportAuditEnabled = getOrDefault(properties, FilterEntries.ENABLE_TRANSPORT.getKey(), true);
            final boolean resolveBulkRequests = getOrDefault(properties, FilterEntries.RESOLVE_BULK_REQUESTS.getKey(), false);
            final boolean logRequestBody = getOrDefault(properties, FilterEntries.LOG_REQUEST_BODY.getKey(), true);
            final boolean resolveIndices = getOrDefault(properties, FilterEntries.RESOLVE_INDICES.getKey(), true);
            final boolean excludeSensitiveHeaders = getOrDefault(properties, FilterEntries.EXCLUDE_SENSITIVE_HEADERS.getKey(), true);
            final Set<AuditCategory> disabledCategories = AuditCategory.parse(
                getOrDefault(properties, FilterEntries.DISABLE_CATEGORIES.getKey(), Collections.emptyList())
            );
            final Set<AuditCategory> disabledRestCategories = AuditCategory.parse(
                getOrDefault(
                    properties,
                    FilterEntries.DISABLE_REST_CATEGORIES.getKey(),
                    ConfigConstants.OPENDISTRO_SECURITY_AUDIT_DISABLED_REST_CATEGORIES_DEFAULT
                )
            );
            final Set<AuditCategory> disabledTransportCategories = AuditCategory.parse(
                getOrDefault(
                    properties,
                    FilterEntries.DISABLE_TRANSPORT_CATEGORIES.getKey(),
                    ConfigConstants.OPENDISTRO_SECURITY_AUDIT_DISABLED_TRANSPORT_CATEGORIES_DEFAULT
                )
            );
            final List<String> rawIgnoredUsers = getOrDefault(properties, FilterEntries.IGNORE_USERS.getKey(), DEFAULT_IGNORED_USERS);
            final Set<String> ignoredAuditUsers = rawIgnoredUsers.size() == 1 && "NONE".equalsIgnoreCase(rawIgnoredUsers.get(0))
                ? Collections.emptySet()
                : ImmutableSet.copyOf(rawIgnoredUsers);
            final Set<String> ignoreAuditRequests = ImmutableSet.copyOf(
                getOrDefault(properties, FilterEntries.IGNORE_REQUESTS.getKey(), Collections.emptyList())
            );
            final Set<String> ignoreHeaders = ImmutableSet.copyOf(
                getOrDefault(properties, FilterEntries.IGNORE_HEADERS.getKey(), Collections.emptyList())
            );

            final boolean unifiedPresent = properties.containsKey(FilterEntries.DISABLE_CATEGORIES.getKey());
            final boolean splitPresent = properties.containsKey(FilterEntries.DISABLE_REST_CATEGORIES.getKey())
                || properties.containsKey(FilterEntries.DISABLE_TRANSPORT_CATEGORIES.getKey());
            warnIfBothUnifiedAndSplitConfigured(unifiedPresent, splitPresent);

            final List<String> bodyExclusions = getOrDefault(properties, "body_logging_exclusions", Collections.emptyList());

            // Parse action groups from security index — handle both formats:
            // Map<String, List<String>> (correct) or Map<String, String> (comma-separated)
            final Map<String, List<String>> actionGroupsFromConfig;
            if (properties.containsKey("action_groups")) {
                Object raw = properties.get("action_groups");
                if (raw instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> rawMap = (Map<String, Object>) raw;
                    actionGroupsFromConfig = parseActionGroupsFromMap(rawMap);
                } else {
                    actionGroupsFromConfig = Collections.emptyMap();
                }
            } else {
                actionGroupsFromConfig = Collections.emptyMap();
            }

            Filter filter = new Filter(
                isRestApiAuditEnabled,
                isTransportAuditEnabled,
                resolveBulkRequests,
                logRequestBody,
                resolveIndices,
                excludeSensitiveHeaders,
                ignoredAuditUsers,
                ignoreAuditRequests,
                ignoreHeaders,
                new HashSet<>(),
                disabledRestCategories,
                disabledTransportCategories,
                disabledCategories
            );
            filter.setActionGroups(actionGroupsFromConfig);
            filter.setBodyLoggingExclusions(bodyExclusions);
            return filter;

        }

        /**
         * Generate audit logging configuration from settings defined in opensearch.yml
         * @param settings settings
         * @return audit configuration filter
         */
        public static Filter from(Settings settings) {
            final boolean isRestApiAuditEnabled = fromSettingBoolean(settings, FilterEntries.ENABLE_REST, true);
            final boolean isTransportAuditEnabled = fromSettingBoolean(settings, FilterEntries.ENABLE_TRANSPORT, true);
            final boolean resolveBulkRequests = fromSettingBoolean(settings, FilterEntries.RESOLVE_BULK_REQUESTS, false);
            final boolean logRequestBody = fromSettingBoolean(settings, FilterEntries.LOG_REQUEST_BODY, true);
            final boolean resolveIndices = fromSettingBoolean(settings, FilterEntries.RESOLVE_INDICES, true);
            final boolean excludeSensitiveHeaders = fromSettingBoolean(settings, FilterEntries.EXCLUDE_SENSITIVE_HEADERS, true);
            final Set<AuditCategory> disabledCategories = AuditCategory.parse(
                fromSettingStringSet(settings, FilterEntries.DISABLE_CATEGORIES, Collections.emptyList())
            );
            final Set<AuditCategory> disabledRestCategories = AuditCategory.parse(
                fromSettingStringSet(
                    settings,
                    FilterEntries.DISABLE_REST_CATEGORIES,
                    ConfigConstants.OPENDISTRO_SECURITY_AUDIT_DISABLED_REST_CATEGORIES_DEFAULT
                )
            );
            final Set<AuditCategory> disabledTransportCategories = AuditCategory.parse(
                fromSettingStringSet(
                    settings,
                    FilterEntries.DISABLE_TRANSPORT_CATEGORIES,
                    ConfigConstants.OPENDISTRO_SECURITY_AUDIT_DISABLED_TRANSPORT_CATEGORIES_DEFAULT
                )
            );
            final Set<String> ignoredAuditUsers = fromSettingStringSet(settings, FilterEntries.IGNORE_USERS, DEFAULT_IGNORED_USERS);
            final Set<String> ignoreAuditRequests = fromSettingStringSet(settings, FilterEntries.IGNORE_REQUESTS, Collections.emptyList());
            final Set<String> ignoreHeaders = fromSettingStringSet(settings, FilterEntries.IGNORE_HEADERS, Collections.emptyList());

            final boolean unifiedPresent = settings.hasValue(FilterEntries.DISABLE_CATEGORIES.getKeyWithNamespace());
            final boolean splitPresent = settings.hasValue(FilterEntries.DISABLE_REST_CATEGORIES.getKeyWithNamespace())
                || settings.hasValue(FilterEntries.DISABLE_REST_CATEGORIES.getLegacyKeyWithNamespace())
                || settings.hasValue(FilterEntries.DISABLE_TRANSPORT_CATEGORIES.getKeyWithNamespace())
                || settings.hasValue(FilterEntries.DISABLE_TRANSPORT_CATEGORIES.getLegacyKeyWithNamespace());
            warnIfBothUnifiedAndSplitConfigured(unifiedPresent, splitPresent);

            Filter filter = new Filter(
                isRestApiAuditEnabled,
                isTransportAuditEnabled,
                resolveBulkRequests,
                logRequestBody,
                resolveIndices,
                excludeSensitiveHeaders,
                ignoredAuditUsers,
                ignoreAuditRequests,
                ignoreHeaders,
                new HashSet<>(),
                disabledRestCategories,
                disabledTransportCategories,
                disabledCategories
            );

            // Load action groups from opensearch.yml (static)
            Map<String, List<String>> groups = parseActionGroupsFromSettings(settings);
            filter.setActionGroups(groups);

            // Apply initial body logging exclusions
            // NOTE: Read directly from Settings to avoid circular static initialization between
            // AuditConfig and SecuritySettings (AuditConfig.Filter.DEFAULT triggers this path
            // during class loading before SecuritySettings fields are initialized).
            List<String> exclusions = settings.getAsList(BODY_LOGGING_EXCLUSIONS_KEY, Collections.emptyList());
            filter.setBodyLoggingExclusions(exclusions);

            return filter;
        }

        static boolean fromSettingBoolean(final Settings settings, FilterEntries filterEntry, final boolean defaultValue) {
            return settings.getAsBoolean(
                filterEntry.getKeyWithNamespace(),
                settings.getAsBoolean(filterEntry.getLegacyKeyWithNamespace(), defaultValue)
            );
        }

        static Set<String> fromSettingStringSet(final Settings settings, FilterEntries filterEntry, final List<String> defaultValue) {
            final String defaultDetectorValue = "__DEFAULT_DETECTION__";
            final Set<String> stringSetOfKey = ConfigConstants.getSettingAsSet(
                settings,
                filterEntry.getKeyWithNamespace(),
                ImmutableList.of(defaultDetectorValue),
                true
            );

            final boolean foundDefault = stringSetOfKey.stream().anyMatch(defaultDetectorValue::equals);
            if (!foundDefault) {
                return stringSetOfKey;
            }

            // Fallback to the legacy keyname
            return ConfigConstants.getSettingAsSet(settings, filterEntry.getLegacyKeyWithNamespace(), defaultValue, true);
        }

        private static void warnIfBothUnifiedAndSplitConfigured(boolean unifiedPresent, boolean splitPresent) {
            if (unifiedPresent && splitPresent) {
                final DeprecationLogger deprecationLogger = DeprecationLogger.getLogger(AuditConfig.class);
                deprecationLogger.deprecate(
                    "disabled_rest_transport_categories",
                    "Both 'disabled_categories' and 'disabled_rest_categories'/'disabled_transport_categories' are configured. "
                        + "They will work in tandem, but consider migrating to 'disabled_categories' only."
                );
            }
        }

        /**
         * Splits a raw settings value (which may be a single comma-separated string or an already-split
         * list entry) into individual trimmed patterns. Shared by all action-group parsing paths.
         */
        static List<String> splitPatterns(List<String> rawList) {
            List<String> patterns = new ArrayList<>();
            for (String entry : rawList) {
                if (entry.contains(",")) {
                    for (String part : entry.split(",")) {
                        patterns.add(part.trim());
                    }
                } else {
                    patterns.add(entry.trim());
                }
            }
            return patterns;
        }

        /**
         * Parses action groups from an OpenSearch {@link Settings} object.
         * Used by both {@code AuditConfig.Filter.from(Settings)} and
         * {@code OpenSearchSecurityPlugin.parseActionGroups()}.
         */
        public static Map<String, List<String>> parseActionGroupsFromSettings(Settings settings) {
            Settings groupSettings = settings.getByPrefix(ACTION_GROUPS_PREFIX);
            Map<String, List<String>> groups = new HashMap<>();
            for (String groupName : groupSettings.keySet()) {
                List<String> rawList = settings.getAsList(ACTION_GROUPS_PREFIX + groupName);
                groups.put(groupName, splitPatterns(rawList));
            }
            return Collections.unmodifiableMap(groups);
        }

        /**
         * Parses action groups from a Map (security index deserialization path).
         * Handles both {@code Map<String, List<String>>} and {@code Map<String, String>} formats.
         */
        static Map<String, List<String>> parseActionGroupsFromMap(Map<String, Object> rawMap) {
            Map<String, List<String>> parsed = new HashMap<>();
            for (Map.Entry<String, Object> entry : rawMap.entrySet()) {
                Object val = entry.getValue();
                if (val instanceof List) {
                    @SuppressWarnings("unchecked")
                    List<String> list = (List<String>) val;
                    parsed.put(entry.getKey(), list);
                } else if (val instanceof String) {
                    parsed.put(entry.getKey(), splitPatterns(List.of((String) val)));
                }
            }
            return Collections.unmodifiableMap(parsed);
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
         * Check if request body logging should be excluded for the given action or path.
         *
         * <p><b>Two-namespace matching model:</b> This method is called with different string types
         * depending on the audit layer:
         * <ul>
         *   <li><b>REST layer</b> ({@code AuditMessage.addRestRequestInfo}): matches against
         *       {@code request.path()} — e.g. {@code /_bulk}, {@code /my-index/_search}.
         *       Note that indexed-resource paths contain the index name, so a fixed path pattern
         *       won't match them; use the transport action instead.</li>
         *   <li><b>Transport layer</b> ({@code AbstractAuditLog}, {@code AuditActionFilter}): matches
         *       against the transport action string — e.g. {@code indices:data/write/bulk[s][p]}.</li>
         * </ul>
         *
         * <p>To fully suppress body logging for a request across both layers, an action group must
         * contain both a path pattern and an action wildcard. For example, the BULK group needs:
         * {@code indices:data/write/bulk*,/_bulk}.
         *
         * @param actionOrPath transport action string or REST path
         * @return true if body should NOT be logged for this action/path
         */
        public boolean isBodyExcluded(String actionOrPath) {
            return actionOrPath != null && bodyExclusionMatcher.test(actionOrPath);
        }

        /**
         * Sets the action groups map (read from opensearch.yml at startup).
         * Triggers a rebuild of the body exclusion matcher if exclusions are configured.
         *
         * <p><b>Thread-safety note:</b> This class is not internally synchronized. Correctness
         * relies on action groups being static (set once at startup, never updated dynamically).
         * Only {@link #setBodyLoggingExclusions} is called at runtime via dynamic settings.
         * If action groups were ever made dynamic, the rebuild logic would need synchronization.
         */
        public void setActionGroups(Map<String, List<String>> groups) {
            this.actionGroups = groups != null ? groups : Collections.emptyMap();
            rebuildBodyExclusionMatcher();
        }

        /**
         * Sets the body logging exclusions list. Group names are resolved against the
         * current action groups map. Order of setActionGroups/setBodyLoggingExclusions
         * does not matter — both trigger a matcher rebuild.
         * Called at startup and when the dynamic body_logging_exclusions setting changes.
         */
        public void setBodyLoggingExclusions(List<String> exclusions) {
            if (exclusions == null || exclusions.isEmpty()) {
                this.bodyLoggingExclusions = Collections.emptyList();
            } else {
                this.bodyLoggingExclusions = List.copyOf(exclusions);
            }
            rebuildBodyExclusionMatcher();
        }

        /**
         * Rebuilds the pre-compiled body exclusion matcher from the current exclusions
         * and action groups. Called by both setters so order doesn't matter.
         */
        private void rebuildBodyExclusionMatcher() {
            List<String> exclusions = this.bodyLoggingExclusions;
            if (exclusions.isEmpty()) {
                this.bodyExclusionMatcher = WildcardMatcher.NONE;
                return;
            }
            Map<String, List<String>> groups = this.actionGroups;
            List<String> expandedPatterns = new ArrayList<>();
            for (String entry : exclusions) {
                if (groups.containsKey(entry)) {
                    expandedPatterns.addAll(groups.get(entry));
                } else {
                    expandedPatterns.add(entry);
                    // Warn about entries that don't look like action patterns or paths
                    if (!entry.contains(":") && !entry.startsWith("/") && !entry.contains("*")) {
                        log.warn(
                            "Body logging exclusion '{}' is not a known action group and does not look like "
                                + "an action pattern or path — it will be treated as a literal match.",
                            entry
                        );
                    }
                }
            }
            this.bodyExclusionMatcher = WildcardMatcher.from(expandedPatterns);
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
         * @param user effective user name (from FGAC user or SSL principal)
         * @return true if user is excluded from audit logging
         */
        public boolean isAuditDisabled(String user) {
            return ignoredAuditUsersMatcher.test(user);
        }

        /**
         * Check if user is included in audit.
         * @param user effective user name (from FGAC user or SSL principal)
         * @return true if user is included in audit logging
         */
        public boolean isAuditEnabled(String user) {
            return !ignoredAuditUsersMatcher.test(user);
        }

        @VisibleForTesting
        WildcardMatcher getIgnoredAuditRequestsMatcher() {
            return ignoredAuditRequestsMatcher;
        }

        @VisibleForTesting
        WildcardMatcher getIgnoredCustomHeadersMatcher() {
            return ignoredCustomHeadersMatcher;
        }

        @VisibleForTesting
        WildcardMatcher getIgnoredUrlParamsMatcher() {
            return ignoredUrlParamsMatcher;
        }

        /**
         * Check if the specified url param is excluded from the audit
         *
         * @param param
         * @return true if header should be excluded
         */
        public boolean shouldExcludeUrlParam(String param) {
            return ignoredUrlParamsMatcher.test(param);
        }

        /**
         * Check if the specified header is excluded from the audit
         *
         * @param header
         * @return true if header should be excluded
         */
        public boolean shouldExcludeHeader(String header) {
            return ignoredCustomHeadersMatcher.test(header);
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
         * URL Params to redact for auditing
         */
        public void setIgnoredUrlParams(Set<String> ignoredUrlParams) {
            if (ignoredUrlParams == null) {
                return;
            }
            this.ignoredUrlParamsMatcher = WildcardMatcher.from(ignoredUrlParams);
            this.ignoredUrlParams = ignoredUrlParams;
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

        /**
         * Unified disabled categories for both REST and Transport API auditing
         * @return set of categories
         */
        public Set<AuditCategory> getDisabledCategories() {
            return disabledCategories;
        }

        // Dynamic setters for cluster settings updates

        public void setLogRequestBody(boolean logRequestBody) {
            this.logRequestBody = logRequestBody;
        }

        public void setResolveBulkRequests(boolean resolveBulkRequests) {
            this.resolveBulkRequests = resolveBulkRequests;
        }

        public void setResolveIndices(boolean resolveIndices) {
            this.resolveIndices = resolveIndices;
        }

        public void setExcludeSensitiveHeaders(boolean excludeSensitiveHeaders) {
            this.excludeSensitiveHeaders = excludeSensitiveHeaders;
        }

        public void setRestApiAuditEnabled(boolean enabled) {
            this.isRestApiAuditEnabled = enabled;
        }

        public void setTransportApiAuditEnabled(boolean enabled) {
            this.isTransportApiAuditEnabled = enabled;
        }

        public void setIgnoredAuditUsers(List<String> users) {
            Set<String> newSet = ImmutableSet.copyOf(users);
            WildcardMatcher newMatcher = WildcardMatcher.from(newSet);
            this.ignoredAuditUsers = newSet;
            this.ignoredAuditUsersMatcher = newMatcher;
        }

        public void setIgnoredAuditRequests(List<String> requests) {
            Set<String> newSet = ImmutableSet.copyOf(requests);
            WildcardMatcher newMatcher = WildcardMatcher.from(newSet);
            this.ignoredAuditRequests = newSet;
            this.ignoredAuditRequestsMatcher = newMatcher;
        }

        public void setDisabledCategories(List<String> categories) {
            this.disabledCategories = AuditCategory.parse(categories);
        }

        public void setDisabledRestCategories(List<String> categories) {
            this.disabledRestCategories = AuditCategory.parse(categories);
        }

        public void setDisabledTransportCategories(List<String> categories) {
            this.disabledTransportCategories = AuditCategory.parse(categories);
        }

        public void log(Logger logger) {
            logger.info("Auditing on REST API is {}.", isRestApiAuditEnabled ? "enabled" : "disabled");
            logger.info("{} are excluded from REST API auditing.", disabledRestCategories);
            logger.info("Auditing on Transport API is {}.", isTransportApiAuditEnabled ? "enabled" : "disabled");
            logger.info("{} are excluded from Transport API auditing.", disabledTransportCategories);
            logger.info("Auditing of request body is {}.", logRequestBody ? "enabled" : "disabled");
            logger.info("Bulk requests resolution is {} during request auditing.", resolveBulkRequests ? "enabled" : "disabled");
            logger.info("Index resolution is {} during request auditing.", resolveIndices ? "enabled" : "disabled");
            logger.info("Sensitive headers exclusion from auditing is {}.", excludeSensitiveHeaders ? "enabled" : "disabled");
            logger.info("Auditing requests from {} users is disabled.", ignoredAuditUsersMatcher);
            logger.info("Auditing request headers {} is disabled.", ignoredCustomHeadersMatcher);
            logger.info("Auditing request url params {} is disabled.", ignoredUrlParamsMatcher);
        }

        @Override
        public String toString() {
            return "Filter{"
                + "isRestApiAuditEnabled="
                + isRestApiAuditEnabled
                + ", disabledRestCategories="
                + disabledRestCategories
                + ", isTransportApiAuditEnabled="
                + isTransportApiAuditEnabled
                + ", disabledTransportCategories="
                + disabledTransportCategories
                + ", resolveBulkRequests="
                + resolveBulkRequests
                + ", logRequestBody="
                + logRequestBody
                + ", resolveIndices="
                + resolveIndices
                + ", excludeSensitiveHeaders="
                + excludeSensitiveHeaders
                + ", ignoredAuditUsers="
                + ignoredAuditUsersMatcher
                + ", ignoreAuditRequests="
                + ignoredAuditRequestsMatcher
                + ", ignoredCustomHeaders="
                + ignoredCustomHeadersMatcher
                + ", ignoredUrlParamsMatcher="
                + ignoredUrlParamsMatcher
                + '}';
        }
    }

    /**
     * List of keys that are deprecated
     */
    @Deprecated
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
        return AuditConfig.DEPRECATED_KEYS.stream().filter(settings::hasValue).collect(Collectors.toSet());
    }

    public static final Set<String> FIELD_PATHS = Sets.union(
        Utils.generateFieldResourcePaths(AuditConfig.FIELDS, "/"),
        Sets.union(
            Utils.generateFieldResourcePaths(Filter.FIELDS, "/audit/"),
            Utils.generateFieldResourcePaths(ComplianceConfig.FIELDS, "/compliance/")
        )
    );
}
