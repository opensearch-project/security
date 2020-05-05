package com.amazon.opendistroforelasticsearch.security.auditlog.config;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

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

    private static final Set<String> DEFAULT_IGNORED_USERS = Collections.singleton("kibanaserver");
    private static final EnumSet<AuditCategory> DEFAULT_DISABLED_CATEGORIES = EnumSet.of(
            AuditCategory.AUTHENTICATED, AuditCategory.GRANTED_PRIVILEGES);

    @JsonProperty(value = Key.ENABLED)
    private boolean auditLogEnabled = true;
    @JsonProperty(value = Key.AUDIT)
    private Filter filter = new Filter();
    @JsonProperty(value = Key.COMPLIANCE)
    private Compliance compliance = new Compliance();

    @JsonIgnore
    public boolean isEnabled() {
        return auditLogEnabled;
    }

    @JsonIgnore
    public void setEnabled(boolean auditLogEnabled) {
        this.auditLogEnabled = auditLogEnabled;
    }

    @JsonIgnore
    public Filter getFilter() {
        return filter;
    }

    @JsonProperty(value = Key.AUDIT)
    public void setFilter(Filter filter) {
        this.filter = filter;
    }

    @JsonIgnore
    public Compliance getCompliance() {
        return compliance;
    }

    @JsonProperty(value = Key.COMPLIANCE)
    public void setCompliance(Compliance compliance) {
        this.compliance = compliance;
    }

    /**
     * Filter represents set of filtering configuration settings for audit logging.
     * Audit logger will use these settings to determine what audit logs are to be generated.
     */
    public static class Filter {
        @JsonProperty(value = Key.ENABLE_REST)
        private boolean isRestApiAuditEnabled = true;
        @JsonProperty(value = Key.DISABLED_REST_CATEGORIES)
        private EnumSet<AuditCategory> disabledRestCategories = DEFAULT_DISABLED_CATEGORIES;
        @JsonProperty(value = Key.ENABLE_TRANSPORT)
        private boolean isTransportApiAuditEnabled = true;
        @JsonProperty(value = Key.DISABLED_TRANSPORT_CATEGORIES)
        private EnumSet<AuditCategory> disabledTransportCategories = DEFAULT_DISABLED_CATEGORIES;
        @JsonProperty(value = Key.RESOLVE_BULK_REQUESTS)
        private boolean resolveBulkRequests = false;
        @JsonProperty(value = Key.LOG_REQUEST_BODY)
        private boolean logRequestBody = true;
        @JsonProperty(value = Key.RESOLVE_INDICES)
        private boolean resolveIndices = true;
        @JsonProperty(value = Key.EXCLUDE_SENSITIVE_HEADERS)
        private boolean excludeSensitiveHeaders = true;
        @JsonProperty(value = Key.IGNORE_USERS)
        private Set<String> ignoredAuditUsers = DEFAULT_IGNORED_USERS;
        @JsonProperty(value = Key.IGNORE_REQUESTS)
        private Set<String> ignoreAuditRequests = Collections.emptySet();

        /**
         * Checks if auditing for REST API is enabled or disabled
         * @return true/false
         */
        @JsonIgnore
        public boolean isRestApiAuditEnabled() {
            return isRestApiAuditEnabled;
        }

        @JsonIgnore
        public void setRestApiAuditEnabled(boolean enableRest) {
            this.isRestApiAuditEnabled = enableRest;
        }

        /**
         * Disabled categories for REST API auditing
         * @return set of categories
         */
        @JsonIgnore
        public EnumSet<AuditCategory> getDisabledRestCategories() {
            return disabledRestCategories;
        }

        @JsonSetter(value = Key.DISABLED_REST_CATEGORIES, nulls = Nulls.AS_EMPTY)
        public void setDisabledRestCategories(Set<AuditCategory> disabledRestCategories) {
            if (disabledRestCategories != null && !disabledRestCategories.isEmpty()) {
                if (disabledRestCategories instanceof EnumSet) {
                    this.disabledRestCategories = (EnumSet) disabledRestCategories;
                } else {
                    this.disabledRestCategories = EnumSet.copyOf(disabledRestCategories);
                }
            } else {
                this.disabledRestCategories = EnumSet.noneOf(AuditCategory.class);
            }
        }

        /**
         * Checks if auditing for Transport API is enabled or disabled
         * @return true/false
         */
        @JsonIgnore
        public boolean isTransportApiAuditEnabled() {
            return isTransportApiAuditEnabled;
        }

        @JsonIgnore
        public void setTransportApiAuditEnabled(boolean enableTransport) {
            this.isTransportApiAuditEnabled = enableTransport;
        }

        /**
         * Disabled categories for Transport API auditing
         * @return set of categories
         */
        @JsonIgnore
        public EnumSet<AuditCategory> getDisabledTransportCategories() {
            return disabledTransportCategories;
        }

        @JsonSetter(value = Key.DISABLED_TRANSPORT_CATEGORIES, nulls = Nulls.AS_EMPTY)
        public void setDisabledTransportCategories(Set<AuditCategory> disabledTransportCategories) {
            if (disabledTransportCategories != null && !disabledTransportCategories.isEmpty()) {
                if (disabledTransportCategories instanceof EnumSet) {
                    this.disabledTransportCategories = (EnumSet) disabledTransportCategories;
                } else {
                    this.disabledTransportCategories = EnumSet.copyOf(disabledTransportCategories);
                }
            } else {
                this.disabledTransportCategories = EnumSet.noneOf(AuditCategory.class);
            }
        }

        /**
         * Check if indices must be resolved during auditing
         * @return true/false
         */
        @JsonIgnore
        public boolean shouldResolveBulkRequests() {
            return resolveBulkRequests;
        }

        @JsonIgnore
        public void setResolveBulkRequests(boolean resolveBulkRequests) {
            this.resolveBulkRequests = resolveBulkRequests;
        }

        /**
         * Checks if request body must be logged
         * @return true/false
         */
        @JsonIgnore
        public boolean shouldLogRequestBody() {
            return logRequestBody;
        }

        @JsonIgnore
        public void setLogRequestBody(boolean logRequestBody) {
            this.logRequestBody = logRequestBody;
        }

        /**
         * Check if indices must be resolved during auditing
         * @return true/false
         */
        @JsonIgnore
        public boolean shouldResolveIndices() {
            return resolveIndices;
        }

        @JsonIgnore
        public void setResolveIndices(boolean resolveIndices) {
            this.resolveIndices = resolveIndices;
        }

        /**
         * Checks if sensitive headers eg: Authorization must be excluded in log messages
         * @return true/false
         */
        @JsonIgnore
        public boolean shouldExcludeSensitiveHeaders() {
            return excludeSensitiveHeaders;
        }

        @JsonIgnore
        public void setExcludeSensitiveHeaders(boolean excludeSensitiveHeaders) {
            this.excludeSensitiveHeaders = excludeSensitiveHeaders;
        }

        /**
         * Set of users for whom auditing must be ignored.
         * @return set of users
         */
        @JsonIgnore
        public Set<String> getIgnoredAuditUsers() {
            return ignoredAuditUsers;
        }

        @JsonSetter(value = Key.IGNORE_USERS, nulls = Nulls.AS_EMPTY)
        public void setIgnoreUsers(Set<String> ignoreUsers) {
            if (ignoreUsers != null) {
                this.ignoredAuditUsers = ignoreUsers;
            } else {
                this.ignoredAuditUsers = Collections.emptySet();
            }
        }

        /**
         * Request patterns that must be ignored.
         * @return set of request patterns
         */
        @JsonIgnore
        public Set<String> getIgnoredAuditRequests() {
            return ignoreAuditRequests;
        }

        @JsonSetter(value = Key.IGNORE_REQUESTS, nulls = Nulls.AS_EMPTY)
        public void setIgnoreRequests(Set<String> ignoreRequests) {
            if (ignoreRequests != null) {
                this.ignoreAuditRequests = ignoreRequests;
            } else {
                this.ignoreAuditRequests = Collections.emptySet();
            }
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
        }
    }

    public static class Compliance {
        @JsonProperty(value = Key.ENABLED)
        private boolean complianceEnabled = true;
        @JsonProperty(value = Key.INTERNAL_CONFIG_ENABLED)
        private boolean internalConfigEnabled = true;
        @JsonProperty(value = Key.EXTERNAL_CONFIG_ENABLED)
        private boolean externalConfigEnabled = false;
        @JsonProperty(value = Key.READ_METADATA_ONLY)
        private boolean readMetadataOnly = true;
        @JsonProperty(value = Key.READ_WATCHED_FIELDS)
        private Map<String, Set<String>> readWatchedFields = Collections.emptyMap();
        @JsonProperty(value = Key.READ_IGNORE_USERS)
        private Set<String> readIgnoreUsers = Collections.emptySet();
        @JsonProperty(value = Key.WRITE_METADATA_ONLY)
        private boolean writeMetadataOnly = true;
        @JsonProperty(value = Key.WRITE_LOG_DIFFS)
        private boolean writeLogDiffs = false;
        @JsonProperty(value = Key.WRITE_WATCHED_INDICES)
        private List<String> writeWatchedIndices = Collections.emptyList();
        @JsonProperty(value = Key.WRITE_IGNORE_USERS)
        private Set<String> writeIgnoreUsers = Collections.emptySet();

        @JsonIgnore
        public boolean isComplianceEnabled() {
            return complianceEnabled;
        }

        @JsonIgnore
        public void setComplianceEnabled(boolean complianceEnabled) {
            this.complianceEnabled = complianceEnabled;
        }

        @JsonIgnore
        public boolean isInternalConfigEnabled() {
            return internalConfigEnabled;
        }

        @JsonIgnore
        public void setInternalConfigEnabled(boolean internalConfigEnabled) {
            this.internalConfigEnabled = internalConfigEnabled;
        }

        @JsonIgnore
        public boolean isExternalConfigEnabled() {
            return externalConfigEnabled;
        }

        @JsonIgnore
        public void setExternalConfigEnabled(boolean externalConfigEnabled) {
            this.externalConfigEnabled = externalConfigEnabled;
        }

        @JsonIgnore
        public boolean isReadMetadataOnly() {
            return readMetadataOnly;
        }

        @JsonIgnore
        public void setReadMetadataOnly(boolean readMetadataOnly) {
            this.readMetadataOnly = readMetadataOnly;
        }

        @JsonIgnore
        public Map<String, Set<String>> getReadWatchedFields() {
            return readWatchedFields;
        }

        @JsonSetter(value = Key.READ_WATCHED_FIELDS, nulls = Nulls.AS_EMPTY)
        public void setReadWatchedFields(Map<String, Set<String>> readWatchedFields) {
            if (readWatchedFields != null) {
                this.readWatchedFields = readWatchedFields;
            } else {
                this.readWatchedFields = Collections.emptyMap();
            }
        }

        @JsonIgnore
        public Set<String> getReadIgnoreUsers() {
            return readIgnoreUsers;
        }

        @JsonSetter(value = Key.READ_IGNORE_USERS, nulls = Nulls.AS_EMPTY)
        public void setReadIgnoreUsers(Set<String> readIgnoreUsers) {
            if (readIgnoreUsers != null) {
                this.readIgnoreUsers = readIgnoreUsers;
            } else {
                this.readIgnoreUsers = Collections.emptySet();
            }
        }

        @JsonIgnore
        public boolean isWriteMetadataOnly() {
            return writeMetadataOnly;
        }

        @JsonIgnore
        public void setWriteMetadataOnly(boolean writeMetadataOnly) {
            this.writeMetadataOnly = writeMetadataOnly;
        }

        @JsonIgnore
        public boolean isWriteLogDiffs() {
            return writeLogDiffs;
        }

        @JsonIgnore
        public void setWriteLogDiffs(boolean writeLogDiffs) {
            this.writeLogDiffs = writeLogDiffs;
        }

        @JsonIgnore
        public List<String> getWriteWatchedIndices() {
            return writeWatchedIndices;
        }

        @JsonSetter(value = Key.WRITE_WATCHED_INDICES, nulls = Nulls.AS_EMPTY)
        public void setWriteWatchedIndices(List<String> writeWatchedIndices) {
            if (writeWatchedIndices != null) {
                this.writeWatchedIndices = writeWatchedIndices;
            } else {
                this.writeWatchedIndices = Collections.emptyList();
            }
        }

        @JsonIgnore
        public Set<String> getWriteIgnoreUsers() {
            return writeIgnoreUsers;
        }

        @JsonSetter(value = Key.WRITE_IGNORE_USERS, nulls = Nulls.AS_EMPTY)
        public void setWriteIgnoreUsers(Set<String> writeIgnoreUsers) {
            if (writeIgnoreUsers != null) {
                this.writeIgnoreUsers = writeIgnoreUsers;
            } else {
                this.readIgnoreUsers = Collections.emptySet();
            }
        }
    }

    public static class Key {
        public static final String ENABLED = "enabled";
        public static final String AUDIT = "audit";
        public static final String COMPLIANCE = "compliance";
        public static final String ENABLE_REST = "enable_rest";
        public static final String DISABLED_REST_CATEGORIES = "disabled_rest_categories";
        public static final String ENABLE_TRANSPORT = "enable_transport";
        public static final String DISABLED_TRANSPORT_CATEGORIES = "disabled_transport_categories";
        public static final String INTERNAL_CONFIG_ENABLED = "internal_config";
        public static final String EXTERNAL_CONFIG_ENABLED = "external_config";
        public static final String RESOLVE_BULK_REQUESTS = "resolve_bulk_requests";
        public static final String LOG_REQUEST_BODY = "log_request_body";
        public static final String RESOLVE_INDICES = "resolve_indices";
        public static final String EXCLUDE_SENSITIVE_HEADERS = "exclude_sensitive_headers";
        public static final String IGNORE_USERS = "ignore_users";
        public static final String IGNORE_REQUESTS = "ignore_requests";
        public static final String READ_METADATA_ONLY = "read_metadata_only";
        public static final String READ_WATCHED_FIELDS = "read_watched_fields";
        public static final String READ_IGNORE_USERS = "read_ignore_users";
        public static final String WRITE_METADATA_ONLY = "write_metadata_only";
        public static final String WRITE_LOG_DIFFS = "write_log_diffs";
        public static final String WRITE_WATCHED_INDICES = "write_watched_indices";
        public static final String WRITE_IGNORE_USERS = "write_ignore_users";
    }

    private static final List<String> DEFAULT_IGNORED_USERS_LIST = ImmutableList.copyOf(DEFAULT_IGNORED_USERS);
    private static final List<String> DEFAULT_DISABLED_CATEGORIES_LIST = DEFAULT_DISABLED_CATEGORIES.stream().map(Enum::name).collect(Collectors.toList());

    /**
     * Generate audit logging configuration from settings defined in elasticsearch.yml
     * @param settings settings
     * @return audit configuration filter
     */
    public static AuditConfig from(Settings settings) {
        final AuditConfig auditConfig = new AuditConfig();
        final Filter audit = new Filter();
        final Compliance compliance = new Compliance();
        audit.setRestApiAuditEnabled(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true));
        audit.setTransportApiAuditEnabled(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true));
        audit.setResolveBulkRequests(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false));
        audit.setLogRequestBody(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, true));
        audit.setResolveIndices(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, true));
        audit.setExcludeSensitiveHeaders(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS, true));

        audit.setDisabledRestCategories(AuditCategory.parse(getSettingAsSet(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES,
                DEFAULT_DISABLED_CATEGORIES_LIST,
                true)));

        audit.setDisabledTransportCategories(AuditCategory.parse(getSettingAsSet(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES,
                DEFAULT_DISABLED_CATEGORIES_LIST,
                true)));

        audit.setIgnoreUsers(getSettingAsSet(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS,
                DEFAULT_IGNORED_USERS_LIST,
                false));

        audit.setIgnoreRequests(ImmutableSet.copyOf(settings.getAsList(
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS,
                Collections.emptyList())));

        compliance.setExternalConfigEnabled(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false));
        compliance.setInternalConfigEnabled(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, false));
        compliance.setReadMetadataOnly(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY, false));
        compliance.setWriteMetadataOnly(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY, false));
        compliance.setWriteLogDiffs(settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, false));

        final List<String> setReadWatchedFieldsList = settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS,
                Collections.emptyList(), false);
        //opendistro_security.compliance.pii_fields:
        //  - indexpattern,fieldpattern,fieldpattern,....
        Map<String, Set<String>> readEnabledFields = setReadWatchedFieldsList.stream()
                .map(watchedReadField -> watchedReadField.split(","))
                .filter(split -> split.length != 0 && !Strings.isNullOrEmpty(split[0]))
                .collect(Collectors.toMap(
                        split -> split[0],
                        split -> split.length == 1 ?
                                Collections.singleton("*") : Arrays.stream(split).skip(1).collect(Collectors.toSet())
                ));
        compliance.setReadWatchedFields(readEnabledFields);

        compliance.setWriteWatchedIndices(settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, Collections.emptyList()));
        compliance.setReadIgnoreUsers(getSettingAsSet(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS,
                DEFAULT_IGNORED_USERS_LIST,
                false));
        compliance.setWriteIgnoreUsers(getSettingAsSet(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS,
                DEFAULT_IGNORED_USERS_LIST,
                false));
        auditConfig.setFilter(audit);
        auditConfig.setCompliance(compliance);
        return auditConfig;
    }

    private static Set<String> getSettingAsSet(final Settings settings, final String key, final List<String> defaultList, final boolean ignoreCaseForNone) {
        final List<String> list = settings.getAsList(key, defaultList);
        if (list.size() == 1 && "NONE".equals(ignoreCaseForNone? list.get(0).toUpperCase() : list.get(0))) {
            return Collections.emptySet();
        }
        return ImmutableSet.copyOf(list);
    }
}
