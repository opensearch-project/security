package com.amazon.opendistroforelasticsearch.security.securityconf.impl;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import com.google.common.collect.ImmutableSet;

import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import static com.amazon.opendistroforelasticsearch.security.support.ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT_DEFAULT;

public class Audit {
    private static final Set<String> DEFAULT_IGNORED_USERS = Collections.singleton("kibanaserver");
    private static final EnumSet<AuditCategory> DEFAULT_DISABLED_CATEGORIES = EnumSet.of(AuditCategory.AUTHENTICATED, AuditCategory.GRANTED_PRIVILEGES);

    @JsonProperty(value = Key.ENABLE_REST)
    private boolean enableRest = true;
    @JsonProperty(value = Key.DISABLED_REST_CATEGORIES)
    private EnumSet<AuditCategory> disabledRestCategories = DEFAULT_DISABLED_CATEGORIES;
    @JsonProperty(value = Key.ENABLE_TRANSPORT)
    private boolean enableTransport = true;
    @JsonProperty(value = Key.DISABLED_TRANSPORT_CATEGORIES)
    private EnumSet<AuditCategory> disabledTransportCategories = DEFAULT_DISABLED_CATEGORIES;
    @JsonProperty(value = Key.INTERNAL_CONFIG_ENABLED)
    private boolean internalConfigEnabled = true;
    @JsonProperty(value = Key.EXTERNAL_CONFIG_ENABLED)
    private boolean externalConfigEnabled = false;
    @JsonProperty(value = Key.RESOLVE_BULK_REQUESTS)
    private boolean resolveBulkRequests = false;
    @JsonProperty(value = Key.LOG_REQUEST_BODY)
    private boolean logRequestBody = true;
    @JsonProperty(value = Key.RESOLVE_INDICES)
    private boolean resolveIndices = true;
    @JsonProperty(value = Key.EXCLUDE_SENSITIVE_HEADERS)
    private boolean excludeSensitiveHeaders = true;
    @JsonProperty(value = Key.IGNORE_USERS)
    private Set<String> ignoreUsers = DEFAULT_IGNORED_USERS;
    @JsonProperty(value = Key.IGNORE_REQUESTS)
    private Set<String> ignoreRequests = Collections.emptySet();
    @JsonProperty(value = Key.IMMUTABLE_INDICES)
    private Set<String> immutableIndices = Collections.emptySet();
    @JsonProperty(value = Key.READ_METADATA_ONLY)
    private boolean readMetadataOnly = true;
    @JsonProperty(value = Key.READ_WATCHED_FIELDS)
    private List<String> readWatchedFields = Collections.emptyList();
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
    @JsonProperty(value = Key.SALT)
    private String salt = OPENDISTRO_SECURITY_COMPLIANCE_SALT_DEFAULT;

    @JsonProperty(value = Key.ENABLE_REST)
    public boolean isEnableRest() {
        return enableRest;
    }

    @JsonProperty(value = Key.ENABLE_REST)
    public void setEnableRest(boolean enableRest) {
        this.enableRest = enableRest;
    }

    @JsonProperty(value = Key.DISABLED_REST_CATEGORIES)
    public EnumSet<AuditCategory> getDisabledRestCategories() {
        return disabledRestCategories;
    }

    @JsonProperty(value = Key.DISABLED_REST_CATEGORIES)
    public void setDisabledRestCategories(EnumSet<AuditCategory> disabledRestCategories) {
        if (disabledRestCategories != null) {
            this.disabledRestCategories = disabledRestCategories;
        } else {
            this.disabledRestCategories = EnumSet.noneOf(AuditCategory.class);
        }
    }

    @JsonProperty(value = Key.ENABLE_TRANSPORT)
    public boolean isEnableTransport() {
        return enableTransport;
    }

    @JsonProperty(value = Key.ENABLE_TRANSPORT)
    public void setEnableTransport(boolean enableTransport) {
        this.enableTransport = enableTransport;
    }

    @JsonProperty(value = Key.DISABLED_TRANSPORT_CATEGORIES)
    public EnumSet<AuditCategory> getDisabledTransportCategories() {
        return disabledTransportCategories;
    }

    @JsonProperty(value = Key.DISABLED_TRANSPORT_CATEGORIES)
    @JsonSetter(nulls = Nulls.AS_EMPTY)
    public void setDisabledTransportCategories(EnumSet<AuditCategory> disabledTransportCategories) {
        if (disabledTransportCategories != null) {
            this.disabledTransportCategories = disabledTransportCategories;
        } else {
            this.disabledTransportCategories = EnumSet.noneOf(AuditCategory.class);
        }
    }

    @JsonProperty(value = Key.INTERNAL_CONFIG_ENABLED)
    public boolean isInternalConfigEnabled() {
        return internalConfigEnabled;
    }

    @JsonProperty(value = Key.INTERNAL_CONFIG_ENABLED)
    public void setInternalConfigEnabled(boolean internalConfigEnabled) {
        this.internalConfigEnabled = internalConfigEnabled;
    }

    @JsonProperty(value = Key.EXTERNAL_CONFIG_ENABLED)
    public boolean isExternalConfigEnabled() {
        return externalConfigEnabled;
    }

    @JsonProperty(value = Key.EXTERNAL_CONFIG_ENABLED)
    public void setExternalConfigEnabled(boolean externalConfigEnabled) {
        this.externalConfigEnabled = externalConfigEnabled;
    }

    @JsonProperty(value = Key.RESOLVE_BULK_REQUESTS)
    public boolean isResolveBulkRequests() {
        return resolveBulkRequests;
    }

    @JsonProperty(value = Key.RESOLVE_BULK_REQUESTS)
    public void setResolveBulkRequests(boolean resolveBulkRequests) {
        this.resolveBulkRequests = resolveBulkRequests;
    }

    @JsonProperty(value = Key.LOG_REQUEST_BODY)
    public boolean isLogRequestBody() {
        return logRequestBody;
    }

    @JsonProperty(value = Key.LOG_REQUEST_BODY)
    public void setLogRequestBody(boolean logRequestBody) {
        this.logRequestBody = logRequestBody;
    }

    @JsonProperty(value = Key.RESOLVE_INDICES)
    public boolean isResolveIndices() {
        return resolveIndices;
    }

    @JsonProperty(value = Key.RESOLVE_INDICES)
    public void setResolveIndices(boolean resolveIndices) {
        this.resolveIndices = resolveIndices;
    }

    @JsonProperty(value = Key.EXCLUDE_SENSITIVE_HEADERS)
    public boolean isExcludeSensitiveHeaders() {
        return excludeSensitiveHeaders;
    }

    @JsonProperty(value = Key.EXCLUDE_SENSITIVE_HEADERS)
    public void setExcludeSensitiveHeaders(boolean excludeSensitiveHeaders) {
        this.excludeSensitiveHeaders = excludeSensitiveHeaders;
    }

    @JsonProperty(value = Key.IGNORE_USERS)
    public Set<String> getIgnoreUsers() {
        return ignoreUsers;
    }

    @JsonProperty(value = Key.IGNORE_USERS)
    @JsonSetter(nulls = Nulls.AS_EMPTY)
    public void setIgnoreUsers(Set<String> ignoreUsers) {
        if (ignoreUsers != null)
            this.ignoreUsers = ignoreUsers;
    }

    @JsonProperty(value = Key.IGNORE_REQUESTS)
    public Set<String> getIgnoreRequests() {
        return ignoreRequests;
    }

    @JsonProperty(value = Key.IGNORE_REQUESTS)
    public void setIgnoreRequests(Set<String> ignoreRequests) {
        if (ignoreRequests != null)
            this.ignoreRequests = ignoreRequests;
    }

    @JsonProperty(value = Key.IMMUTABLE_INDICES)
    public Set<String> getImmutableIndices() {
        return immutableIndices;
    }

    @JsonProperty(value = Key.IMMUTABLE_INDICES)
    public void setImmutableIndices(Set<String> immutableIndices) {
        if (immutableIndices != null)
            this.immutableIndices = immutableIndices;
    }

    @JsonProperty(value = Key.READ_METADATA_ONLY)
    public boolean isReadMetadataOnly() {
        return readMetadataOnly;
    }

    @JsonProperty(value = Key.READ_METADATA_ONLY)
    public void setReadMetadataOnly(boolean readMetadataOnly) {
        this.readMetadataOnly = readMetadataOnly;
    }

    @JsonProperty(value = Key.READ_WATCHED_FIELDS)
    public List<String> getReadWatchedFields() {
        return readWatchedFields;
    }

    @JsonProperty(value = Key.READ_WATCHED_FIELDS)
    public void setReadWatchedFields(List<String> readWatchedFields) {
        if (readWatchedFields != null)
            this.readWatchedFields = readWatchedFields;
    }

    @JsonProperty(value = Key.READ_IGNORE_USERS)
    public Set<String> getReadIgnoreUsers() {
        return readIgnoreUsers;
    }

    @JsonProperty(value = Key.READ_IGNORE_USERS)
    public void setReadIgnoreUsers(Set<String> readIgnoreUsers) {
        if (readIgnoreUsers != null)
            this.readIgnoreUsers = readIgnoreUsers;
    }

    @JsonProperty(value = Key.WRITE_METADATA_ONLY)
    public boolean isWriteMetadataOnly() {
        return writeMetadataOnly;
    }

    @JsonProperty(value = Key.WRITE_METADATA_ONLY)
    public void setWriteMetadataOnly(boolean writeMetadataOnly) {
        this.writeMetadataOnly = writeMetadataOnly;
    }

    @JsonProperty(value = Key.WRITE_LOG_DIFFS)
    public boolean isWriteLogDiffs() {
        return writeLogDiffs;
    }

    @JsonProperty(value = Key.WRITE_LOG_DIFFS)
    public void setWriteLogDiffs(boolean writeLogDiffs) {
        this.writeLogDiffs = writeLogDiffs;
    }

    @JsonProperty(value = Key.WRITE_WATCHED_INDICES)
    public List<String> getWriteWatchedIndices() {
        return writeWatchedIndices;
    }

    @JsonProperty(value = Key.WRITE_WATCHED_INDICES)
    public void setWriteWatchedIndices(List<String> writeWatchedIndices) {
        if (writeWatchedIndices != null)
            this.writeWatchedIndices = writeWatchedIndices;
    }

    @JsonProperty(value = Key.WRITE_IGNORE_USERS)
    public Set<String> getWriteIgnoreUsers() {
        return writeIgnoreUsers;
    }

    @JsonProperty(value = Key.WRITE_IGNORE_USERS)
    public void setWriteIgnoreUsers(Set<String> writeIgnoreUsers) {
        if (writeIgnoreUsers != null)
            this.writeIgnoreUsers = writeIgnoreUsers;
    }

    @JsonProperty(value = Key.SALT)
    public String getSalt() {
        return salt;
    }

    @JsonProperty(value = Key.SALT)
    public void setSalt(String salt) {
        this.salt = salt;
    }

    @Override
    public String toString() {
        return "Audit{" +
                "enableRest=" + enableRest +
                ", disabledRestCategories=" + disabledRestCategories +
                ", enableTransport=" + enableTransport +
                ", disabledTransportCategories=" + disabledTransportCategories +
                ", internalConfigEnabled=" + internalConfigEnabled +
                ", externalConfigEnabled=" + externalConfigEnabled +
                ", resolveBulkRequests=" + resolveBulkRequests +
                ", logRequestBody=" + logRequestBody +
                ", resolveIndices=" + resolveIndices +
                ", excludeSensitiveHeaders=" + excludeSensitiveHeaders +
                ", ignoreUsers=" + ignoreUsers +
                ", ignoreRequests=" + ignoreRequests +
                ", immutableIndices=" + immutableIndices +
                ", readMetadataOnly=" + readMetadataOnly +
                ", readWatchedFields=" + readWatchedFields +
                ", readIgnoreUsers=" + readIgnoreUsers +
                ", writeMetadataOnly=" + writeMetadataOnly +
                ", writeLogDiffs=" + writeLogDiffs +
                ", writeWatchedIndices=" + writeWatchedIndices +
                ", writeIgnoreUsers=" + writeIgnoreUsers +
                ", salt='" + salt + '\'' +
                '}';
    }

    public static class Key {
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
        public static final String IMMUTABLE_INDICES = "immutable_indices";
        public static final String READ_METADATA_ONLY = "read_metadata_only";
        public static final String READ_WATCHED_FIELDS = "read_watched_fields";
        public static final String READ_IGNORE_USERS = "read_ignore_users";
        public static final String WRITE_METADATA_ONLY = "write_metadata_only";
        public static final String WRITE_LOG_DIFFS = "write_log_diffs";
        public static final String WRITE_WATCHED_INDICES = "write_watched_indices";
        public static final String WRITE_IGNORE_USERS = "write_ignore_users";
        public static final String SALT = "salt";

        public static final Set<String> KEYS = ImmutableSet.of(
                ENABLE_REST,
                DISABLED_REST_CATEGORIES,
                ENABLE_TRANSPORT,
                DISABLED_TRANSPORT_CATEGORIES,
                INTERNAL_CONFIG_ENABLED,
                EXTERNAL_CONFIG_ENABLED,
                RESOLVE_BULK_REQUESTS,
                LOG_REQUEST_BODY,
                RESOLVE_INDICES,
                EXCLUDE_SENSITIVE_HEADERS,
                IGNORE_USERS,
                IGNORE_REQUESTS,
                IMMUTABLE_INDICES,
                READ_METADATA_ONLY,
                READ_WATCHED_FIELDS,
                READ_IGNORE_USERS,
                WRITE_METADATA_ONLY,
                WRITE_LOG_DIFFS,
                WRITE_WATCHED_INDICES,
                WRITE_IGNORE_USERS,
                SALT
        );

        public static void validate(final List<String> keys) {
            keys.forEach(key -> {
                if (!KEYS.contains(key)) {
                    throw new IllegalArgumentException("Input list " + keys + " contains invalid key " + key);
                }
            });
        }
    }
}
