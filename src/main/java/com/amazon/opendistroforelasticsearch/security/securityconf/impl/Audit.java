package com.amazon.opendistroforelasticsearch.security.securityconf.impl;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.fasterxml.jackson.annotation.JsonIgnore;
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

    @JsonIgnore
    public boolean isRestApiAuditEnabled() {
        return enableRest;
    }

    @JsonIgnore
    public void setRestApiAuditEnabled(boolean enableRest) {
        this.enableRest = enableRest;
    }

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

    @JsonIgnore
    public boolean isTransportApiAuditEnabled() {
        return enableTransport;
    }

    @JsonIgnore
    public void setTransportApiAuditEnabled(boolean enableTransport) {
        this.enableTransport = enableTransport;
    }

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
    public boolean isResolveBulkRequests() {
        return resolveBulkRequests;
    }

    @JsonIgnore
    public void setResolveBulkRequests(boolean resolveBulkRequests) {
        this.resolveBulkRequests = resolveBulkRequests;
    }

    @JsonIgnore
    public boolean isLogRequestBody() {
        return logRequestBody;
    }

    @JsonIgnore
    public void setLogRequestBody(boolean logRequestBody) {
        this.logRequestBody = logRequestBody;
    }

    @JsonIgnore
    public boolean isResolveIndices() {
        return resolveIndices;
    }

    @JsonIgnore
    public void setResolveIndices(boolean resolveIndices) {
        this.resolveIndices = resolveIndices;
    }

    @JsonIgnore
    public boolean isExcludeSensitiveHeaders() {
        return excludeSensitiveHeaders;
    }

    @JsonIgnore
    public void setExcludeSensitiveHeaders(boolean excludeSensitiveHeaders) {
        this.excludeSensitiveHeaders = excludeSensitiveHeaders;
    }

    @JsonIgnore
    public Set<String> getIgnoreUsers() {
        return ignoreUsers;
    }

    @JsonSetter(value = Key.IGNORE_USERS, nulls = Nulls.AS_EMPTY)
    public void setIgnoreUsers(Set<String> ignoreUsers) {
        if (ignoreUsers != null) {
            this.ignoreUsers = ignoreUsers;
        } else {
            this.ignoreUsers = Collections.emptySet();
        }
    }

    @JsonIgnore
    public Set<String> getIgnoreRequests() {
        return ignoreRequests;
    }

    @JsonSetter(value = Key.IGNORE_REQUESTS, nulls = Nulls.AS_EMPTY)
    public void setIgnoreRequests(Set<String> ignoreRequests) {
        if (ignoreRequests != null) {
            this.ignoreRequests = ignoreRequests;
        } else {
            this.ignoreRequests = Collections.emptySet();
        }
    }

    @JsonIgnore
    public Set<String> getImmutableIndices() {
        return immutableIndices;
    }

    @JsonSetter(value = Key.IMMUTABLE_INDICES, nulls = Nulls.AS_EMPTY)
    public void setImmutableIndices(Set<String> immutableIndices) {
        if (immutableIndices != null) {
            this.immutableIndices = immutableIndices;
        } else {
            this.immutableIndices = Collections.emptySet();
        }
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
    public List<String> getReadWatchedFields() {
        return readWatchedFields;
    }

    @JsonSetter(value = Key.READ_WATCHED_FIELDS, nulls = Nulls.AS_EMPTY)
    public void setReadWatchedFields(List<String> readWatchedFields) {
        if (readWatchedFields != null) {
            this.readWatchedFields = readWatchedFields;
        } else {
            this.readWatchedFields = Collections.emptyList();
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

    @JsonIgnore
    public String getSalt() {
        return salt;
    }

    @JsonIgnore
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
