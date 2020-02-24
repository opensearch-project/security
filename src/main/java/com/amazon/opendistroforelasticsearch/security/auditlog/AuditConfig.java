package com.amazon.opendistroforelasticsearch.security.auditlog;

import com.amazon.opendistroforelasticsearch.security.auditlog.impl.AuditCategory;
import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.settings.Settings;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;

public class AuditConfig {
    private final Logger log = LogManager.getLogger(getClass());

    private final boolean restAuditingEnabled;
    private final boolean transportAuditingEnabled;
    private final boolean resolveBulkRequests;
    private final boolean logRequestBody;
    private final boolean resolveIndices;
    private final boolean excludeSensitiveHeaders;
    private final boolean logDiffsForWrite;
    private final boolean logWriteMetadataOnly;
    private final boolean logReadMetadataOnly;
    private final boolean logExternalConfig;
    private final boolean logInternalConfig;
    private final List<String> ignoredAuditUsers;
    private final List<String> ignoredComplianceUsersForRead;
    private final List<String> ignoredComplianceUsersForWrite;
    private final List<String> ignoreAuditRequests;
    private final List<String> watchedReadFields;
    private final List<String> watchedWriteIndices;
    private final EnumSet<AuditCategory> disabledRestCategories;
    private final EnumSet<AuditCategory> disabledTransportCategories;
    private final Set<String> immutableIndicesPatterns;
    private final String saltAsString;
    private final String opendistrosecurityIndex;
    private final String type;
    private final String index;

    private final Map<String, Set<String>> readEnabledFields = new HashMap<>(100);
    private final LoadingCache<String, Set<String>> cache;
    private final byte[] salt16;
    private DateTimeFormatter auditLogPattern;
    private String auditLogIndex;
    private volatile boolean enabled = true;

    public AuditConfig(final boolean restAuditingEnabled,
                       final boolean transportAuditingEnabled,
                       final boolean resolveBulkRequests,
                       final boolean logRequestBody,
                       final boolean resolveIndices,
                       final boolean excludeSensitiveHeaders,
                       final boolean logDiffsForWrite,
                       final boolean logWriteMetadataOnly,
                       final boolean logReadMetadataOnly,
                       final boolean logExternalConfig,
                       final boolean logInternalConfig,
                       final List<String> ignoredAuditUsers,
                       final List<String> ignoredComplianceUsersForRead,
                       final List<String> ignoredComplianceUsersForWrite,
                       final List<String> ignoreAuditRequests,
                       final List<String> watchedReadFields,
                       final List<String> watchedWriteIndices,
                       final EnumSet<AuditCategory> disabledRestCategories,
                       final EnumSet<AuditCategory> disabledTransportCategories,
                       final Set<String> immutableIndicesPatterns,
                       final String saltAsString,
                       final String opendistrosecurityIndex,
                       final String type,
                       final String index) {
        this.restAuditingEnabled = restAuditingEnabled;
        this.transportAuditingEnabled = transportAuditingEnabled;
        this.resolveBulkRequests = resolveBulkRequests;
        this.logRequestBody = logRequestBody;
        this.resolveIndices = resolveIndices;
        this.excludeSensitiveHeaders = excludeSensitiveHeaders;
        this.logDiffsForWrite = logDiffsForWrite;
        this.logWriteMetadataOnly = logWriteMetadataOnly;
        this.logReadMetadataOnly = logReadMetadataOnly;
        this.logExternalConfig = logExternalConfig;
        this.logInternalConfig = logInternalConfig;
        this.ignoredAuditUsers = ignoredAuditUsers;
        this.ignoredComplianceUsersForRead = ignoredComplianceUsersForRead;
        this.ignoredComplianceUsersForWrite = ignoredComplianceUsersForWrite;
        this.ignoreAuditRequests = ignoreAuditRequests;
        this.watchedReadFields = watchedReadFields;
        this.watchedWriteIndices = watchedWriteIndices;
        this.disabledRestCategories = disabledRestCategories;
        this.disabledTransportCategories = disabledTransportCategories;
        this.immutableIndicesPatterns = immutableIndicesPatterns;
        this.saltAsString = saltAsString;
        this.opendistrosecurityIndex = opendistrosecurityIndex;
        this.type = type;
        this.index = index;

        final byte[] saltAsBytes = saltAsString.getBytes(StandardCharsets.UTF_8);
        if (saltAsString.equals(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT_DEFAULT)) {
            log.warn("If you plan to use field masking pls configure " + ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT + " to be a random string of 16 chars length identical on all nodes");
        }
        if (saltAsBytes.length < 16) {
            throw new ElasticsearchException(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT + " must at least contain 16 bytes");
        }
        if (saltAsBytes.length > 16) {
            log.warn(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT + " is greater than 16 bytes. Only the first 16 bytes are used for salting");
        }
        salt16 = Arrays.copyOf(saltAsBytes, 16);

        for (String watchedReadField : watchedReadFields) {
            final List<String> split = new ArrayList<>(Arrays.asList(watchedReadField.split(",")));
            if (split.isEmpty()) {
                continue;
            } else if (split.size() == 1) {
                readEnabledFields.put(split.get(0), Collections.singleton("*"));
            } else {
                Set<String> _fields = new HashSet<String>(split.subList(1, split.size()));
                readEnabledFields.put(split.get(0), _fields);
            }
        }

        if ("internal_elasticsearch".equalsIgnoreCase(type)) {
            try {
                auditLogPattern = DateTimeFormat.forPattern(index); //throws IllegalArgumentException if no pattern
            } catch (IllegalArgumentException e) {
                //no pattern
                auditLogIndex = index;
            } catch (Exception e) {
                log.error("Unable to check if auditlog index {} is part of compliance setup", index, e);
            }
        }

        log.info("PII configuration [auditLogPattern={},  auditLogIndex={}]: {}", auditLogPattern, auditLogIndex, readEnabledFields);
        cache = CacheBuilder.newBuilder()
                .maximumSize(1000)
                .build(new CacheLoader<String, Set<String>>() {
                    @Override
                    public Set<String> load(String index) throws Exception {
                        return getFieldsForIndex(index);
                    }
                });
    }

    public static AuditConfig getConfig(Settings settings) {
        boolean restAuditingEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_REST, true);
        boolean transportAuditingEnabled = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ENABLE_TRANSPORT, true);
        boolean resolveBulkRequests = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_BULK_REQUESTS, false);
        boolean logRequestBody = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_LOG_REQUEST_BODY, true);
        boolean resolveIndices = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_RESOLVE_INDICES, true);
        boolean excludeSensitiveHeaders = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_EXCLUDE_SENSITIVE_HEADERS, true);
        boolean logDiffsForWrite = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, false);
        boolean logWriteMetadataOnly = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY, false);
        boolean logReadMetadataOnly = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY, false);
        boolean logExternalConfig = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false);
        boolean logInternalConfig = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, false);

        final List<String> defaultDisabledCategories = Arrays.asList(AuditCategory.AUTHENTICATED.toString(), AuditCategory.GRANTED_PRIVILEGES.toString());

        EnumSet<AuditCategory> disabledRestCategories = AuditCategory.parse(getConfigList(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_REST_CATEGORIES,
                defaultDisabledCategories));

        EnumSet<AuditCategory> disabledTransportCategories = AuditCategory.parse(getConfigList(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DISABLED_TRANSPORT_CATEGORIES,
                defaultDisabledCategories));

        final List<String> defaultIgnoredUsers = Arrays.asList("kibanaserver");

        List<String> ignoredAuditUsers = getConfigList(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_USERS,
                defaultIgnoredUsers);

        List<String> ignoredComplianceUsersForRead = getConfigList(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS,
                defaultIgnoredUsers);

        List<String> ignoredComplianceUsersForWrite = getConfigList(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS,
                defaultIgnoredUsers);

        List<String> ignoreAuditRequests = getConfigList(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_AUDIT_IGNORE_REQUESTS,
                Collections.emptyList());

        List<String> watchedReadFields = settings.getAsList(
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS,
                Collections.emptyList(),
                false);

        List<String> watchedWriteIndices = settings.getAsList(
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES,
                Collections.emptyList());

        Set<String> immutableIndicesPatterns = new HashSet<>(
                settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_IMMUTABLE_INDICES, Collections.emptyList()));

        String saltAsString = settings.get(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT, ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT_DEFAULT);
        String opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        String type = settings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_TYPE_DEFAULT, null);
        String index = settings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ES_INDEX, "'security-auditlog-'YYYY.MM.dd");

        return new AuditConfig(restAuditingEnabled,
                transportAuditingEnabled,
                resolveBulkRequests,
                logRequestBody,
                resolveIndices,
                excludeSensitiveHeaders,
                logDiffsForWrite,
                logWriteMetadataOnly,
                logReadMetadataOnly,
                logExternalConfig,
                logInternalConfig,
                ignoredAuditUsers,
                ignoredComplianceUsersForRead,
                ignoredComplianceUsersForWrite,
                ignoreAuditRequests,
                watchedReadFields,
                watchedWriteIndices,
                disabledRestCategories,
                disabledTransportCategories,
                immutableIndicesPatterns,
                saltAsString,
                opendistrosecurityIndex,
                type,
                index);
    }

    private static List<String> getConfigList(final Settings settings,
                                              final String key,
                                              final List<String> defaultList) {
        List<String> list = new ArrayList<>(settings.getAsList(key, defaultList));
        if (list.size() == 1 && "NONE".equals(list.get(0))) {
            list.clear();
        }
        return list;
    }

    public boolean isRestAuditingEnabled() {
        return restAuditingEnabled;
    }

    public boolean isTransportAuditingEnabled() {
        return transportAuditingEnabled;
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

    public List<String> getIgnoredAuditUsers() {
        return ignoredAuditUsers;
    }

    public List<String> getIgnoredComplianceUsersForRead() {
        return ignoredComplianceUsersForRead;
    }

    public List<String> getIgnoredComplianceUsersForWrite() {
        return ignoredComplianceUsersForWrite;
    }

    public List<String> getIgnoreAuditRequests() {
        return ignoreAuditRequests;
    }

    public EnumSet<AuditCategory> getDisabledRestCategories() {
        return disabledRestCategories;
    }

    public EnumSet<AuditCategory> getDisabledTransportCategories() {
        return disabledTransportCategories;
    }

    public boolean shouldLogExternalConfig() {
        return logExternalConfig;
    }

    public byte[] getSalt16() {
        return salt16.clone();
    }

    public boolean isEnabled() {
        return this.enabled;
    }

    //cached
    private Set<String> getFieldsForIndex(String index) {
        if (index == null) {
            return Collections.emptySet();
        }

        if (auditLogIndex != null && auditLogIndex.equalsIgnoreCase(index)) {
            return Collections.emptySet();
        }

        if (auditLogPattern != null) {
            if (index.equalsIgnoreCase(getExpandedIndexName(auditLogPattern, null))) {
                return Collections.emptySet();
            }
        }

        final Set<String> tmp = new HashSet<>(100);
        for (String indexPattern : readEnabledFields.keySet()) {
            if (indexPattern != null && !indexPattern.isEmpty() && WildcardMatcher.match(indexPattern, index)) {
                tmp.addAll(readEnabledFields.get(indexPattern));
            }
        }
        return tmp;
    }

    private String getExpandedIndexName(DateTimeFormatter indexPattern, String index) {
        if (indexPattern == null) {
            return index;
        }
        return indexPattern.print(DateTime.now(DateTimeZone.UTC));
    }

    //do not check for isEnabled
    public boolean isWriteHistoryEnabledForIndex(String index) {
        if (index == null) {
            return false;
        }

        if (opendistrosecurityIndex.equals(index)) {
            return logInternalConfig;
        }

        if (auditLogIndex != null && auditLogIndex.equalsIgnoreCase(index)) {
            return false;
        }

        if (auditLogPattern != null) {
            if (index.equalsIgnoreCase(getExpandedIndexName(auditLogPattern, null))) {
                return false;
            }
        }

        return WildcardMatcher.matchAny(watchedWriteIndices, index);
    }

    //no patterns here as parameters
    //check for isEnabled
    public boolean isReadHistoryEnabledForIndex(String index) {
        if (!this.enabled) {
            return false;
        }

        if (opendistrosecurityIndex.equals(index)) {
            return logInternalConfig;
        }

        try {
            return !cache.get(index).isEmpty();
        } catch (ExecutionException e) {
            log.error(e);
            return true;
        }
    }

    //no patterns here as parameters
    //check for isEnabled
    public boolean isReadHistoryEnabledForField(String index, String field) {
        if (!this.enabled) {
            return false;
        }

        if (opendistrosecurityIndex.equals(index)) {
            return logInternalConfig;
        }

        try {
            final Set<String> fields = cache.get(index);
            if (fields.isEmpty()) {
                return false;
            }
            return WildcardMatcher.matchAny(fields, field);
        } catch (ExecutionException e) {
            log.error(e);
            return true;
        }
    }

    public boolean shouldLogDiffsForWrite() {
        return !shouldLogWriteMetadataOnly() && logDiffsForWrite;
    }

    public boolean shouldLogWriteMetadataOnly() {
        return logWriteMetadataOnly;
    }

    public boolean shouldLogReadMetadataOnly() {
        return logReadMetadataOnly;
    }

    //check for isEnabled
    public boolean isIndexImmutable(Object request, IndexResolverReplacer irr) {
        if (!this.enabled) {
            return false;
        }

        if (immutableIndicesPatterns.isEmpty()) {
            return false;
        }

        final IndexResolverReplacer.Resolved resolved = irr.resolveRequest(request);
        final Set<String> allIndices = resolved.getAllIndices();
        return WildcardMatcher.matchAny(immutableIndicesPatterns, allIndices);
    }
}
