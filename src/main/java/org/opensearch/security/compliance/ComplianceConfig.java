/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright OpenSearch Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package org.opensearch.security.compliance;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.config.AuditConfig;
import com.fasterxml.jackson.annotation.JacksonInject;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.google.common.annotations.VisibleForTesting;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.Strings;
import org.opensearch.common.settings.Settings;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

import static org.opensearch.security.DefaultObjectMapper.getOrDefault;

/**
 * This class represents all configurations for compliance.
 * DLS/FLS uses this configuration for filtering and anonymizing fields.
 * Audit Logger uses this configuration to post compliance audit logs.
 */
@JsonAutoDetect(getterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ComplianceConfig {

    private static final Logger log = LogManager.getLogger(ComplianceConfig.class);
    public static final ComplianceConfig DEFAULT = ComplianceConfig.from(Settings.EMPTY);
    private static final int CACHE_SIZE = 1000;
    private static final String INTERNAL_OPENSEARCH = "internal_opensearch";
    public static Set<String> FIELDS = DefaultObjectMapper.getFields(ComplianceConfig.class);

    private final boolean logExternalConfig;
    private final boolean logInternalConfig;
    private final boolean logReadMetadataOnly;
    private final boolean logWriteMetadataOnly;
    @JsonProperty("write_log_diffs")
    private final boolean logDiffsForWrite;
    @JsonProperty("read_watched_fields")
    private final Map<String, List<String>> watchedReadFields;
    @JsonProperty("read_ignore_users")
    private final Set<String> ignoredComplianceUsersForRead;
    @JsonProperty("write_watched_indices")
    private final List<String> watchedWriteIndicesPatterns;
    @JsonProperty("write_ignore_users")
    private final Set<String> ignoredComplianceUsersForWrite;

    private final WildcardMatcher watchedWriteIndicesMatcher;
    private final WildcardMatcher ignoredComplianceUsersForReadMatcher;
    private final WildcardMatcher ignoredComplianceUsersForWriteMatcher;
    private final String securityIndex;

    private final Map<WildcardMatcher, Set<String>> readEnabledFields;
    private final LoadingCache<String, WildcardMatcher> readEnabledFieldsCache;
    private final DateTimeFormatter auditLogPattern;
    private final String auditLogIndex;
    private final boolean enabled;

    private ComplianceConfig(
            final boolean enabled,
            final boolean logExternalConfig,
            final boolean logInternalConfig,
            final boolean logReadMetadataOnly,
            final Map<String, List<String>> watchedReadFields,
            final Set<String> ignoredComplianceUsersForRead,
            final boolean logWriteMetadataOnly,
            final boolean logDiffsForWrite,
            final List<String> watchedWriteIndicesPatterns,
            final Set<String> ignoredComplianceUsersForWrite,
            final String securityIndex,
            final String destinationType,
            final String destinationIndex) {
        this.enabled = enabled;
        this.logExternalConfig = logExternalConfig;
        this.logInternalConfig = logInternalConfig;
        this.logReadMetadataOnly = logReadMetadataOnly;
        this.logWriteMetadataOnly = logWriteMetadataOnly;
        this.logDiffsForWrite = logDiffsForWrite;
        this.watchedWriteIndicesMatcher = WildcardMatcher.from(watchedWriteIndicesPatterns);
        this.ignoredComplianceUsersForReadMatcher = WildcardMatcher.from(ignoredComplianceUsersForRead);
        this.ignoredComplianceUsersForWriteMatcher = WildcardMatcher.from(ignoredComplianceUsersForWrite);
        this.securityIndex = securityIndex;
        this.watchedReadFields = watchedReadFields;
        this.ignoredComplianceUsersForRead = ignoredComplianceUsersForRead;
        this.watchedWriteIndicesPatterns = watchedWriteIndicesPatterns;
        this.ignoredComplianceUsersForWrite = ignoredComplianceUsersForWrite;

        this.readEnabledFields = watchedReadFields.entrySet().stream()
                .filter(entry -> !Strings.isNullOrEmpty(entry.getKey()))
                .collect(
                    ImmutableMap.toImmutableMap(
                        entry -> WildcardMatcher.from(entry.getKey()),
                        entry -> ImmutableSet.copyOf(entry.getValue())
                    )
                );

        DateTimeFormatter auditLogPattern = null;
        String auditLogIndex = null;
        if (INTERNAL_OPENSEARCH.equalsIgnoreCase(destinationType)) {
            try {
                auditLogPattern = DateTimeFormat.forPattern(destinationIndex); //throws IllegalArgumentException if no pattern
            } catch (IllegalArgumentException e) {
                //no pattern
                auditLogIndex = destinationIndex;
            } catch (Exception e) {
                log.error("Unable to check if auditlog index {} is part of compliance setup", destinationIndex, e);
            }
        }
        this.auditLogPattern = auditLogPattern;
        this.auditLogIndex = auditLogIndex;

        this.readEnabledFieldsCache = CacheBuilder.newBuilder()
                .maximumSize(CACHE_SIZE)
                .build(new CacheLoader<String, WildcardMatcher>() {
                    @Override
                    public WildcardMatcher load(String index) throws Exception {
                        return WildcardMatcher.from(getFieldsForIndex(index));
                    }
                });
    }

    @VisibleForTesting
    public ComplianceConfig(
            final boolean enabled,
            final boolean logExternalConfig,
            final boolean logInternalConfig,
            final boolean logReadMetadataOnly,
            final Map<String, List<String>> watchedReadFields,
            final Set<String> ignoredComplianceUsersForRead,
            final boolean logWriteMetadataOnly,
            final boolean logDiffsForWrite,
            final List<String> watchedWriteIndicesPatterns,
            final Set<String> ignoredComplianceUsersForWrite,
            Settings settings) {
        this(
                enabled,
                logExternalConfig,
                logInternalConfig,
                logReadMetadataOnly,
                watchedReadFields,
                ignoredComplianceUsersForRead,
                logWriteMetadataOnly,
                logDiffsForWrite,
                watchedWriteIndicesPatterns,
                ignoredComplianceUsersForWrite,
                settings.get(ConfigConstants.SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX),
                settings.get(ConfigConstants.SECURITY_AUDIT_TYPE_DEFAULT, null),
                settings.get(ConfigConstants.SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.SECURITY_AUDIT_OPENSEARCH_INDEX, "'security-auditlog-'YYYY.MM.dd")
        );
    }

    public void log(Logger logger) {
        logger.info("Auditing of external configuration is {}.", logExternalConfig ? "enabled" : "disabled");
        logger.info("Auditing of internal configuration is {}.", logInternalConfig ? "enabled" : "disabled");
        logger.info("Auditing only metadata information for read request is {}.", logReadMetadataOnly ? "enabled" : "disabled");
        logger.info("Auditing will watch {} for read requests.", readEnabledFields);
        logger.info("Auditing read operation requests from {} users is disabled.", ignoredComplianceUsersForReadMatcher);
        logger.info("Auditing only metadata information for write request is {}.", logWriteMetadataOnly ? "enabled" : "disabled");
        logger.info("Auditing diffs for write requests is {}.", logDiffsForWrite ? "enabled" : "disabled");
        logger.info("Auditing write operation requests from {} users is disabled.", ignoredComplianceUsersForWriteMatcher);
        logger.info("Auditing will watch {} for write requests.", watchedWriteIndicesMatcher);
        logger.info("{} is used as internal security index.", securityIndex);
        logger.info("Internal index used for posting audit logs is {}", auditLogIndex);
    }

    @VisibleForTesting
    @JsonCreator
    public static ComplianceConfig from(Map<String, Object> properties, @JacksonInject Settings settings) throws JsonProcessingException {
        if (!FIELDS.containsAll(properties.keySet())) {
            throw new UnrecognizedPropertyException(null, "Invalid property present in the input data for compliance config", null, ComplianceConfig.class, null, null);
        }

        final boolean enabled = getOrDefault(properties, "enabled", true);
        final boolean logExternalConfig = getOrDefault(properties, "external_config", false);
        final boolean logInternalConfig = getOrDefault(properties, "internal_config", false);
        final boolean logReadMetadataOnly = getOrDefault(properties, "read_metadata_only", false);
        final Map<String, List<String>> watchedReadFields = getOrDefault(properties, "read_watched_fields", Collections.emptyMap());
        final Set<String> ignoredComplianceUsersForRead = ImmutableSet.copyOf(getOrDefault(properties, "read_ignore_users", AuditConfig.DEFAULT_IGNORED_USERS));
        final boolean logWriteMetadataOnly = getOrDefault(properties, "write_metadata_only", false);
        final boolean logDiffsForWrite = getOrDefault(properties, "write_log_diffs", false);
        final List<String> watchedWriteIndicesPatterns = getOrDefault(properties, "write_watched_indices", Collections.emptyList());
        final Set<String> ignoredComplianceUsersForWrite = ImmutableSet.copyOf(getOrDefault(properties, "write_ignore_users", AuditConfig.DEFAULT_IGNORED_USERS));

        return new ComplianceConfig(
                enabled,
                logExternalConfig,
                logInternalConfig,
                logReadMetadataOnly,
                watchedReadFields,
                ignoredComplianceUsersForRead,
                logWriteMetadataOnly,
                logDiffsForWrite,
                watchedWriteIndicesPatterns,
                ignoredComplianceUsersForWrite,
                settings
        );
    }

    /**
     * Create compliance configuration from Settings defined in opensearch.yml
     * @param settings settings
     * @return compliance configuration
     */
    public static ComplianceConfig from(Settings settings) {
        final boolean logExternalConfig = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false);
        final boolean logInternalConfig = settings.getAsBoolean(ConfigConstants.SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, false);
        final boolean logReadMetadataOnly = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY, false);
        final boolean logWriteMetadataOnly = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY, false);
        final boolean logDiffsForWrite = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, false);
        final List<String> watchedReadFields = settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS,
                Collections.emptyList(), false);
        //plugins.security.compliance.pii_fields:
        //  - indexpattern,fieldpattern,fieldpattern,....
        final Map<String, List<String>> readEnabledFields = watchedReadFields.stream()
                .map(watchedReadField -> watchedReadField.split(","))
                .filter(split -> split.length != 0 && !Strings.isNullOrEmpty(split[0]))
                .collect(ImmutableMap.toImmutableMap(
                        split -> split[0],
                        split -> split.length == 1 ?
                                ImmutableList.of("*") : Arrays.stream(split).skip(1).collect(ImmutableList.toImmutableList())
                ));
        final List<String> watchedWriteIndices = settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, Collections.emptyList());
        final Set<String> ignoredComplianceUsersForRead = ConfigConstants.getSettingAsSet(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_IGNORE_USERS,
                AuditConfig.DEFAULT_IGNORED_USERS,
                false);
        final Set<String> ignoredComplianceUsersForWrite = ConfigConstants.getSettingAsSet(
                settings,
                ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_IGNORE_USERS,
                AuditConfig.DEFAULT_IGNORED_USERS,
                false);

        return new ComplianceConfig(
                true,
                logExternalConfig,
                logInternalConfig,
                logReadMetadataOnly,
                readEnabledFields,
                ignoredComplianceUsersForRead,
                logWriteMetadataOnly,
                logDiffsForWrite,
                watchedWriteIndices,
                ignoredComplianceUsersForWrite,
                settings);
    }

    /**
     * Checks if config defined in OpenSearch config directory must be logged
     * @return true/false
     */
    @JsonProperty("external_config")
    public boolean shouldLogExternalConfig() {
        return logExternalConfig;
    }

    /**
     * Checks if internal config must be logged
     * @return true/false
     */
    @JsonProperty("internal_config")
    public boolean shouldLogInternalConfig() {
        return logInternalConfig;
    }

    /**
     * Checks if compliance is enabled
     * @return true/false
     */
    @JsonProperty
    public boolean isEnabled() {
        return this.enabled;
    }

    /**
     * Checks if logs diffs must be recorded for write requests
     * Log metadata only for write requests must be disabled
     * @return true/false
     */
    public boolean shouldLogDiffsForWrite() {
        return !shouldLogWriteMetadataOnly() && logDiffsForWrite;
    }

    /**
     * Checks if only metadata for write requests should be logged
     * @return true/false
     */
    @JsonProperty("write_metadata_only")
    public boolean shouldLogWriteMetadataOnly() {
        return logWriteMetadataOnly;
    }

    /**
     * Checks if only metadata for read requests should be logged
     * @return true/false
     */
    @JsonProperty("read_metadata_only")
    public boolean shouldLogReadMetadataOnly() {
        return logReadMetadataOnly;
    }

    @VisibleForTesting
    public WildcardMatcher getIgnoredComplianceUsersForReadMatcher() {
        return ignoredComplianceUsersForReadMatcher;
    }

    /**
     * Check if user is excluded from compliance read audit
     * @param user
     * @return true if user is excluded from compliance read audit
     */
    public boolean isComplianceReadAuditDisabled(String user) {
        return ignoredComplianceUsersForReadMatcher.test(user);
    }

    @VisibleForTesting
    public WildcardMatcher getIgnoredComplianceUsersForWriteMatcher() {
        return ignoredComplianceUsersForWriteMatcher;
    }

    /**
     * Check if user is excluded from compliance write audit
     * @param user
     * @return true if user is excluded from compliance write audit
     */
    public boolean isComplianceWriteAuditDisabled(String user) {
        return ignoredComplianceUsersForWriteMatcher.test(user);
    }

    @VisibleForTesting
    public Map<WildcardMatcher, Set<String>> getReadEnabledFields() {
        return readEnabledFields;
    }

    @VisibleForTesting
    public WildcardMatcher getWatchedWriteIndicesMatcher() {
        return watchedWriteIndicesMatcher;
    }

    @VisibleForTesting
    public String getSecurityIndex() {
        return securityIndex;
    }

    @VisibleForTesting
    public String getAuditLogIndex() {
        return auditLogIndex;
    }

    /**
     * This function is used for caching the fields
     * @param index index to check for fields
     * @return set of fields which is used by cache
     */
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

        return readEnabledFields.entrySet().stream()
                .filter(entry -> entry.getKey().test(index))
                .flatMap(entry -> entry.getValue().stream())
                .collect(ImmutableSet.toImmutableSet());
    }

    /**
     * Get the index name with date pattern for rolling indexes
     * @param indexPattern index pattern
     * @param index index
     * @return index name
     */
    private String getExpandedIndexName(DateTimeFormatter indexPattern, String index) {
        if (indexPattern == null) {
            return index;
        }
        return indexPattern.print(DateTime.now(DateTimeZone.UTC));
    }

    /**
     * Check if write history is enabled for the index.
     * Does not check for compliance here.
     * @param index index
     * @return true/false
     */
    public boolean writeHistoryEnabledForIndex(String index) {
        if (index == null || !isEnabled()) {
            return false;
        }
        // if security index (internal index) check if internal config logging is enabled
        if (securityIndex.equals(index)) {
            return logInternalConfig;
        }
        // if the index is used for audit logging, return false
        if (auditLogIndex != null && auditLogIndex.equalsIgnoreCase(index)) {
            return false;
        }
        // if the index is used for audit logging (rolling index name), return false
        if (auditLogPattern != null) {
            if (index.equalsIgnoreCase(getExpandedIndexName(auditLogPattern, null))) {
                return false;
            }
        }

        return watchedWriteIndicesMatcher.test(index);
    }

    /**
     * Check if read compliance history is enabled for given index
     * Checks if compliance is enabled
     * @param index index
     * @return true/false
     */
    public boolean readHistoryEnabledForIndex(String index) {
        if (!this.isEnabled()) {
            return false;
        }
        // if security index (internal index) check if internal config logging is enabled
        if (securityIndex.equals(index)) {
            return logInternalConfig;
        }
        try {
            return readEnabledFieldsCache.get(index) != WildcardMatcher.NONE;
        } catch (ExecutionException e) {
            log.warn("Failed to get index {} fields enabled for read from cache. Bypassing cache.", index, e);
            return getFieldsForIndex(index).isEmpty();
        }
    }

    /**
     * Check if read compliance history is enabled for given index
     * Checks if compliance is enabled
     * @param index index
     * @return true/false
     */
    public boolean readHistoryEnabledForField(String index, String field) {
        if (!this.isEnabled()) {
            return false;
        }
        // if security index (internal index) check if internal config logging is enabled
        if (securityIndex.equals(index)) {
            return logInternalConfig;
        }
        WildcardMatcher matcher;
        try {
            matcher = readEnabledFieldsCache.get(index);
        } catch (ExecutionException e) {
            log.warn("Failed to get index {} fields enabled for read from cache. Bypassing cache.", index, e);
            matcher = WildcardMatcher.from(getFieldsForIndex(index));
        }
        return matcher.test(field);
    }
}
