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
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package com.amazon.opendistroforelasticsearch.security.compliance;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import com.amazon.opendistroforelasticsearch.security.auditlog.config.AuditConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.ImmutableSet;

/**
 * This class represents all configurations for compliance.
 * DLS/FLS uses this configuration for filtering and anonymizing fields.
 * Audit Logger uses this configuration to post compliance audit logs.
 */
public class ComplianceConfig {

    private static final Logger log = LogManager.getLogger(ComplianceConfig.class);
    private static final int SALT_SIZE = 16;
    private static final int CACHE_SIZE = 1000;
    private static final String INTERNAL_ELASTICSEARCH = "internal_elasticsearch";

    private final boolean logExternalConfig;
    private final boolean logInternalConfig;
    private final boolean logReadMetadataOnly;
    private final boolean logWriteMetadataOnly;
    private final boolean logDiffsForWrite;
    private final List<String> watchedWriteIndicesPatterns;
    private final Set<String> ignoredComplianceUsersForRead;
    private final Set<String> ignoredComplianceUsersForWrite;
    private final Set<String> immutableIndicesPatterns;
    private final String opendistrosecurityIndex;
    private final Map<String, Set<String>> readEnabledFields;
    private final LoadingCache<String, Set<String>> readEnabledFieldsCache;
    private final byte[] salt16;
    private final DateTimeFormatter auditLogPattern;
    private final String auditLogIndex;
    private final boolean enabled;

    private ComplianceConfig(
            final boolean complianceEnabled,
            final boolean logExternalConfig,
            final boolean logInternalConfig,
            final boolean logReadMetadataOnly,
            final List<String> watchedReadFields,
            final Set<String> ignoredComplianceUsersForRead,
            final boolean logWriteMetadataOnly,
            final boolean logDiffsForWrite,
            final List<String> watchedWriteIndicesPatterns,
            final Set<String> ignoredComplianceUsersForWrite,
            final Set<String> immutableIndicesPatterns,
            final String saltAsString,
            final String opendistrosecurityIndex,
            final String destinationType,
            final String destinationIndex) {
        this.enabled = complianceEnabled;
        this.logExternalConfig = logExternalConfig;
        this.logInternalConfig = logInternalConfig;
        this.logReadMetadataOnly = logReadMetadataOnly;
        this.logWriteMetadataOnly = logWriteMetadataOnly;
        this.logDiffsForWrite = logDiffsForWrite;
        this.watchedWriteIndicesPatterns = watchedWriteIndicesPatterns;
        this.ignoredComplianceUsersForRead = ignoredComplianceUsersForRead;
        this.ignoredComplianceUsersForWrite = ignoredComplianceUsersForWrite;
        this.immutableIndicesPatterns = immutableIndicesPatterns;
        this.opendistrosecurityIndex = opendistrosecurityIndex;

        this.salt16 = new byte[SALT_SIZE];
        if (saltAsString.equals(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT_DEFAULT)) {
            log.warn("If you plan to use field masking pls configure compliance salt {} to be a random string of 16 chars length identical on all nodes", saltAsString);
        }
        try {
            ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(saltAsString);
            byteBuffer.get(salt16);
            if (byteBuffer.remaining() > 0) {
                log.warn("Provided compliance salt {} is greater than 16 bytes. Only the first 16 bytes are used for salting", saltAsString);
            }
        } catch (BufferUnderflowException e) {
            throw new ElasticsearchException("Provided compliance salt " + saltAsString + " must at least contain 16 bytes", e);
        }

        //opendistro_security.compliance.pii_fields:
        //  - indexpattern,fieldpattern,fieldpattern,....
        this.readEnabledFields = watchedReadFields.stream()
                .map(watchedReadField -> watchedReadField.split(","))
                .filter(split -> split.length != 0 && !Strings.isNullOrEmpty(split[0]))
                .collect(Collectors.toMap(
                        split -> split[0],
                        split -> split.length == 1 ?
                                Collections.singleton("*") : Arrays.stream(split).skip(1).collect(Collectors.toSet())
                ));

        DateTimeFormatter auditLogPattern = null;
        String auditLogIndex = null;
        if (INTERNAL_ELASTICSEARCH.equalsIgnoreCase(destinationType)) {
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
                .build(new CacheLoader<String, Set<String>>() {
                    @Override
                    public Set<String> load(String index) throws Exception {
                        return getFieldsForIndex(index);
                    }
                });
    }

    public void log(Logger logger) {
        logger.info("Auditing of external configuration is {}.", logExternalConfig ? "enabled" : "disabled");
        logger.info("Auditing of internal configuration is {}.", logInternalConfig ? "enabled" : "disabled");
        logger.info("Auditing only metadata information for read request is {}.", logReadMetadataOnly ? "enabled" : "disabled");
        logger.info("Auditing will watch {} for read requests.", readEnabledFields);
        logger.info("Auditing only metadata information for write request is {}.", logWriteMetadataOnly ? "enabled" : "disabled");
        logger.info("Auditing diffs for write requests is {}.", logDiffsForWrite ? "enabled" : "disabled");
        logger.info("Auditing will watch {} for write requests.", watchedWriteIndicesPatterns);
        logger.info("{} indices are made immutable.", immutableIndicesPatterns);
        logger.info("{} is used as internal security index.", opendistrosecurityIndex);
        logger.info("Internal index used for posting audit logs is {}", auditLogIndex);
        logger.info("Compliance read operation requests auditing from {} users is disabled.", ignoredComplianceUsersForRead);
        logger.info("Compliance write operation requests auditing from {} users is disabled.", ignoredComplianceUsersForWrite);
    }

    /**
     * Create compliance configuration from Settings defined in elasticsearch.yml
     * @param settings settings
     * @return compliance configuration
     */
    public static ComplianceConfig from(Settings settings) {
        final AuditConfig.Compliance compliance = AuditConfig.from(settings).getCompliance();
        return from(compliance, settings);
    }

    /**
     * Create compliance configuration from audit
     * saltAsString - Read from settings. Not hot-reloaded. Used for anonymization of fields in FLS using consistent hash.
     * opendistrosecurityIndex - used to determine if internal index is written to or read from.
     * type - checks if log destination used is internal elasticsearch.
     * index - the index used for storing audit logs to avoid monitoring it.
     * @param configCompliance configCompliance
     * @param settings settings
     * @return ComplianceConfig
     */
    public static ComplianceConfig from(AuditConfig.Compliance configCompliance, Settings settings) {
        final String saltAsString = settings.get(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT, ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT_DEFAULT);
        final Set<String> immutableIndicesPatterns = ImmutableSet.copyOf(settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_IMMUTABLE_INDICES, Collections.emptyList()));
        final String opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        final String type = settings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_TYPE_DEFAULT, null);
        final String index = settings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ES_INDEX, "'security-auditlog-'YYYY.MM.dd");

        return new ComplianceConfig(
                configCompliance.isComplianceEnabled(),
                configCompliance.isExternalConfigEnabled(),
                configCompliance.isInternalConfigEnabled(),
                configCompliance.isReadMetadataOnly(),
                configCompliance.getReadWatchedFields(),
                configCompliance.getReadIgnoreUsers(),
                configCompliance.isWriteMetadataOnly(),
                configCompliance.isWriteLogDiffs(),
                configCompliance.getWriteWatchedIndices(),
                configCompliance.getWriteIgnoreUsers(),
                immutableIndicesPatterns,
                saltAsString,
                opendistrosecurityIndex,
                type,
                index);
    }

    /**
     * Checks if config defined in elasticsearch config directory must be logged
     * @return true/false
     */
    public boolean shouldLogExternalConfig() {
        return logExternalConfig;
    }

    /**
     * Checks if internal config must be logged
     * @return true/false
     */
    public boolean shouldLogInternalConfig() {
        return logInternalConfig;
    }

    /**
     * Checks if compliance is enabled
     * @return true/false
     */
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
    public boolean shouldLogWriteMetadataOnly() {
        return logWriteMetadataOnly;
    }

    /**
     * Checks if only metadata for read requests should be logged
     * @return true/false
     */
    public boolean shouldLogReadMetadataOnly() {
        return logReadMetadataOnly;
    }

    /**
     * Get set of immutable index pattern
     * @return set of index patterns
     */
    public Set<String> getImmutableIndicesPatterns() {
        return immutableIndicesPatterns;
    }

    /**
     * Get the salt in bytes for filed anonymization
     * @return salt in bytes
     */
    public byte[] getSalt16() {
        return Arrays.copyOf(salt16, salt16.length);
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
                .filter(entry -> WildcardMatcher.match(entry.getKey(), index))
                .flatMap(entry -> entry.getValue().stream())
                .collect(Collectors.toSet());
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
        if (index == null) {
            return false;
        }
        // if open distro index (internal index) check if internal config logging is enabled
        if (opendistrosecurityIndex.equals(index)) {
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
        return WildcardMatcher.matchAny(watchedWriteIndicesPatterns, index);
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
        // if open distro index (internal index) check if internal config logging is enabled
        if (opendistrosecurityIndex.equals(index)) {
            return logInternalConfig;
        }
        try {
            return !readEnabledFieldsCache.get(index).isEmpty();
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
        // if open distro index (internal index) check if internal config logging is enabled
        if (opendistrosecurityIndex.equals(index)) {
            return logInternalConfig;
        }
        Set<String> fields;
        try {
            fields = readEnabledFieldsCache.get(index);
            if (fields.isEmpty()) {
                return false;
            }
        } catch (ExecutionException e) {
            log.warn("Failed to get index {} fields enabled for read from cache. Bypassing cache.", index, e);
            fields = getFieldsForIndex(index);
        }
        return WildcardMatcher.matchAny(fields, field);
    }
}
