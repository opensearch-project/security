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

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.WildcardMatcher;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.ImmutableSet;
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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;

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
    private final List<String> watchedWriteIndices;
    private final Set<String> immutableIndicesPatterns;
    private final String opendistrosecurityIndex;

    private final Map<String, Set<String>> readEnabledFields = new HashMap<>(100);
    private final LoadingCache<String, Set<String>> cache;
    private final byte[] salt16;
    private final DateTimeFormatter auditLogPattern;
    private final String auditLogIndex;
    private volatile boolean enabled = true;

    private ComplianceConfig(
            final boolean logExternalConfig,
            final boolean logInternalConfig,
            final boolean logReadMetadataOnly,
            final boolean logWriteMetadataOnly,
            final boolean logDiffsForWrite,
            final List<String> watchedReadFields,
            final List<String> watchedWriteIndices,
            final Set<String> immutableIndicesPatterns,
            final String saltAsString,
            final String opendistrosecurityIndex,
            final String destinationType,
            final String destinationIndex) {
        this.logExternalConfig = logExternalConfig;
        this.logInternalConfig = logInternalConfig;
        this.logReadMetadataOnly = logReadMetadataOnly;
        this.logWriteMetadataOnly = logWriteMetadataOnly;
        this.logDiffsForWrite = logDiffsForWrite;
        this.watchedWriteIndices = watchedWriteIndices;
        this.immutableIndicesPatterns = immutableIndicesPatterns;
        this.opendistrosecurityIndex = opendistrosecurityIndex;

        final byte[] saltAsBytes = saltAsString.getBytes(StandardCharsets.UTF_8);
        if (saltAsString.equals(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT_DEFAULT)) {
            log.warn("If you plan to use field masking pls configure compliance salt {} to be a random string of 16 chars length identical on all nodes", saltAsString);
        }
        if (saltAsBytes.length < SALT_SIZE) {
            throw new ElasticsearchException("Provided compliance salt " + saltAsString + " must at least contain 16 bytes");
        }
        if (saltAsBytes.length > SALT_SIZE) {
            log.warn("Provided compliance salt {} is greater than 16 bytes. Only the first 16 bytes are used for salting", saltAsString);
        }
        this.salt16 = Arrays.copyOf(saltAsBytes, SALT_SIZE);

        //opendistro_security.compliance.pii_fields:
        //  - indexpattern,fieldpattern,fieldpattern,....
        for (String watchedReadField : watchedReadFields) {
            final List<String> split = new ArrayList<>(Arrays.asList(watchedReadField.split(",")));
            if (split.isEmpty()) {
                continue;
            } else if (split.size() == 1) {
                this.readEnabledFields.put(split.get(0), Collections.singleton("*"));
            } else {
                Set<String> _fields = new HashSet<String>(split.subList(1, split.size()));
                this.readEnabledFields.put(split.get(0), _fields);
            }
        }

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

        this.cache = CacheBuilder.newBuilder()
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
        logger.info("Auditing will watch {} for write requests.", watchedWriteIndices);
        logger.info("{} indices are made immutable.", immutableIndicesPatterns);
        logger.info("{} is used as internal security index.", opendistrosecurityIndex);
        logger.info("Internal index used for posting audit logs is {}", auditLogIndex);
    }

    /**
     * Create compliance configuration from Settings defined in elasticsearch.yml
     * @param settings settings
     * @return compliance configuration
     */
    public static ComplianceConfig from(Settings settings) {
        final boolean logExternalConfig = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false);
        final boolean logInternalConfig = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, false);
        final boolean logReadMetadataOnly = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY, false);
        final boolean logWriteMetadataOnly = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY, false);
        final boolean logDiffsForWrite = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, false);
        final List<String> watchedReadFields = settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS,
                Collections.emptyList(), false);
        final List<String> watchedWriteIndices = settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, Collections.emptyList());
        final Set<String> immutableIndicesPatterns = ImmutableSet.copyOf(settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_IMMUTABLE_INDICES, Collections.emptyList()));
        final String saltAsString = settings.get(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT, ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT_DEFAULT);
        final String opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        final String type = settings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_TYPE_DEFAULT, null);
        final String index = settings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ES_INDEX, "'security-auditlog-'YYYY.MM.dd");

        return new ComplianceConfig(
                logExternalConfig,
                logInternalConfig,
                logReadMetadataOnly,
                logWriteMetadataOnly,
                logDiffsForWrite,
                watchedReadFields,
                watchedWriteIndices,
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
        return salt16.clone();
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

        final Set<String> tmp = new HashSet<String>(100);
        for (String indexPattern : readEnabledFields.keySet()) {
            if (indexPattern != null && !indexPattern.isEmpty() && WildcardMatcher.match(indexPattern, index)) {
                tmp.addAll(readEnabledFields.get(indexPattern));
            }
        }
        return tmp;
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
        return WildcardMatcher.matchAny(watchedWriteIndices, index);
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
            return !cache.get(index).isEmpty();
        } catch (ExecutionException e) {
            log.error(e);
            return true;
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
}
