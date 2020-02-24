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

import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer;
import com.amazon.opendistroforelasticsearch.security.resolver.IndexResolverReplacer.Resolved;
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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;

public class ComplianceConfig {

    private final Logger log = LogManager.getLogger(getClass());

    private final List<String> watchedReadFields;
    private final List<String> watchedWriteIndices;
    private final boolean logDiffsForWrite;
    private final boolean logWriteMetadataOnly;
    private final boolean logReadMetadataOnly;
    private final boolean logExternalConfig;
    private final boolean logInternalConfig;
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
    private volatile boolean externalConfigLogged = false;

    public ComplianceConfig(final List<String> watchedReadFields,
                            final List<String> watchedWriteIndices,
                            final boolean logDiffsForWrite,
                            final boolean logWriteMetadataOnly,
                            final boolean logReadMetadataOnly,
                            final boolean logExternalConfig,
                            final boolean logInternalConfig,
                            final Set<String> immutableIndicesPatterns,
                            final String saltAsString,
                            final String opendistrosecurityIndex,
                            final String type,
                            final String index) {
        this.watchedReadFields = watchedReadFields;
        this.watchedWriteIndices = watchedWriteIndices;
        this.logDiffsForWrite = logDiffsForWrite;
        this.logWriteMetadataOnly = logWriteMetadataOnly;
        this.logReadMetadataOnly = logReadMetadataOnly;
        this.logExternalConfig = logExternalConfig;
        this.logInternalConfig = logInternalConfig;
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
                        return getFieldsForIndex0(index);
                    }
                });
    }

    public static ComplianceConfig getConfig(final Settings settings) {
        List<String> watchedReadFields = settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_WATCHED_FIELDS,
                Collections.emptyList(), false);
        List<String> watchedWriteIndices = settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_WATCHED_INDICES, Collections.emptyList());
        boolean logDiffsForWrite = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_LOG_DIFFS, false);
        boolean logWriteMetadataOnly = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_WRITE_METADATA_ONLY, false);
        boolean logReadMetadataOnly = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_READ_METADATA_ONLY, false);
        boolean logExternalConfig = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_EXTERNAL_CONFIG_ENABLED, false);
        boolean logInternalConfig = settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_HISTORY_INTERNAL_CONFIG_ENABLED, false);
        Set<String> immutableIndicesPatterns = new HashSet<>(settings.getAsList(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_IMMUTABLE_INDICES, Collections.emptyList()));
        String saltAsString = settings.get(ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT, ConfigConstants.OPENDISTRO_SECURITY_COMPLIANCE_SALT_DEFAULT);
        String opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME, ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);
        String type = settings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_TYPE_DEFAULT, null);
        String index = settings.get(ConfigConstants.OPENDISTRO_SECURITY_AUDIT_CONFIG_DEFAULT_PREFIX + ConfigConstants.OPENDISTRO_SECURITY_AUDIT_ES_INDEX, "'security-auditlog-'YYYY.MM.dd");

        return new ComplianceConfig(watchedReadFields, watchedWriteIndices, logDiffsForWrite, logWriteMetadataOnly, logReadMetadataOnly, logExternalConfig, logInternalConfig, immutableIndicesPatterns, saltAsString, opendistrosecurityIndex, type, index);
    }

    public boolean isLogExternalConfig() {
        return logExternalConfig;
    }

    public boolean isExternalConfigLogged() {
        return externalConfigLogged;
    }

    public void setExternalConfigLogged(boolean externalConfigLogged) {
        this.externalConfigLogged = externalConfigLogged;
    }

    public boolean isEnabled() {
        return this.enabled;
    }

    //cached
    @SuppressWarnings("unchecked")
    private Set<String> getFieldsForIndex0(String index) {

        if (index == null) {
            return Collections.EMPTY_SET;
        }

        if (auditLogIndex != null && auditLogIndex.equalsIgnoreCase(index)) {
            return Collections.EMPTY_SET;
        }

        if (auditLogPattern != null) {
            if (index.equalsIgnoreCase(getExpandedIndexName(auditLogPattern, null))) {
                return Collections.EMPTY_SET;
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
    public boolean writeHistoryEnabledForIndex(String index) {

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
    public boolean readHistoryEnabledForIndex(String index) {

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
    public boolean readHistoryEnabledForField(String index, String field) {

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

    public boolean logDiffsForWrite() {
        return !logWriteMetadataOnly() && logDiffsForWrite;
    }

    public boolean logWriteMetadataOnly() {
        return logWriteMetadataOnly;
    }

    public boolean logReadMetadataOnly() {
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

        final Resolved resolved = irr.resolveRequest(request);
        final Set<String> allIndices = resolved.getAllIndices();


        return WildcardMatcher.matchAny(immutableIndicesPatterns, allIndices);
    }

    public byte[] getSalt16() {
        return salt16.clone();
    }
}
