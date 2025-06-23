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

package org.opensearch.security.configuration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;

/**
 * Represents the document structure for the .opensearch_security_config_versions system index
 *
 * @opensearch.experimental
 */

public class SecurityConfigVersionDocument {

    private long seqNo = -1;
    private long primaryTerm = -1;

    private final List<Version<?>> versions;

    @JsonCreator
    public SecurityConfigVersionDocument(@JsonProperty("versions") List<Version<?>> versions) {
        this.versions = (versions != null) ? versions : new ArrayList<>();
    }

    // No-arg constructor
    public SecurityConfigVersionDocument() {
        this.versions = new ArrayList<>();
    }

    @JsonProperty("versions")
    public List<Version<?>> getVersions() {
        return versions;
    }

    public void addVersion(Version<?> version) {
        versions.add(version);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> docMap = new HashMap<>();
        List<Map<String, Object>> versionsList = new ArrayList<>();
        for (Version<?> v : versions) {
            versionsList.add(v.toMap());
        }
        docMap.put("versions", versionsList);
        return docMap;
    }

    public long getSeqNo() {
        return seqNo;
    }

    public void setSeqNo(long seqNo) {
        this.seqNo = seqNo;
    }

    public long getPrimaryTerm() {
        return primaryTerm;
    }

    public void setPrimaryTerm(long primaryTerm) {
        this.primaryTerm = primaryTerm;
    }

    public static class Version<T> {
        private final String version_id;
        private final String timestamp;
        private final Map<String, HistoricSecurityConfig<?>> security_configs;

        private final String modified_by;

        @JsonCreator
        public Version(
            @JsonProperty("version_id") String version_id,
            @JsonProperty("timestamp") String timestamp,
            @JsonProperty("security_configs") Map<String, HistoricSecurityConfig<?>> security_configs,
            @JsonProperty("modified_by") String modified_by
        ) {
            this.version_id = version_id;
            this.timestamp = timestamp;
            this.security_configs = (security_configs != null) ? security_configs : new HashMap<>();
            this.modified_by = modified_by;
        }

        @JsonProperty("version_id")
        public String getVersion_id() {
            return version_id;
        }

        @JsonProperty("timestamp")
        public String getTimestamp() {
            return timestamp;
        }

        @JsonProperty("security_configs")
        public Map<String, HistoricSecurityConfig<?>> getSecurity_configs() {
            return security_configs;
        }

        @JsonProperty("modified_by")
        public String getModified_by() {
            return modified_by;
        }

        public void addSecurityConfig(String type, HistoricSecurityConfig<?> config) {
            security_configs.put(type, config);
        }

        public Map<String, Object> toMap() {
            Map<String, Object> versionMap = new HashMap<>();
            versionMap.put("version_id", version_id);
            versionMap.put("timestamp", timestamp);
            versionMap.put("modified_by", modified_by);
            Map<String, Object> scsMap = new HashMap<>();
            for (Entry<String, HistoricSecurityConfig<?>> entry : security_configs.entrySet()) {
                scsMap.put(entry.getKey(), entry.getValue().toMap());
            }
            versionMap.put("security_configs", scsMap);
            return versionMap;
        }
    }

    /**
     * configData is map of fields in the ConfigTypes and SecurityDynamicConfiguration
     */
    public static class HistoricSecurityConfig<T> {
        private final String lastUpdated;
        private final Map<String, SecurityDynamicConfiguration<T>> configData;

        @JsonCreator
        public HistoricSecurityConfig(
            @JsonProperty("lastUpdated") String lastUpdated,
            @JsonProperty("configData") Map<String, SecurityDynamicConfiguration<T>> configData
        ) {
            this.lastUpdated = lastUpdated;
            this.configData = (configData != null) ? configData : new HashMap<>();
        }

        @JsonProperty("lastUpdated")
        public String getLastUpdated() {
            return lastUpdated;
        }

        @JsonProperty("configData")
        public Map<String, SecurityDynamicConfiguration<T>> getConfigData() {
            return configData;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> scMap = new HashMap<>();
            scMap.put("lastUpdated", lastUpdated);
            scMap.put("configData", configData);
            return scMap;
        }
    }
}
