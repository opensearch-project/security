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

import java.util.Map;
import java.util.TreeMap;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.configuration.SecurityConfigVersionDocument.HistoricSecurityConfig;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;

import com.flipkart.zjsonpatch.JsonDiff;

/**
 * Utility class to compute differences between two versions of security configurations
 *
 * @opensearch.experimental
 */

public class SecurityConfigDiffCalculator {
    private static final Logger LOGGER = LogManager.getLogger(SecurityConfigDiffCalculator.class);

    private static final ObjectMapper objectMapper = DefaultObjectMapper.objectMapper;

    public static boolean hasSecurityConfigChanged(
        Map<String, HistoricSecurityConfig<?>> oldConfig,
        Map<String, HistoricSecurityConfig<?>> newConfig
    ) {
        try {
            if (oldConfig == null || oldConfig.isEmpty()) {
                LOGGER.info("Old configuration is empty. Treating as a new configuration.");
                return true;
            }

            JsonNode oldNode = buildConfigDataNode(oldConfig);
            JsonNode newNode = buildConfigDataNode(newConfig);

            JsonNode diff = JsonDiff.asJson(oldNode, newNode);

            if (diff.isEmpty()) {
                LOGGER.info("No changes detected in security configuration.");
                return false;
            } else {
                LOGGER.info("Detected changes in security configuration: {}", diff.toString());
                return true;
            }
        } catch (Exception e) {
            LOGGER.error("Error while comparing security configurations", e);
            return false;
        }
    }

    private static JsonNode buildConfigDataNode(Map<String, HistoricSecurityConfig<?>> configMap) {
        Map<String, Map<String, ?>> structuredConfigData = new TreeMap<>();

        if (configMap == null) {
            return objectMapper.createObjectNode();
        }

        for (Map.Entry<String, HistoricSecurityConfig<?>> configEntry : configMap.entrySet()) {
            String type = configEntry.getKey();
            HistoricSecurityConfig<?> securityConfig = configEntry.getValue();

            if (securityConfig == null) {
                continue;
            }

            Map<String, ?> configData = securityConfig.getConfigData();
            if (configData == null) {
                continue;
            }

            Map<String, Map<String, ?>> extractedCEntriesPerType = new TreeMap<>();

            for (Map.Entry<String, ?> configDataEntry : configData.entrySet()) {
                String configName = configDataEntry.getKey();
                Object dynamicConfig = configDataEntry.getValue();

                if (dynamicConfig instanceof SecurityDynamicConfiguration<?>) {
                    SecurityDynamicConfiguration<?> dynConf = (SecurityDynamicConfiguration<?>) dynamicConfig;
                    if (dynConf.getCEntries() != null) {
                        extractedCEntriesPerType.put(configName, new TreeMap<>(dynConf.getCEntries()));
                    }
                } else {
                    try {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> serializedMap = objectMapper.convertValue(dynamicConfig, Map.class);
                        extractedCEntriesPerType.put(configName, new TreeMap<>(serializedMap));
                    } catch (Exception e) {
                        LOGGER.error(
                            "Failed to serialize unexpected config type for {}: {}",
                            configName,
                            dynamicConfig.getClass().getName(),
                            e
                        );
                    }
                }
            }

            structuredConfigData.put(type, extractedCEntriesPerType);
        }

        return objectMapper.valueToTree(structuredConfigData);
    }
}
