/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.resources;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;

import org.yaml.snakeyaml.Yaml;

// CS-SUPPRESS-SINGLE: RegexpSingleline get Resource Sharing Extensions
/**
 * Helper class to load `resource-action-groups.yml` file for all resource sharing extensions.
 */
public class ResourceActionGroupsHelper {
    public static final Logger log = LogManager.getLogger(ResourceActionGroupsHelper.class);

    /**
     * Loads action-groups config from the {@code resource-action-groups.yml} file from each resource sharing extension
     * @param resourcePluginInfo will store the loaded action-groups config
     *
     * Sample yml file:
     *  resource_types:
     *      sample-resource:
     *          sample_read_only:
     *              allowed_actions:
     *                  - "cluster:admin/sample-resource-plugin/get"
     */
    @SuppressWarnings("unchecked")
    public static void loadActionGroupsConfig(ResourcePluginInfo resourcePluginInfo) {
        var exts = resourcePluginInfo.getResourceSharingExtensions();
        for (var ext : exts) {
            URL url = ext.getClass().getClassLoader().getResource("resource-action-groups.yml");
            if (url == null) {
                log.info("resource-action-groups.yml not found for {}", ext.getClass().getName());
                continue;
            }

            try (var in = url.openStream()) {
                String yaml = new String(in.readAllBytes(), StandardCharsets.UTF_8);

                Map<String, Object> root = new Yaml().load(yaml);
                if (root == null) {
                    log.info("Empty resource-action-groups.yml for {}", ext.getClass().getName());
                    continue;
                }

                Object rtNode = root.get("resource_types");
                if (!(rtNode instanceof Map<?, ?> byType)) {
                    log.warn("'resource_types' missing or invalid in {}", ext.getClass().getName());
                    continue;
                }

                // For each type this extension provides, read its OWN map directly as groups (no wrapper)
                for (var rp : ext.getResourceProviders()) {
                    String resType = rp.resourceType();

                    Object typeCfgNode = byType.get(resType);
                    if (!(typeCfgNode instanceof Map<?, ?> typeMapRaw)) {
                        log.info("No per-type block for {} in {}", resType, ext.getClass().getName());
                        continue; // no fallback
                    }

                    SecurityDynamicConfiguration<ActionGroupsV7> cfg = SecurityDynamicConfiguration.fromMap(
                        (Map<String, Object>) typeMapRaw,
                        CType.ACTIONGROUPS
                    );

                    // prune groups that ended up empty after normalization
                    cfg.getCEntries()
                        .entrySet()
                        .removeIf(
                            e -> e.getValue() == null
                                || e.getValue().getAllowed_actions() == null
                                || e.getValue().getAllowed_actions().isEmpty()
                        );

                    FlattenedActionGroups flattened = new FlattenedActionGroups(cfg);

                    // Publish to ResourcePluginInfo → used by UI and authZ
                    resourcePluginInfo.registerActionGroupNames(resType, cfg.getCEntries().keySet());
                    resourcePluginInfo.registerFlattened(resType, flattened);

                    log.info("Registered {} action-groups for {}", cfg.getCEntries().size(), resType);
                }

            } catch (Exception e) {
                log.warn("Failed loading/parsing resource-action-groups.yml for {}: {}", ext.getClass().getName(), e.toString());
            }
        }
    }
}
// CS-ENFORCE-SINGLE
