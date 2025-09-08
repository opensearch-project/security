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
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
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
     *   resource_types:
     *   org.opensearch.sample.SampleResource:
     *       sample_read_only:
     *         - "cluster:admin/sample-resource-plugin/get"
     *         - "indices:data/read*"
     */
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
                    String typeFqn = rp.resourceType();

                    Object typeCfgNode = byType.get(typeFqn);
                    if (!(typeCfgNode instanceof Map<?, ?> typeMapRaw)) {
                        log.info("No per-type block for {} in {}", typeFqn, ext.getClass().getName());
                        continue; // no fallback
                    }

                    // buildActionGroupsYaml() accepts only lists-of-strings; anything else becomes allowed_actions: []
                    String perTypeAgYaml = buildActionGroupsYaml(typeMapRaw);

                    // Parse + flatten for THIS type
                    SecurityDynamicConfiguration<ActionGroupsV7> cfg = SecurityDynamicConfiguration.fromYaml(
                        perTypeAgYaml,
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
                    resourcePluginInfo.registerActionGroupNames(typeFqn, cfg.getCEntries().keySet());
                    resourcePluginInfo.registerFlattened(typeFqn, flattened);

                    log.info("Registered {} action-groups for {}", cfg.getCEntries().size(), typeFqn);
                }

            } catch (Exception e) {
                log.warn("Failed loading/parsing resource-action-groups.yml for {}: {}", ext.getClass().getName(), e.toString());
            }
        }
    }

    /**
     * Build a minimal action-groups YAML from a per-type "action_groups" map.
     * Input shape:
     * { actionGroupName -> [ ... ] }
     * Output YAML:
     *   actionGroupName:
     *     allowed_actions:
     *       - "..."
     */
    private static String buildActionGroupsYaml(Map<?, ?> groupsRaw) {
        Map<String, Object> normalized = new LinkedHashMap<>();

        if (groupsRaw != null) {
            for (Map.Entry<?, ?> e : groupsRaw.entrySet()) {
                String group = String.valueOf(e.getKey());
                Object v = e.getValue();

                // default to empty list
                List<String> actions = List.of();

                // Accept ONLY shape A: group: [ "action:a", "action:b", ... ]
                if (v instanceof Collection<?> coll) {
                    List<String> tmp = new ArrayList<>(coll.size());
                    boolean allStrings = true;
                    for (Object item : coll) {
                        if (!(item instanceof String s)) {
                            allStrings = false;
                            break;
                        }
                        tmp.add(s);
                    }
                    if (allStrings) {
                        actions = tmp;
                    }
                }

                Map<String, Object> groupObj = new LinkedHashMap<>();
                groupObj.put("allowed_actions", actions);
                normalized.put(group, groupObj);
            }
        }

        return new Yaml().dump(normalized);
    }
}
// CS-ENFORCE-SINGLE
