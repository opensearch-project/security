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
import java.util.HashSet;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.spi.SecurityConfigExtension;

/**
 * Loads {@code default-roles.yml} from each plugin that implements {@link SecurityConfigExtension}.
 * Roles are merged into the static roles pool in {@link DynamicConfigFactory}, with plugin-provided
 * definitions taking precedence over entries in the security plugin's own {@code static_roles.yml}.
 */
public class PluginDefaultRolesHelper {

    private static final Logger log = LogManager.getLogger(PluginDefaultRolesHelper.class);
    private static final String DEFAULT_ROLES_FILE = "default-roles.yml";

    /**
     * Loads default roles from all discovered {@link SecurityConfigExtension} implementations
     * and merges them into a single configuration. Plugin roles override any existing entries
     * with the same name (last writer wins across plugins, but all plugins win over static_roles.yml).
     *
     * <p>Multiple extensions from the same plugin (sharing a classloader) will resolve to the
     * same {@code default-roles.yml} URL — these are deduplicated so the file is only loaded once.</p>
     *
     * @param extensions the set of discovered SecurityConfigExtension implementations
     * @return merged SecurityDynamicConfiguration containing all plugin-provided roles
     */
    public static SecurityDynamicConfiguration<RoleV7> loadDefaultRoles(Set<SecurityConfigExtension> extensions) {
        SecurityDynamicConfiguration<RoleV7> merged = SecurityDynamicConfiguration.empty(CType.ROLES);
        Set<String> processedUrls = new HashSet<>();

        for (SecurityConfigExtension ext : extensions) {
            URL url = ext.getClass().getClassLoader().getResource(DEFAULT_ROLES_FILE);
            if (url == null) {
                log.debug("{} not found for {}", DEFAULT_ROLES_FILE, ext.getClass().getName());
                continue;
            }

            // Deduplicate: multiple extensions from the same plugin share a classloader
            if (!processedUrls.add(url.toString())) {
                log.debug("{} already loaded from {} (shared classloader), skipping", DEFAULT_ROLES_FILE, ext.getClass().getName());
                continue;
            }

            try (var in = url.openStream()) {
                String yaml = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                JsonNode node = DefaultObjectMapper.YAML_MAPPER.readTree(yaml);
                if (node == null || node.isEmpty()) {
                    log.debug("Empty {} for {}", DEFAULT_ROLES_FILE, ext.getClass().getName());
                    continue;
                }

                SecurityDynamicConfiguration<RoleV7> pluginRoles = SecurityDynamicConfiguration.fromNode(node, CType.ROLES, 2, 0, 0);

                // Mark all plugin-provided roles as static and reserved
                for (var entry : pluginRoles.getCEntries().entrySet()) {
                    entry.getValue().setStatic(true);
                    entry.getValue().setReserved(true);
                }

                log.info(
                    "Loaded {} default role(s) from {}: {}",
                    pluginRoles.getCEntries().size(),
                    ext.getClass().getName(),
                    pluginRoles.getCEntries().keySet()
                );

                merged.add(pluginRoles);
            } catch (Exception e) {
                log.warn("Failed to load/parse {} from {}: {}", DEFAULT_ROLES_FILE, ext.getClass().getName(), e.toString());
            }
        }

        return merged;
    }
}
