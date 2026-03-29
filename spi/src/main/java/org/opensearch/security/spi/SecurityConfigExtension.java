/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.spi;

/**
 * Extension point for OpenSearch plugins that want to contribute static security configuration
 * (e.g. default roles, action groups) to the security plugin.
 *
 * <p>Plugins implement this interface and place a {@code default-roles.yml} file in their
 * classpath resources. The security plugin discovers implementations via
 * {@link org.opensearch.plugins.ExtensionAwarePlugin#loadExtensions} and loads the
 * YAML files from each plugin's classloader.</p>
 *
 * <p>Static roles contributed by plugins are held in-memory only (never persisted to the
 * security index) and take precedence over entries in the security plugin's own
 * {@code roles.yml} when a name collision exists.</p>
 *
 * @opensearch.experimental
 */
public interface SecurityConfigExtension {

    // Marker interface for now — the security plugin discovers implementations
    // and reads default-roles.yml from the implementing class's classloader.
    //
    // Future additions may include methods like:
    // String defaultRolesResourcePath(); // override the file name
    // String defaultActionGroupsResourcePath(); // plugin-provided action groups
}
