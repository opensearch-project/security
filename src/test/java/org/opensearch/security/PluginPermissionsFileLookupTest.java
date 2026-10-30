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

package org.opensearch.security;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import static org.opensearch.security.OpenSearchSecurityPlugin.PLUGIN_PERMISSIONS_FILE;
import static org.opensearch.security.OpenSearchSecurityPlugin.findPluginPermissionsFile;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/** Tests that a plugin's permissions file is looked up in the plugin's own jars, not in the plugins it extends. */
public class PluginPermissionsFileLookupTest {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Test
    public void ignoresTheFileOfAnExtendedPlugin() throws IOException {
        try (
            URLClassLoader extended = loaderWithFile("extended", "cluster_permissions: []\n");
            URLClassLoader plugin = new URLClassLoader(new URL[] { folder.newFolder("plugin").toURI().toURL() }, extended)
        ) {
            // Shows the parent's file is reachable, so only the lookup itself can return null
            assertNotNull(plugin.getResource(PLUGIN_PERMISSIONS_FILE));
            assertNull(findPluginPermissionsFile(plugin));
        }
    }

    @Test
    public void findsThePluginsOwnFileWhenTheExtendedPluginHasOne() throws IOException {
        try (
            URLClassLoader extended = loaderWithFile("extended", "cluster_permissions: [\"extended\"]\n");
            URLClassLoader plugin = loaderWithFile("plugin", "cluster_permissions: [\"plugin\"]\n", extended)
        ) {
            URL file = findPluginPermissionsFile(plugin);
            assertEquals("cluster_permissions: [\"plugin\"]\n", new String(file.openStream().readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    private URLClassLoader loaderWithFile(String name, String content) throws IOException {
        return loaderWithFile(name, content, null);
    }

    private URLClassLoader loaderWithFile(String name, String content, ClassLoader parent) throws IOException {
        Path dir = folder.newFolder(name).toPath();
        Files.writeString(dir.resolve(PLUGIN_PERMISSIONS_FILE), content);
        return new URLClassLoader(new URL[] { dir.toUri().toURL() }, parent);
    }
}
