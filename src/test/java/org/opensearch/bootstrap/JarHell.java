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

package org.opensearch.bootstrap;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Disable JarHell to unblock test development
 * https://github.com/opensearch-project/security/issues/1938
 */
public class JarHell {
    private JarHell() {}

    public static void checkJarHell(Consumer<String> output) throws IOException, Exception {}

    public static void checkJarHell(Set<URL> urls, Consumer<String> output) throws URISyntaxException, IOException {}

    public static void checkVersionFormat(String targetVersion) {}

    public static void checkJavaVersion(String resource, String targetVersion) {}

    public static Set<URL> parseClassPath() {
        return new HashSet<URL>();
    }
}
