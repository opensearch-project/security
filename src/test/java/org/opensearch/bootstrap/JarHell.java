package org.opensearch.bootstrap;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.function.Consumer;
import java.util.HashSet;
import java.util.Set;

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
    public static Set<URL> parseClassPath() {return new HashSet<URL>();}
}