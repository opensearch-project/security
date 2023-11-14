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

package org.opensearch.security.httpclient;

import org.junit.Assert;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.file.FileHelper;

public class HttpClientTest extends SingleClusterTest {

    @Override
    protected String getResourceFolder() {
        return "auditlog";
    }

    @Test
    public void testPlainConnection() throws Exception {

        final Settings settings = Settings.builder()
            .put("plugins.security.ssl.http.enabled", false)
            .loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/configuration_valid.yml"))
            .build();

        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings);

        Thread.sleep(1000);

        try (
            final HttpClient httpClient = HttpClient.builder(clusterInfo.httpHost + ":" + clusterInfo.httpPort)
                .setBasicCredentials("admin", "admin")
                .build()
        ) {
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
        }

        try (final HttpClient httpClient = HttpClient.builder("unknownhost:6654").setBasicCredentials("admin", "admin").build()) {
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
        }

        try (
            final HttpClient httpClient = HttpClient.builder("unknownhost:6654", clusterInfo.httpHost + ":" + clusterInfo.httpPort)
                .enableSsl(FileHelper.getKeystoreFromClassPath("auditlog/truststore.jks", "changeit"), false)
                .setBasicCredentials("admin", "admin")
                .build()
        ) {
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
        }

        try (
            final HttpClient httpClient = HttpClient.builder("unknownhost:6654", clusterInfo.httpHost + ":" + clusterInfo.httpPort)
                .setBasicCredentials("admin", "admin")
                .build()
        ) {
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
        }

    }

    @Test
    public void testSslConnection() throws Exception {

        final Settings settings = Settings.builder()
            .put("plugins.security.ssl.http.enabled", true)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, false)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/truststore.jks"))
            .loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/configuration_valid.yml"))
            .build();

        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings);

        Thread.sleep(1000);

        try (
            final HttpClient httpClient = HttpClient.builder(clusterInfo.httpHost + ":" + clusterInfo.httpPort)
                .enableSsl(FileHelper.getKeystoreFromClassPath("auditlog/truststore.jks", "changeit"), false)
                .setBasicCredentials("admin", "admin")
                .build()
        ) {
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
        }

        try (
            final HttpClient httpClient = HttpClient.builder(clusterInfo.httpHost + ":" + clusterInfo.httpPort)
                .setBasicCredentials("admin", "admin")
                .build()
        ) {
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
        }

    }

    @Test
    public void testSslConnectionPKIAuth() throws Exception {

        final Settings settings = Settings.builder()
            .put("plugins.security.ssl.http.enabled", true)
            .put("plugins.security.ssl.http.clientauth_mode", "REQUIRE")
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, false)
            .put(SSLConfigConstants.SECURITY_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
            .put("plugins.security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/node-0-keystore.jks"))
            .put("plugins.security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/truststore.jks"))
            .loadFromPath(FileHelper.getAbsoluteFilePathFromClassPath("auditlog/endpoints/routing/configuration_valid.yml"))
            .build();

        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings);

        Thread.sleep(1000);

        try (
            final HttpClient httpClient = HttpClient.builder(clusterInfo.httpHost + ":" + clusterInfo.httpPort)
                .enableSsl(FileHelper.getKeystoreFromClassPath("auditlog/truststore.jks", "changeit"), false)
                .setPkiCredentials(
                    FileHelper.getKeystoreFromClassPath("auditlog/spock-keystore.jks", "changeit"),
                    "changeit".toCharArray(),
                    null
                )
                .build()
        ) {
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
        }

    }
}
