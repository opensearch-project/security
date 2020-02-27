/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.httpclient;

import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.amazon.opendistroforelasticsearch.security.httpclient.HttpClient;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;

public class HttpClientTest extends SingleClusterTest {

    @Override
    protected String getResourceFolder() {
        return "auditlog";
    }

    @Test
    public void testPlainConnection() throws Exception {

        final Settings settings = Settings.builder()
                .put("opendistro_security.ssl.http.enabled", false)
                .build();

        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings);

        Thread.sleep(1000);

        try(final HttpClient httpClient = HttpClient.builder(clusterInfo.httpHost+":"+clusterInfo.httpPort)
                .setBasicCredentials("admin", "admin").build()) {
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
        }

        try(final HttpClient httpClient = HttpClient.builder("unknownhost:6654")
                .setBasicCredentials("admin", "admin").build()) {
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
        }

        try(final HttpClient httpClient = HttpClient.builder("unknownhost:6654", clusterInfo.httpHost+":"+clusterInfo.httpPort)
                .enableSsl(FileHelper.getKeystoreFromClassPath("auditlog/truststore.jks","changeit"), false)
                .setBasicCredentials("admin", "admin").build()) {
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
        }

        try(final HttpClient httpClient = HttpClient.builder("unknownhost:6654", clusterInfo.httpHost+":"+clusterInfo.httpPort)
                .setBasicCredentials("admin", "admin").build()) {
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
        }

    }

    @Test
    public void testSslConnection() throws Exception {

        final Settings settings = Settings.builder()
                .put("opendistro_security.ssl.http.enabled", true)
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, false)
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
                .put("opendistro_security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/node-0-keystore.jks"))
                .put("opendistro_security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/truststore.jks"))
                .build();

        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings);

        Thread.sleep(1000);

        try(final HttpClient httpClient = HttpClient.builder(clusterInfo.httpHost+":"+clusterInfo.httpPort)
                .enableSsl(FileHelper.getKeystoreFromClassPath("auditlog/truststore.jks","changeit"), false)
                .setBasicCredentials("admin", "admin").build()) {
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
        }

        try(final HttpClient httpClient = HttpClient.builder(clusterInfo.httpHost+":"+clusterInfo.httpPort)
                .setBasicCredentials("admin", "admin").build()) {
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertFalse(httpClient.index("{\"a\":5}", "index", "type", true));
        }

    }

    @Test
    public void testSslConnectionPKIAuth() throws Exception {

        final Settings settings = Settings.builder()
                .put("opendistro_security.ssl.http.enabled", true)
                .put("opendistro_security.ssl.http.clientauth_mode", "REQUIRE")
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, false)
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
                .put("opendistro_security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/node-0-keystore.jks"))
                .put("opendistro_security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("auditlog/truststore.jks"))
                .build();

        setup(Settings.EMPTY, new DynamicSecurityConfig(), settings);

        Thread.sleep(1000);

        try(final HttpClient httpClient = HttpClient.builder(clusterInfo.httpHost+":"+clusterInfo.httpPort)
                .enableSsl(FileHelper.getKeystoreFromClassPath("auditlog/truststore.jks","changeit"), false)
                .setPkiCredentials(FileHelper.getKeystoreFromClassPath("auditlog/spock-keystore.jks", "changeit"), "changeit".toCharArray(), null)
                .build()) {
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", false));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
            Assert.assertTrue(httpClient.index("{\"a\":5}", "index", "type", true));
        }

    }
}
