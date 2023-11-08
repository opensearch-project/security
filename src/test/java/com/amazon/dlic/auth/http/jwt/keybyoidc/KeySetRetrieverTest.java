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

package com.amazon.dlic.auth.http.jwt.keybyoidc;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Map;

import com.google.common.hash.Hashing;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.apache.http.ssl.PrivateKeyDetails;
import org.apache.http.ssl.PrivateKeyStrategy;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.network.SocketUtils;

import com.amazon.dlic.util.SettingsBasedSSLConfigurator;

public class KeySetRetrieverTest {
    protected static MockIpdServer mockIdpServer;

    @BeforeClass
    public static void setUp() throws Exception {
        mockIdpServer = new MockIpdServer(TestJwk.Jwks.ALL);
    }

    @AfterClass
    public static void tearDown() {
        if (mockIdpServer != null) {
            try {
                mockIdpServer.close();
            } catch (Exception ignored) {}
        }
    }

    @Test
    public void cacheTest() {
        KeySetRetriever keySetRetriever = new KeySetRetriever(mockIdpServer.getDiscoverUri(), null, true);

        keySetRetriever.get();

        Assert.assertEquals(1, keySetRetriever.getOidcCacheMisses());
        Assert.assertEquals(0, keySetRetriever.getOidcCacheHits());

        keySetRetriever.get();
        Assert.assertEquals(1, keySetRetriever.getOidcCacheMisses());
        Assert.assertEquals(1, keySetRetriever.getOidcCacheHits());
    }

    @Test
    public void clientCertTest() throws Exception {

        try (MockIpdServer sslMockIdpServer = new MockIpdServer(TestJwk.Jwks.ALL, SocketUtils.findAvailableTcpPort(), true) {
            @Override
            protected void handleDiscoverRequest(HttpRequest request, HttpResponse response, HttpContext context) throws HttpException,
                IOException {

                MockIpdServer.SSLTestHttpServerConnection connection =
                    (MockIpdServer.SSLTestHttpServerConnection) ((HttpCoreContext) context).getConnection();

                X509Certificate peerCert = (X509Certificate) connection.getPeerCertificates()[0];

                try {
                    String sha256Fingerprint = Hashing.sha256().hashBytes(peerCert.getEncoded()).toString();

                    Assert.assertEquals("04b2b8baea7a0a893f0223d95b72081e9a1e154a0f9b1b4e75998085972b1b68", sha256Fingerprint);

                } catch (CertificateEncodingException e) {
                    throw new RuntimeException(e);
                }

                super.handleDiscoverRequest(request, response, context);
            }
        }) {
            SSLContextBuilder sslContextBuilder = SSLContexts.custom();

            KeyStore trustStore = KeyStore.getInstance("JKS");
            InputStream trustStream = new FileInputStream(FileHelper.getAbsoluteFilePathFromClassPath("jwt/truststore.jks").toFile());
            trustStore.load(trustStream, "changeit".toCharArray());

            KeyStore keyStore = KeyStore.getInstance("JKS");
            InputStream keyStream = new FileInputStream(FileHelper.getAbsoluteFilePathFromClassPath("jwt/spock-keystore.jks").toFile());

            keyStore.load(keyStream, "changeit".toCharArray());

            sslContextBuilder.loadTrustMaterial(trustStore, null);

            sslContextBuilder.loadKeyMaterial(keyStore, "changeit".toCharArray(), new PrivateKeyStrategy() {

                @Override
                public String chooseAlias(Map<String, PrivateKeyDetails> aliases, Socket socket) {
                    return "spock";
                }
            });

            SettingsBasedSSLConfigurator.SSLConfig sslConfig = new SettingsBasedSSLConfigurator.SSLConfig(
                sslContextBuilder.build(),
                new String[] { "TLSv1.2", "TLSv1.1" },
                null,
                null,
                false,
                false,
                false,
                trustStore,
                null,
                keyStore,
                null,
                null
            );

            KeySetRetriever keySetRetriever = new KeySetRetriever(sslMockIdpServer.getDiscoverUri(), sslConfig, false);

            keySetRetriever.get();

        }
    }
}
