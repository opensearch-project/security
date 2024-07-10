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
import java.security.KeyStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Map;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

import com.google.common.hash.Hashing;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.http.protocol.HttpCoreContext;
import org.apache.hc.core5.ssl.PrivateKeyDetails;
import org.apache.hc.core5.ssl.PrivateKeyStrategy;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.ssl.SSLContexts;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import org.opensearch.security.test.helper.file.FileHelper;
import org.opensearch.security.test.helper.network.SocketUtils;

import com.amazon.dlic.util.SettingsBasedSSLConfigurator;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

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

        assertThat(keySetRetriever.getOidcCacheMisses(), is(1));
        assertThat(keySetRetriever.getOidcCacheHits(), is(0));

        keySetRetriever.get();
        assertThat(keySetRetriever.getOidcCacheMisses(), is(1));
        assertThat(keySetRetriever.getOidcCacheHits(), is(1));
    }

    @Test
    public void clientCertTest() throws Exception {

        try (MockIpdServer sslMockIdpServer = new MockIpdServer(TestJwk.Jwks.ALL, SocketUtils.findAvailableTcpPort(), true) {
            @Override
            protected void handleDiscoverRequest(HttpRequest request, ClassicHttpResponse response, HttpContext context) throws IOException,
                HttpException {

                SSLSession sslSession = ((HttpCoreContext) context).getSSLSession();

                X509Certificate peerCert = (X509Certificate) sslSession.getPeerCertificates()[0];

                try {
                    String sha256Fingerprint = Hashing.sha256().hashBytes(peerCert.getEncoded()).toString();

                    assertThat(sha256Fingerprint, is("04b2b8baea7a0a893f0223d95b72081e9a1e154a0f9b1b4e75998085972b1b68"));

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
                public String chooseAlias(Map<String, PrivateKeyDetails> aliases, SSLParameters sslParameters) {
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
