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

package org.opensearch.security.auth.http.jwt.keybyoidc;

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
import org.apache.hc.core5.http.io.entity.StringEntity;
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
import org.opensearch.security.util.SettingsBasedSSLConfigurator;

import com.nimbusds.jose.jwk.JWKSet;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class KeySetRetrieverTest {
    protected static MockIpdServer mockIdpServer;
    protected static MockJwksServer mockJwksServer;

    @BeforeClass
    public static void setUp() throws Exception {
        mockIdpServer = new MockIpdServer(TestJwk.Jwks.ALL);
        mockJwksServer = new MockJwksServer(TestJwk.Jwks.ALL);
    }

    @AfterClass
    public static void tearDown() {
        if (mockIdpServer != null) {
            try {
                mockIdpServer.close();
            } catch (Exception ignored) {}
        }
        if (mockJwksServer != null) {
            try {
                mockJwksServer.close();
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

    // Tests for new factory method createForJwksUri
    @Test
    public void testCreateForJwksUri_ValidParameters() {
        String jwksUri = mockJwksServer.getJwksUri();
        long maxResponseSize = 1024 * 1024; // 1MB
        int maxKeyCount = 10;

        KeySetRetriever retriever = KeySetRetriever.createForJwksUri(
            null, // sslConfig
            false, // useCacheForJwksEndpoint
            jwksUri,
            maxResponseSize,
            maxKeyCount
        );

        assertThat(retriever, is(notNullValue()));

        // Test that it can successfully retrieve keys
        JWKSet keySet = retriever.get();
        assertThat(keySet, is(notNullValue()));
        assertThat(keySet.getKeys().size(), is(greaterThan(0)));
    }

    @Test
    public void testCreateForJwksUri_WithCaching() {
        String jwksUri = mockJwksServer.getJwksUri();

        KeySetRetriever retriever = KeySetRetriever.createForJwksUri(
            null, // sslConfig
            true, // useCacheForJwksEndpoint - enable caching
            jwksUri,
            1024 * 1024, // maxResponseSize
            10 // maxKeyCount
        );

        // First call should be a cache miss
        JWKSet keySet1 = retriever.get();
        assertThat(keySet1, is(notNullValue()));
        assertThat(keySet1.getKeys().size(), is(greaterThan(0)));
        assertThat(retriever.getOidcCacheMisses(), is(1));
        assertThat(retriever.getOidcCacheHits(), is(0));

        // Second call should be a cache hit
        JWKSet keySet2 = retriever.get();
        assertThat(keySet2, is(notNullValue()));
        assertThat(keySet2.getKeys().size(), is(greaterThan(0)));
        assertThat(retriever.getOidcCacheMisses(), is(1));
        assertThat(retriever.getOidcCacheHits(), is(1));
    }

    // Tests for direct JWKS URI functionality
    @Test
    public void testDirectJwksUri_BypassesOidcDiscovery() {
        String jwksUri = mockJwksServer.getJwksUri();

        // NOTE: This constructor bypasses OIDC discovery entirely by providing jwksUri directly
        // The 'false' parameter disables caching for this instance
        KeySetRetriever retriever = new KeySetRetriever(null, false, jwksUri);

        JWKSet keySet = retriever.get();
        assertThat(keySet, is(notNullValue()));
        assertThat(keySet.getKeys().size(), is(greaterThan(0)));

        // Verify that no caching was used since caching was disabled (false parameter)
        assertThat(retriever.getOidcCacheMisses(), is(0));
        assertThat(retriever.getOidcCacheHits(), is(0));
    }

    @Test
    public void testDirectJwksUri_InvalidUri() {
        String invalidJwksUri = "http://invalid-host:9999/jwks";

        KeySetRetriever retriever = new KeySetRetriever(null, false, invalidJwksUri);

        AuthenticatorUnavailableException exception = assertThrows(AuthenticatorUnavailableException.class, () -> retriever.get());

        assertTrue(exception.getMessage().contains("Error while getting " + invalidJwksUri));
    }

    // Tests for security validation features
    @Test
    public void testSecurityValidation_ResponseSizeExceeded() throws IOException {
        // Create a mock server that returns a large response
        try (MockJwksServer largeMockServer = new MockJwksServer(TestJwk.Jwks.ALL, SocketUtils.findAvailableTcpPort(), false) {
            @Override
            protected void handleJwksRequest(HttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException,
                IOException {
                response.setCode(200);
                // Create a large response that exceeds our limit
                StringBuilder largeResponse = new StringBuilder();
                largeResponse.append("{\"keys\":[");
                for (int i = 0; i < 1000; i++) {
                    if (i > 0) largeResponse.append(",");
                    largeResponse.append("{\"kty\":\"oct\",\"k\":\"test\",\"kid\":\"key").append(i).append("\"}");
                }
                largeResponse.append("]}");
                response.setEntity(new StringEntity(largeResponse.toString()));
            }
        }) {
            String jwksUri = largeMockServer.getJwksUri();
            long maxResponseSize = 100; // Very small limit

            KeySetRetriever retriever = KeySetRetriever.createForJwksUri(null, false, jwksUri, maxResponseSize, 10);

            AuthenticatorUnavailableException exception = assertThrows(AuthenticatorUnavailableException.class, () -> retriever.get());

            assertTrue(exception.getMessage().contains("JWKS response too large"));
            assertTrue(exception.getMessage().contains("max: " + maxResponseSize));
        }
    }

    @Test
    public void testSecurityValidation_KeyCountExceeded() throws IOException {
        // Create a mock server that returns many keys
        try (MockJwksServer manyKeysMockServer = new MockJwksServer(TestJwk.Jwks.ALL, SocketUtils.findAvailableTcpPort(), false) {
            @Override
            protected void handleJwksRequest(HttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException,
                IOException {
                response.setCode(200);
                // Create a JWKS with many keys
                StringBuilder manyKeysResponse = new StringBuilder();
                manyKeysResponse.append("{\"keys\":[");
                for (int i = 0; i < 15; i++) {
                    if (i > 0) manyKeysResponse.append(",");
                    manyKeysResponse.append("{")
                        .append("\"kty\":\"oct\",")
                        .append("\"k\":\"")
                        .append(TestJwk.OCT_1_K)
                        .append("\",")
                        .append("\"kid\":\"key")
                        .append(i)
                        .append("\",")
                        .append("\"use\":\"sig\",")
                        .append("\"alg\":\"HS256\"")
                        .append("}");
                }
                manyKeysResponse.append("]}");
                response.setEntity(new StringEntity(manyKeysResponse.toString()));
            }
        }) {
            String jwksUri = manyKeysMockServer.getJwksUri();
            int maxKeyCount = 5; // Small limit

            KeySetRetriever retriever = KeySetRetriever.createForJwksUri(
                null,
                false,
                jwksUri,
                1024 * 1024, // Large response size limit
                maxKeyCount
            );

            AuthenticatorUnavailableException exception = assertThrows(AuthenticatorUnavailableException.class, () -> retriever.get());

            assertTrue(exception.getMessage().contains("contains 15 keys"));
            assertTrue(exception.getMessage().contains("max allowed is " + maxKeyCount));
        }
    }

    @Test
    public void testSecurityValidation_WithinLimits() {
        String jwksUri = mockJwksServer.getJwksUri();

        KeySetRetriever retriever = KeySetRetriever.createForJwksUri(
            null,
            false,
            jwksUri,
            1024 * 1024, // 1MB - generous limit
            20 // 20 keys - generous limit
        );

        // Should succeed without throwing exception
        JWKSet keySet = retriever.get();
        assertThat(keySet, is(notNullValue()));
        assertThat(keySet.getKeys().size(), is(greaterThan(0)));
    }

    @Test
    public void testSecurityValidation_UnlimitedSize() {
        String jwksUri = mockJwksServer.getJwksUri();

        KeySetRetriever retriever = KeySetRetriever.createForJwksUri(
            null,
            false,
            jwksUri,
            -1, // Unlimited size
            -1  // Unlimited keys
        );

        // Should succeed without throwing exception
        JWKSet keySet = retriever.get();
        assertThat(keySet, is(notNullValue()));
        assertThat(keySet.getKeys().size(), is(greaterThan(0)));
    }

    // Tests for error handling scenarios
    @Test
    public void testErrorHandling_HttpErrorResponse() throws IOException {
        // Create a mock JWKS server that returns HTTP error
        try (MockJwksServer errorMockServer = new MockJwksServer(TestJwk.Jwks.ALL, SocketUtils.findAvailableTcpPort(), false) {
            @Override
            protected void handleJwksRequest(HttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException,
                IOException {
                response.setCode(404);
                response.setReasonPhrase("Not Found");
                response.setEntity(new StringEntity("JWKS endpoint not found"));
            }
        }) {
            String jwksUri = errorMockServer.getJwksUri();

            KeySetRetriever retriever = KeySetRetriever.createForJwksUri(null, false, jwksUri, 1024 * 1024, 10);

            AuthenticatorUnavailableException exception = assertThrows(AuthenticatorUnavailableException.class, () -> retriever.get());

            assertTrue(exception.getMessage().contains("Error while getting " + jwksUri));
            assertTrue(exception.getMessage().contains("Not Found"));
        }
    }

    @Test
    public void testErrorHandling_EmptyResponse() throws IOException {
        // Create a mock JWKS server that returns empty response
        try (MockJwksServer emptyMockServer = new MockJwksServer(TestJwk.Jwks.ALL, SocketUtils.findAvailableTcpPort(), false) {
            @Override
            protected void handleJwksRequest(HttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException,
                IOException {
                response.setCode(200);
                response.setEntity(new StringEntity("")); // Empty string entity to trigger ParseException
            }
        }) {
            String jwksUri = emptyMockServer.getJwksUri();

            KeySetRetriever retriever = KeySetRetriever.createForJwksUri(null, false, jwksUri, 1024 * 1024, 10);

            AuthenticatorUnavailableException exception = assertThrows(AuthenticatorUnavailableException.class, () -> retriever.get());

            assertTrue(exception.getMessage().contains("Error parsing JWKS"));
        }
    }

    @Test
    public void testErrorHandling_MalformedJwks() throws IOException {
        // Create a mock JWKS server that returns malformed JWKS
        try (MockJwksServer malformedMockServer = new MockJwksServer(TestJwk.Jwks.ALL, SocketUtils.findAvailableTcpPort(), false) {
            @Override
            protected void handleJwksRequest(HttpRequest request, ClassicHttpResponse response, HttpContext context) throws HttpException,
                IOException {
                response.setCode(200);
                response.setEntity(new StringEntity("{ invalid json }"));
            }
        }) {
            String jwksUri = malformedMockServer.getJwksUri();

            KeySetRetriever retriever = KeySetRetriever.createForJwksUri(null, false, jwksUri, 1024 * 1024, 10);

            // Should throw AuthenticatorUnavailableException due to ParseException being wrapped
            AuthenticatorUnavailableException exception = assertThrows(AuthenticatorUnavailableException.class, () -> retriever.get());

            // The exception message should contain parsing error information
            assertTrue(exception.getMessage().contains("Error parsing JWKS"));
            assertThat(exception.getCause(), is(notNullValue()));
        }
    }

    @Test
    public void testErrorHandling_MissingBothEndpoints() {
        // Test when both openIdConnectEndpoint and jwksUri are null/empty
        KeySetRetriever retriever = new KeySetRetriever(null, false, null);

        AuthenticatorUnavailableException exception = assertThrows(AuthenticatorUnavailableException.class, () -> retriever.get());

        assertTrue(exception.getMessage().contains("Either openid_connect_url or jwks_uri must be configured"));
    }

    // Tests for edge cases
    @Test
    public void testEdgeCase_ZeroResponseSizeLimit() {
        String jwksUri = mockJwksServer.getJwksUri();

        KeySetRetriever retriever = KeySetRetriever.createForJwksUri(
            null,
            false,
            jwksUri,
            0, // Zero size limit
            10
        );

        // Should work because 0 means no limit is enforced (only positive values are checked)
        JWKSet keySet = retriever.get();
        assertThat(keySet, is(notNullValue()));
    }

    @Test
    public void testEdgeCase_ZeroKeyCountLimit() {
        String jwksUri = mockJwksServer.getJwksUri();

        KeySetRetriever retriever = KeySetRetriever.createForJwksUri(
            null,
            false,
            jwksUri,
            1024 * 1024,
            0 // Zero key count limit
        );

        // Should work because 0 means no limit is enforced (only positive values are checked)
        JWKSet keySet = retriever.get();
        assertThat(keySet, is(notNullValue()));
    }

    @Test
    public void testEdgeCase_SecurityValidationDisabledForOidcFlow() {
        // Test that security validation is NOT applied for OIDC discovery flow
        // Using direct JWKS URI constructor to bypass OIDC discovery
        KeySetRetriever retriever = new KeySetRetriever(null, false, mockJwksServer.getJwksUri());

        // Should succeed even though we haven't set security limits
        // because security validation is only enabled for createForJwksUri
        JWKSet keySet = retriever.get();
        assertThat(keySet, is(notNullValue()));
        assertThat(keySet.getKeys().size(), is(greaterThan(0)));
    }

    @Test
    public void testRequestTimeout_Configuration() {
        // Test timeout configuration using direct JWKS URI approach
        KeySetRetriever retriever = new KeySetRetriever(null, false, mockJwksServer.getJwksUri());

        // Test default timeout
        assertThat(retriever.getRequestTimeoutMs(), is(10000));

        // Test setting custom timeout
        retriever.setRequestTimeoutMs(5000);
        assertThat(retriever.getRequestTimeoutMs(), is(5000));
    }
}
