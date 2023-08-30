/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.bwc;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.nio.AsyncClientConnectionManager;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.core5.function.Factory;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;
import org.apache.hc.core5.reactor.ssl.TlsDetails;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.junit.Assume;
import org.junit.Before;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import org.opensearch.Version;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;

import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;

import org.junit.Assert;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

public class SecurityBackwardsCompatibilityIT extends OpenSearchRestTestCase {

    private ClusterType CLUSTER_TYPE;
    private String CLUSTER_NAME;

    @Before
    private void testSetup() {
        final String bwcsuiteString = System.getProperty("tests.rest.bwcsuite");
        Assume.assumeTrue("Test cannot be run outside the BWC gradle task 'bwcTestSuite' or its dependent tasks", bwcsuiteString != null);
        CLUSTER_TYPE = ClusterType.parse(bwcsuiteString);
        CLUSTER_NAME = System.getProperty("tests.clustername");
    }

    @Override
    protected final boolean preserveClusterUponCompletion() {
        return true;
    }

    @Override
    protected final boolean preserveIndicesUponCompletion() {
        return true;
    }

    @Override
    protected final boolean preserveReposUponCompletion() {
        return true;
    }

    @Override
    protected boolean preserveTemplatesUponCompletion() {
        return true;
    }

    @Override
    protected String getProtocol() {
        return "https";
    }

    @Override
    protected final Settings restClientSettings() {
        return Settings.builder()
            .put(super.restClientSettings())
            // increase the timeout here to 90 seconds to handle long waits for a green
            // cluster health. the waits for green need to be longer than a minute to
            // account for delayed shards
            .put(OpenSearchRestTestCase.CLIENT_SOCKET_TIMEOUT, "90s")
            .build();
    }

    @Override
    protected RestClient buildClient(Settings settings, HttpHost[] hosts) throws IOException {
        RestClientBuilder builder = RestClient.builder(hosts);
        configureHttpsClient(builder, settings);
        boolean strictDeprecationMode = settings.getAsBoolean("strictDeprecationMode", true);
        builder.setStrictDeprecationMode(strictDeprecationMode);
        return builder.build();
    }

    protected static void configureHttpsClient(RestClientBuilder builder, Settings settings) throws IOException {
        Map<String, String> headers = ThreadContext.buildDefaultHeaders(settings);
        Header[] defaultHeaders = new Header[headers.size()];
        int i = 0;
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            defaultHeaders[i++] = new BasicHeader(entry.getKey(), entry.getValue());
        }
        builder.setDefaultHeaders(defaultHeaders);
        builder.setHttpClientConfigCallback(httpClientBuilder -> {
            String userName = Optional.ofNullable(System.getProperty("tests.opensearch.username"))
                .orElseThrow(() -> new RuntimeException("user name is missing"));
            String password = Optional.ofNullable(System.getProperty("tests.opensearch.password"))
                .orElseThrow(() -> new RuntimeException("password is missing"));
            BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            credentialsProvider.setCredentials(new AuthScope(null, -1), new UsernamePasswordCredentials(userName, password.toCharArray()));
            try {
                SSLContext sslContext = SSLContextBuilder.create().loadTrustMaterial(null, (chains, authType) -> true).build();

                TlsStrategy tlsStrategy = ClientTlsStrategyBuilder.create()
                    .setSslContext(sslContext)
                    .setTlsVersions(new String[] { "TLSv1", "TLSv1.1", "TLSv1.2", "SSLv3" })
                    .setHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    // See please https://issues.apache.org/jira/browse/HTTPCLIENT-2219
                    .setTlsDetailsFactory(new Factory<SSLEngine, TlsDetails>() {
                        @Override
                        public TlsDetails create(final SSLEngine sslEngine) {
                            return new TlsDetails(sslEngine.getSession(), sslEngine.getApplicationProtocol());
                        }
                    })
                    .build();

                final AsyncClientConnectionManager cm = PoolingAsyncClientConnectionManagerBuilder.create()
                    .setTlsStrategy(tlsStrategy)
                    .build();
                return httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider).setConnectionManager(cm);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    public void testBasicBackwardsCompatibility() throws Exception {
        String round = System.getProperty("tests.rest.bwcsuite_round");

        if (round.equals("first") || round.equals("old")) {
            assertPluginUpgrade("_nodes/" + CLUSTER_NAME + "-0/plugins");
        } else if (round.equals("second")) {
            assertPluginUpgrade("_nodes/" + CLUSTER_NAME + "-1/plugins");
        } else if (round.equals("third")) {
            assertPluginUpgrade("_nodes/" + CLUSTER_NAME + "-2/plugins");
        }
    }

    @SuppressWarnings("unchecked")
    public void testWhoAmI() throws Exception {
        Map<String, Object> responseMap = (Map<String, Object>) getAsMap("_plugins/_security/whoami");
        Assert.assertTrue(responseMap.containsKey("dn"));
    }

    private enum ClusterType {
        OLD,
        MIXED,
        UPGRADED;

        public static ClusterType parse(String value) {
            switch (value) {
                case "old_cluster":
                    return OLD;
                case "mixed_cluster":
                    return MIXED;
                case "upgraded_cluster":
                    return UPGRADED;
                default:
                    throw new AssertionError("unknown cluster type: " + value);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void assertPluginUpgrade(String uri) throws Exception {
        Map<String, Map<String, Object>> responseMap = (Map<String, Map<String, Object>>) getAsMap(uri).get("nodes");
        for (Map<String, Object> response : responseMap.values()) {
            List<Map<String, Object>> plugins = (List<Map<String, Object>>) response.get("plugins");
            Set<String> pluginNames = plugins.stream().map(map -> (String) map.get("name")).collect(Collectors.toSet());

            final Version minNodeVersion = this.minimumNodeVersion();

            if (minNodeVersion.major <= 1) {
                assertThat(pluginNames, hasItem("opensearch_security"));
            } else {
                assertThat(pluginNames, hasItem("opensearch-security"));
            }

        }
    }
}
