/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.security.bwc;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.message.BasicHeader;
import org.apache.http.ssl.SSLContextBuilder;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;

import org.opensearch.Version;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestClientBuilder;
import org.opensearch.common.Randomness;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.util.io.IOUtils;
import org.opensearch.security.bwc.helper.RestHelper;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasKey;

public class SecurityBackwardsCompatibilityIT extends OpenSearchRestTestCase {

    private ClusterType CLUSTER_TYPE;
    private String CLUSTER_NAME;

    private final String TEST_USER = "user";
    private final String TEST_PASSWORD = "290735c0-355d-4aaf-9b42-1aaa1f2a3cee";
    private final String TEST_ROLE = "test-dls-fls-role";
    private static RestClient testUserRestClient = null;

    @Before
    public void testSetup() {
        final String bwcsuiteString = System.getProperty("tests.rest.bwcsuite");
        Assume.assumeTrue("Test cannot be run outside the BWC gradle task 'bwcTestSuite' or its dependent tasks", bwcsuiteString != null);
        CLUSTER_TYPE = ClusterType.parse(bwcsuiteString);
        CLUSTER_NAME = System.getProperty("tests.clustername");
        if (testUserRestClient == null) {
            testUserRestClient = buildClient(
                super.restClientSettings(),
                super.getClusterHosts().toArray(new HttpHost[0]),
                TEST_USER,
                TEST_PASSWORD
            );
        }
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

    protected RestClient buildClient(Settings settings, HttpHost[] hosts, String username, String password) {
        RestClientBuilder builder = RestClient.builder(hosts);
        configureHttpsClient(builder, settings, username, password);
        boolean strictDeprecationMode = settings.getAsBoolean("strictDeprecationMode", true);
        builder.setStrictDeprecationMode(strictDeprecationMode);
        return builder.build();
    }

    @Override
    protected RestClient buildClient(Settings settings, HttpHost[] hosts) {
        String username = Optional.ofNullable(System.getProperty("tests.opensearch.username"))
            .orElseThrow(() -> new RuntimeException("user name is missing"));
        String password = Optional.ofNullable(System.getProperty("tests.opensearch.password"))
            .orElseThrow(() -> new RuntimeException("password is missing"));
        return buildClient(super.restClientSettings(), super.getClusterHosts().toArray(new HttpHost[0]), username, password);
    }

    private static void configureHttpsClient(RestClientBuilder builder, Settings settings, String userName, String password) {
        Map<String, String> headers = ThreadContext.buildDefaultHeaders(settings);
        Header[] defaultHeaders = new Header[headers.size()];
        int i = 0;
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            defaultHeaders[i++] = new BasicHeader(entry.getKey(), entry.getValue());
        }
        builder.setDefaultHeaders(defaultHeaders);
        builder.setHttpClientConfigCallback(httpClientBuilder -> {
            CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            credentialsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(userName, password));
            try {
                return httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider)
                    // disable the certificate since our testing cluster just uses the default security configuration
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .setSSLContext(SSLContextBuilder.create().loadTrustMaterial(null, (chains, authType) -> true).build());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    public void testWhoAmI() throws Exception {
        Map<String, Object> responseMap = getAsMap("_plugins/_security/whoami");
        assertThat(responseMap, hasKey("dn"));
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

    /**
     * Tests backward compatibility by created a test user and role with DLS, FLS and masked field settings. Ingests
     * data into a test index and runs a matchAll query against the same.
     */
    public void testDataIngestionAndSearchBackwardsCompatibility() throws Exception {
        String round = System.getProperty("tests.rest.bwcsuite_round");
        String index = "test_index";
        if (round.equals("old")) {
            createTestRoleIfNotExists(TEST_ROLE);
            createUserIfNotExists(TEST_USER, TEST_PASSWORD, TEST_ROLE);
            createIndexIfNotExists(index);
        }
        ingestData(index);
        searchMatchAll(index);
    }

    public void testNodeStats() throws IOException {
        List<Response> responses = RestHelper.requestAgainstAllNodes(client(), "GET", "_nodes/stats", null);
        responses.forEach(r -> Assert.assertEquals(200, r.getStatusLine().getStatusCode()));
    }

    @SuppressWarnings("unchecked")
    private void assertPluginUpgrade(String uri) throws Exception {
        Map<String, Map<String, Object>> responseMap = (Map<String, Map<String, Object>>) getAsMap(uri).get("nodes");
        for (Map<String, Object> response : responseMap.values()) {
            List<Map<String, Object>> plugins = (List<Map<String, Object>>) response.get("plugins");
            Set<String> pluginNames = plugins.stream().map(map -> (String) map.get("name")).collect(Collectors.toSet());

            final Version minNodeVersion = minimumNodeVersion();

            if (minNodeVersion.major <= 1) {
                assertThat(pluginNames, hasItem("opensearch_security")); // With underscore seperator
            } else {
                assertThat(pluginNames, hasItem("opensearch-security")); // With dash seperator
            }
        }
    }

    /**
     * Ingests data into the test index
     * @param index index to ingest data into
     */

    private void ingestData(String index) throws IOException {
        StringBuilder bulkRequestBody = new StringBuilder();
        ObjectMapper objectMapper = new ObjectMapper();
        int numberOfRequests = Randomness.get().nextInt(10);
        while (numberOfRequests-- > 0) {
            for (int i = 0; i < Randomness.get().nextInt(100); i++) {
                Map<String, Map<String, String>> indexRequest = new HashMap<>();
                indexRequest.put("index", new HashMap<>() {
                    {
                        put("_index", index);
                    }
                });
                bulkRequestBody.append(objectMapper.writeValueAsString(indexRequest) + "\n");
                bulkRequestBody.append(objectMapper.writeValueAsString(Song.randomSong().asJson()) + "\n");
            }
            List<Response> responses = RestHelper.requestAgainstAllNodes(
                testUserRestClient,
                "POST",
                "_bulk?refresh=wait_for",
                RestHelper.toHttpEntity(bulkRequestBody.toString())
            );
            responses.forEach(r -> assertEquals(200, r.getStatusLine().getStatusCode()));
        }
    }

    /**
     * Runs a matchAll query against the test index
     * @param index index to search
     */
    private void searchMatchAll(String index) throws IOException {
        String matchAllQuery = "{\n" + "    \"query\": {\n" + "        \"match_all\": {}\n" + "    }\n" + "}";
        int numberOfRequests = Randomness.get().nextInt(10);
        while (numberOfRequests-- > 0) {
            List<Response> responses = RestHelper.requestAgainstAllNodes(
                testUserRestClient,
                "POST",
                index + "/_search",
                RestHelper.toHttpEntity(matchAllQuery)
            );
            responses.forEach(r -> assertEquals(200, r.getStatusLine().getStatusCode()));
        }
    }

    /**
     * Checks if a resource at the specified URL exists
     * @param url of the resource to be checked for existence
     * @return true if the resource exists, false otherwise
     */

    private boolean resourceExists(String url) throws IOException {
        try {
            RestHelper.get(adminClient(), url);
            return true;
        } catch (ResponseException e) {
            if (e.getResponse().getStatusLine().getStatusCode() == 404) {
                return false;
            } else {
                throw e;
            }
        }
    }

    /**
     * Creates a test role with DLS, FLS and masked field settings on the test index.
     */
    private void createTestRoleIfNotExists(String role) throws IOException {
        String url = "_plugins/_security/api/roles/" + role;
        String roleSettings = "{\n"
            + "  \"cluster_permissions\": [\n"
            + "    \"unlimited\"\n"
            + "  ],\n"
            + "  \"index_permissions\": [\n"
            + "    {\n"
            + "      \"index_patterns\": [\n"
            + "        \"test_index*\"\n"
            + "      ],\n"
            + "      \"dls\": \"{ \\\"bool\\\": { \\\"must\\\": { \\\"match\\\": { \\\"genre\\\": \\\"rock\\\" } } } }\",\n"
            + "      \"fls\": [\n"
            + "        \"~lyrics\"\n"
            + "      ],\n"
            + "      \"masked_fields\": [\n"
            + "        \"artist\"\n"
            + "      ],\n"
            + "      \"allowed_actions\": [\n"
            + "        \"read\",\n"
            + "        \"write\"\n"
            + "      ]\n"
            + "    }\n"
            + "  ],\n"
            + "  \"tenant_permissions\": []\n"
            + "}\n";
        Response response = RestHelper.makeRequest(adminClient(), "PUT", url, RestHelper.toHttpEntity(roleSettings));

        assertThat(response.getStatusLine().getStatusCode(), anyOf(equalTo(200), equalTo(201)));
    }

    /**
     * Creates a test index if it does not exist already
     * @param index index to create
     */

    private void createIndexIfNotExists(String index) throws IOException {
        String settings = "{\n"
            + "  \"settings\": {\n"
            + "    \"index\": {\n"
            + "      \"number_of_shards\": 3,\n"
            + "      \"number_of_replicas\": 1\n"
            + "    }\n"
            + "  }\n"
            + "}";
        if (!resourceExists(index)) {
            Response response = RestHelper.makeRequest(client(), "PUT", index, RestHelper.toHttpEntity(settings));
            assertThat(response.getStatusLine().getStatusCode(), equalTo(200));
        }
    }

    /**
     * Creates the test user if it does not exist already and maps it to the test role with DLS/FLS settings.
     * @param  user user to be created
     * @param  password password for the new user
     * @param  role roles that the user has to be mapped to
     */
    private void createUserIfNotExists(String user, String password, String role) throws IOException {
        String url = "_plugins/_security/api/internalusers/" + user;
        if (!resourceExists(url)) {
            String userSettings = String.format(
                Locale.ENGLISH,
                "{\n" + "  \"password\": \"%s\",\n" + "  \"opendistro_security_roles\": [\"%s\"],\n" + "  \"backend_roles\": []\n" + "}",
                password,
                role
            );
            Response response = RestHelper.makeRequest(adminClient(), "PUT", url, RestHelper.toHttpEntity(userSettings));
            assertThat(response.getStatusLine().getStatusCode(), equalTo(201));
        }
    }

    @AfterClass
    public static void cleanUp() throws IOException {
        OpenSearchRestTestCase.closeClients();
        IOUtils.close(testUserRestClient);
    }
}
