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

package org.opensearch.security.dlsfls;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Stream;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.http.HttpStatus;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.security.grpc.GrpcHelpers;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.opensearch.security.grpc.GrpcHelpers.SECURITY_WITH_GRPC_PLUGIN;
import static org.opensearch.security.grpc.GrpcHelpers.createChannelWithBasicAuthorization;
import static org.opensearch.security.grpc.GrpcHelpers.createHeaderInterceptor;
import static org.opensearch.security.grpc.GrpcHelpers.getSecureGrpcEndpoint;
import static org.opensearch.security.grpc.GrpcHelpers.secureChannel;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

public class HeaderAttrInDlsIntegrationTest {
    private static final String DLS_INDEX = "testindex";

    private static final String DLS_INDEX_SETTINGS = """
        {
          "mappings": {
            "properties": {
              "testfield": {
                "type": "text"
              }
            }
          }
        }""";
    private static final String SINGLE_VALUE_DLS_QUERY = "{ \"term\": { \"testfield\": \"${attr.header.x-example-header}\" } }";
    private static final String MULTI_VALUE_DLS_QUERY = "{ \"terms\": { \"testfield\": [${attr.header.x-example-header-mv}] } }";
    private static final String SHORT_VALUE_DLS_QUERY = "{ \"term\": { \"testfield\": \"${attr.header.x-short-header}\" } }";

    static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    static final TestSecurityConfig.User SINGLE_VALUE_DLS_USER = new TestSecurityConfig.User("sv_dls_user").roles(
        new TestSecurityConfig.Role("sv_dls_role").clusterPermissions("*").indexPermissions("*").dls(SINGLE_VALUE_DLS_QUERY).on(DLS_INDEX)
    );

    static final TestSecurityConfig.User MULTI_VALUE_DLS_USER = new TestSecurityConfig.User("mv_dls_user").roles(
        new TestSecurityConfig.Role("mv_dls_role").clusterPermissions("*").indexPermissions("*").dls(MULTI_VALUE_DLS_QUERY).on(DLS_INDEX)
    );

    static final TestSecurityConfig.User SHORT_VALUE_DLS_USER = new TestSecurityConfig.User("short_dls_user").roles(
        new TestSecurityConfig.Role("short_dls_role").clusterPermissions("*").indexPermissions("*").dls(SHORT_VALUE_DLS_QUERY).on(DLS_INDEX)
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.DEFAULT)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, SINGLE_VALUE_DLS_USER, MULTI_VALUE_DLS_USER, SHORT_VALUE_DLS_USER)
        .nodeSetting("plugins.security.unsupported.dls.allowed_request_headers.x-example-header.name", "X-Example-Header")
        .nodeSetting("plugins.security.unsupported.dls.allowed_request_headers.x-example-header.isMultiValue", "false")
        .nodeSetting("plugins.security.unsupported.dls.allowed_request_headers.x-example-header.validationRegex", "[a-z\\-]+")
        .nodeSetting("plugins.security.unsupported.dls.allowed_request_headers.x-example-header-mv.name", "X-Example-Header-MV")
        .nodeSetting("plugins.security.unsupported.dls.allowed_request_headers.x-example-header-mv.isMultiValue", "true")
        .nodeSetting("plugins.security.unsupported.dls.allowed_request_headers.x-example-header-mv.validationRegex", "[a-z\\-]+")
        .nodeSetting("plugins.security.unsupported.dls.allowed_request_headers.x-invalid-header.name", "X-Invalid-Header")
        .nodeSetting("plugins.security.unsupported.dls.allowed_request_headers.x-short-header.name", "X-Short-Header")
        .nodeSetting("plugins.security.unsupported.dls.allowed_request_headers.x-short-header.validationRegex", "[a-z\\-]+")
        .nodeSetting("plugins.security.unsupported.dls.allowed_request_headers.x-short-header.maxValueLength", "3")
        .nodeSettings(GrpcHelpers.SINGLE_NODE_SECURE_AUTH_GRPC_TRANSPORT_SETTINGS)
        .nodeSettings(GrpcHelpers.CLIENT_AUTH_REQUIRE)
        .plugin(SECURITY_WITH_GRPC_PLUGIN)
        .build();

    @BeforeClass
    public static void createTestData() {
        try (final var client = cluster.getRestClient(ADMIN_USER)) {
            client.putJson(DLS_INDEX, DLS_INDEX_SETTINGS);
            client.postJson(DLS_INDEX + "/_doc?refresh=true", "{\"testfield\": \"foobar\"}");
            client.postJson(DLS_INDEX + "/_doc?refresh=true", "{\"testfield\": \"foo\"}");
            client.postJson(DLS_INDEX + "/_doc?refresh=true", "{\"testfield\": \"baz\"}");
        }
    }

    @Test
    public void testQueryWithSingleValueHeaderMatches() {
        assertThat(runSearchAndGetTotalHitsForSingleValueHeader("foobar"), is(1));
        assertThat(runSearchAndGetTotalHitsForSingleValueHeader("does-not-exist"), is(0));
    }

    @Test
    public void testQueryWithMultiValueHeaderMatches() {
        assertThat(runSearchAndGetTotalHitsForMultiValueHeader("foobar"), is(1));
        assertThat(runSearchAndGetTotalHitsForMultiValueHeader("does-not-exist"), is(0));
        assertThat(runSearchAndGetTotalHitsForMultiValueHeader("foobar", "foo"), is(2));
    }

    @Test
    public void testFailureOnValueNotMatchingRegex() {
        try (final var client = cluster.getRestClient(SINGLE_VALUE_DLS_USER)) {
            final var response = client.get(DLS_INDEX + "/_search", new BasicHeader("X-Example-Header", "UPPERCASE-IS-INVALID"));
            assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        }
    }

    @Test
    public void testFailureOnUndefinedRegex() {
        try (final var client = cluster.getRestClient(SINGLE_VALUE_DLS_USER)) {
            final var response = client.get(DLS_INDEX + "/_search", new BasicHeader("X-Invalid-Header", "nothing matches here"));
            assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        }
    }

    @Test
    public void testLengthLimit() {
        // short works
        runSearchAndGetTotalHits(SHORT_VALUE_DLS_USER, new BasicHeader("X-Short-Header", "foo"));
        // exceeding the limit fails it
        try (final var client = cluster.getRestClient(SHORT_VALUE_DLS_USER)) {
            final var response = client.get(DLS_INDEX + "/_search", new BasicHeader("X-Short-Header", "foobar"));
            assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        }
    }

    @Test
    public void testFailureOnMultipleValuesOnSingleValueConfig() {
        try (final var client = cluster.getRestClient(SINGLE_VALUE_DLS_USER)) {
            final var response = client.get(
                DLS_INDEX + "/_search",
                new BasicHeader("X-Example-Header", "a"),
                new BasicHeader("X-Example-Header", "b")
            );
            assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        }
    }

    @Test
    public void testFailureOnTooManyHeadersOverall() {
        try (final var client = cluster.getRestClient(MULTI_VALUE_DLS_USER)) {
            final var headers = Stream.iterate(new BasicHeader("X-Example-Header-MV", "a"), h -> h).limit(257).toArray(Header[]::new);
            final var response = client.get(DLS_INDEX + "/_search", headers);
            assertThat(response.getStatusCode(), is(HttpStatus.SC_BAD_REQUEST));
        }
    }

    @Test
    public void testGrpcChannel() throws Exception {
        final var channel = secureChannel(getSecureGrpcEndpoint(cluster));
        try {
            final var channelWithAuth = createChannelWithBasicAuthorization(
                channel,
                SINGLE_VALUE_DLS_USER.getName(),
                SINGLE_VALUE_DLS_USER.getPassword()
            );
            final var authInterceptor = createHeaderInterceptor(Map.of("X-Example-Header", "foobar"));
            final var channelWithHeader = io.grpc.ClientInterceptors.intercept(channelWithAuth, authInterceptor);

            final var searchResp = GrpcHelpers.doMatchAll(channelWithHeader, DLS_INDEX, 10);
            assertThat(searchResp, notNullValue());
            assertThat(searchResp.getHits().getTotal().getTotalHits().getValue(), is(1L));
        } finally {
            channel.shutdown();
        }
    }

    int runSearchAndGetTotalHitsForSingleValueHeader(final String headerValue) {
        return runSearchAndGetTotalHits(SINGLE_VALUE_DLS_USER, new BasicHeader("X-Example-Header", headerValue));
    }

    int runSearchAndGetTotalHitsForMultiValueHeader(final String... headerValues) {
        final var headers = Arrays.stream(headerValues).map(s -> new BasicHeader("X-Example-Header-MV", s)).toArray(Header[]::new);
        return runSearchAndGetTotalHits(MULTI_VALUE_DLS_USER, headers);
    }

    int runSearchAndGetTotalHits(final TestSecurityConfig.User user, final Header... headers) {
        try (final var client = cluster.getRestClient(user)) {
            final var response = client.get(DLS_INDEX + "/_search", headers);
            assertThat(response.getStatusCode(), is(HttpStatus.SC_OK));
            return response.getIntFromJsonBody("/hits/total/value");
        }
    }
}
