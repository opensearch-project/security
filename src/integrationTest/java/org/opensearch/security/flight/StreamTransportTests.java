/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.flight;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.apache.arrow.flight.CallHeaders;
import org.apache.arrow.flight.FlightCallHeaders;
import org.apache.arrow.flight.FlightClient;
import org.apache.arrow.flight.FlightRuntimeException;
import org.apache.arrow.flight.FlightStream;
import org.apache.arrow.flight.HeaderCallOption;
import org.apache.arrow.flight.Location;
import org.apache.arrow.flight.Ticket;
import org.apache.arrow.memory.ArrowBuf;
import org.apache.arrow.memory.BufferAllocator;
import org.apache.arrow.memory.RootAllocator;
import org.apache.arrow.vector.FieldVector;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.Version;
import org.opensearch.action.OriginalIndices;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchTransportService;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.arrow.allocator.ArrowBasePlugin;
import org.opensearch.arrow.flight.transport.FlightStreamPlugin;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.index.Index;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.internal.AliasFilter;
import org.opensearch.search.internal.ShardSearchRequest;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.certificate.CertificateData;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.nativeprotocol.RawTransportRequestSerializer;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Exercises the Arrow Flight stream transport with the security plugin installed, mirroring the netty transport behaviour.
 */
public class StreamTransportTests {

    private static final String INDEX = "flight-docs";
    private static final String MARKER = "flight-doc-marker";

    private static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS);
    private static final User MONITOR_USER = new User("monitor").roles(
        new Role("cluster_monitor_only").clusterPermissions("cluster_monitor")
    );

    private static final String STREAMING_SEARCH = "{\"size\":1,\"aggs\":{\"values\":{\"terms\":{\"field\":\"value.keyword\"}}}}";

    private static final TestCertificates TEST_CERTIFICATES = new TestCertificates();
    private static final int FLIGHT_PORT = freePort();

    private static final PluginInfo[] PLUGINS = {
        classpathPlugin(ArrowBasePlugin.class.getName(), List.of()),
        classpathPlugin(FlightStreamPlugin.class.getName(), List.of(ArrowBasePlugin.class.getName())),
        classpathPlugin(OpenSearchSecurityPlugin.class.getName(), List.of()) };

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .certificates(TEST_CERTIFICATES)
        .plugin(PLUGINS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, MONITOR_USER)
        .nodeSettings(
            Map.of(
                "opensearch.experimental.feature.transport.stream.enabled",
                true,
                "transport.stream.type.default",
                "FLIGHT-SECURE",
                "flight.ssl.enable",
                true,
                "aux.transport.transport-flight.port",
                String.valueOf(FLIGHT_PORT),
                "arrow.flight.bind_host",
                "127.0.0.1",
                "arrow.flight.publish_host",
                "127.0.0.1",
                "stream.search.enabled",
                true
            )
        )
        .build();

    private static Index index;

    @BeforeClass
    public static void indexDocument() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.prepareIndex(INDEX)
                .setId("1")
                .setSource(Map.of("value", MARKER), XContentType.JSON)
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .get();
            index = client.admin().cluster().prepareState().get().getState().metadata().index(INDEX).getIndex();
        }
    }

    @Test
    public void shardRequestFromNonNodePeerIsRejected() throws Exception {
        CertificateData userCertificate = TEST_CERTIFICATES.issueUserCertificate("flight", "client");

        FlightRuntimeException exception = assertThrows(FlightRuntimeException.class, () -> shardQueryOverFlight(userCertificate));
        assertThat(exception.getMessage(), containsString("not allowed from a non-server node"));
    }

    @Test
    public void shardRequestFromNodePeerIsAccepted() throws Exception {
        assertTrue(shardQueryOverFlight(TEST_CERTIFICATES.getNodeCertificateData(0)).contains(MARKER));
    }

    @Test
    public void streamSearchReturnsResults() {
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            TestRestClient.HttpResponse response = client.postJson(INDEX + "/_search", STREAMING_SEARCH);
            response.assertStatusCode(200);
            assertThat(response.getBody(), containsString(MARKER));
        }
    }

    @Test
    public void streamSearchRequiresIndexPermissions() {
        try (TestRestClient client = cluster.getRestClient(MONITOR_USER)) {
            client.postJson(INDEX + "/_search", STREAMING_SEARCH).assertStatusCode(403);
        }
    }

    /**
     * Sends a single-shard query phase request to the Flight port and returns the response bytes decoded as ISO-8859-1.
     */
    private static String shardQueryOverFlight(CertificateData clientCertificate) throws Exception {
        SearchRequest searchRequest = new SearchRequest(INDEX).source(new SearchSourceBuilder()).allowPartialSearchResults(false);
        ShardSearchRequest shardRequest = new ShardSearchRequest(
            new OriginalIndices(searchRequest),
            searchRequest,
            new ShardId(index, 0),
            1,
            new AliasFilter(null, new String[0]),
            1.0f,
            System.currentTimeMillis(),
            null,
            new String[0]
        );
        Ticket ticket = new Ticket(RawTransportRequestSerializer.serialize(SearchTransportService.QUERY_ACTION_NAME, shardRequest, 1));

        CallHeaders headers = new FlightCallHeaders();
        headers.insert("correlation-id", "1");

        StringBuilder response = new StringBuilder();
        try (
            BufferAllocator allocator = new RootAllocator();
            FlightClient client = FlightClient.builder()
                .allocator(allocator)
                .location(Location.forGrpcTls(InetAddress.getLoopbackAddress().getHostAddress(), FLIGHT_PORT))
                .useTls()
                .trustedCertificates(pem(TEST_CERTIFICATES.getRootCertificateData().certificateInPemFormat()))
                .clientCertificate(pem(clientCertificate.certificateInPemFormat()), pem(clientCertificate.privateKeyInPemFormat(null)))
                .build();
            FlightStream stream = client.getStream(ticket, new HeaderCallOption(headers))
        ) {
            while (stream.next()) {
                for (FieldVector vector : stream.getRoot().getFieldVectors()) {
                    for (ArrowBuf buffer : vector.getFieldBuffers()) {
                        byte[] bytes = new byte[(int) buffer.readableBytes()];
                        buffer.getBytes(0, bytes);
                        response.append(new String(bytes, StandardCharsets.ISO_8859_1));
                    }
                }
            }
        }
        return response.toString();
    }

    private static ByteArrayInputStream pem(String pem) {
        return new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII));
    }

    private static PluginInfo classpathPlugin(String className, List<String> extendedPlugins) {
        return new PluginInfo(className, "classpath plugin", "NA", Version.CURRENT, "21", className, null, extendedPlugins, false);
    }

    private static int freePort() {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
