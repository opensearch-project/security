/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.grpc;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.opensearch.common.transport.PortsRange;
import org.opensearch.core.common.transport.TransportAddress;
import org.opensearch.plugin.transport.grpc.ssl.SecureNetty4GrpcServerTransport;
import org.opensearch.protobufs.BulkRequest;
import org.opensearch.protobufs.BulkRequestBody;
import org.opensearch.protobufs.BulkResponse;
import org.opensearch.protobufs.IndexOperation;
import org.opensearch.protobufs.MatchAllQuery;
import org.opensearch.protobufs.QueryContainer;
import org.opensearch.protobufs.Refresh;
import org.opensearch.protobufs.SearchRequest;
import org.opensearch.protobufs.SearchRequestBody;
import org.opensearch.protobufs.SearchResponse;
import org.opensearch.protobufs.services.DocumentServiceGrpc;
import org.opensearch.protobufs.services.SearchServiceGrpc;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.certificate.TestCertificates;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.LocalOpenSearchCluster;

import io.grpc.ChannelCredentials;
import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.TlsChannelCredentials;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

import static org.opensearch.plugin.transport.grpc.ssl.SecureNetty4GrpcServerTransport.GRPC_SECURE_TRANSPORT_SETTING_KEY;
import static org.opensearch.plugin.transport.grpc.ssl.SecureNetty4GrpcServerTransport.SETTING_GRPC_SECURE_PORT;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_CLIENTAUTH_MODE;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_ENABLED;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_PEMCERT_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_PEMKEY_FILEPATH;
import static org.opensearch.security.ssl.util.SSLConfigConstants.SECURITY_SSL_AUX_PEMTRUSTEDCAS_FILEPATH;
import static org.opensearch.transport.AuxTransport.AUX_TRANSPORT_TYPES_KEY;
import static com.carrotsearch.randomizedtesting.RandomizedTest.randomFrom;
import static io.grpc.internal.GrpcUtil.NOOP_PROXY_DETECTOR;

public class GrpcHelpers {
    protected static final TestCertificates TEST_CERTIFICATES = new TestCertificates();
    protected static final TestCertificates UN_TRUSTED_TEST_CERTIFICATES = new TestCertificates();
    protected static final Map<String, Object> CLIENT_AUTH_NONE = Map.of(
        SECURITY_SSL_AUX_CLIENTAUTH_MODE.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(),
        ClientAuth.NONE.name()
    );
    protected static final Map<String, Object> CLIENT_AUTH_OPT = Map.of(
        SECURITY_SSL_AUX_CLIENTAUTH_MODE.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(),
        ClientAuth.OPTIONAL.name()
    );
    protected static final Map<String, Object> CLIENT_AUTH_REQUIRE = Map.of(
        SECURITY_SSL_AUX_CLIENTAUTH_MODE.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(),
        ClientAuth.REQUIRE.name()
    );

    private static final PortsRange PORTS_RANGE = new PortsRange("9400-9500");

    public static final Map<String, Object> SINGLE_NODE_SECURE_GRPC_TRANSPORT_SETTINGS = Map.of(
        ConfigConstants.SECURITY_SSL_ONLY,
        true,
        AUX_TRANSPORT_TYPES_KEY,
        GRPC_SECURE_TRANSPORT_SETTING_KEY,
        SETTING_GRPC_SECURE_PORT.getKey(),
        PORTS_RANGE.getPortRangeString(),
        SECURITY_SSL_AUX_ENABLED.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(),
        true,
        SECURITY_SSL_AUX_PEMKEY_FILEPATH.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(),
        TEST_CERTIFICATES.getNodeKey(0, null).getAbsolutePath(),
        SECURITY_SSL_AUX_PEMCERT_FILEPATH.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(),
        TEST_CERTIFICATES.getNodeCertificate(0).getAbsolutePath(),
        SECURITY_SSL_AUX_PEMTRUSTEDCAS_FILEPATH.getConcreteSettingForNamespace(GRPC_SECURE_TRANSPORT_SETTING_KEY).getKey(),
        TEST_CERTIFICATES.getRootCertificate().getAbsolutePath()
    );

    public static TransportAddress getSecureGrpcEndpoint(LocalCluster cluster) {
        List<TransportAddress> transportAddresses = new ArrayList<>();
        List<LocalOpenSearchCluster.Node> nodeList = cluster.nodes();
        for (LocalOpenSearchCluster.Node node : nodeList) {
            TransportAddress boundAddress = new TransportAddress(
                node.getInjectable(SecureNetty4GrpcServerTransport.class).getBoundAddress().publishAddress().address()
            );
            transportAddresses.add(boundAddress);
        }
        return randomFrom(transportAddresses);
    }

    /*
    Plaintext connection.
    No encryption in transit.
    */
    public static ManagedChannel plaintextChannel(TransportAddress addr) {
        return NettyChannelBuilder.forAddress(addr.getAddress(), addr.getPort()).proxyDetector(NOOP_PROXY_DETECTOR).usePlaintext().build();
    }

    /*
    TLS with no client certificate.
    */
    public static ManagedChannel insecureChannel(TransportAddress addr) {
        ChannelCredentials credentials = TlsChannelCredentials.newBuilder()
            .trustManager(InsecureTrustManagerFactory.INSTANCE.getTrustManagers())
            .build();
        return Grpc.newChannelBuilderForAddress(addr.address().getHostName(), addr.getPort(), credentials).build();
    }

    /*
    TLS with client certificate trusted by server.
    */
    public static ManagedChannel secureChannel(TransportAddress addr) throws IOException {
        ChannelCredentials credentials = TlsChannelCredentials.newBuilder()
            .keyManager(TEST_CERTIFICATES.getNodeCertificate(0), TEST_CERTIFICATES.getNodeKey(0, null))
            .trustManager(InsecureTrustManagerFactory.INSTANCE.getTrustManagers())
            .build();
        return Grpc.newChannelBuilderForAddress(addr.address().getHostName(), addr.getPort(), credentials).build();
    }

    /*
    TLS with client certificate not trusted by server.
    */
    public static ManagedChannel secureUntrustedChannel(TransportAddress addr) throws IOException {
        ChannelCredentials credentials = TlsChannelCredentials.newBuilder()
            .keyManager(UN_TRUSTED_TEST_CERTIFICATES.getNodeCertificate(0), UN_TRUSTED_TEST_CERTIFICATES.getNodeKey(0, null))
            .trustManager(InsecureTrustManagerFactory.INSTANCE.getTrustManagers())
            .build();
        return Grpc.newChannelBuilderForAddress(addr.address().getHostName(), addr.getPort(), credentials).build();
    }

    public static BulkResponse doBulk(ManagedChannel channel, String index, long numDocs) {
        BulkRequest.Builder requestBuilder = BulkRequest.newBuilder().setRefresh(Refresh.REFRESH_TRUE);
        for (int i = 0; i < numDocs; i++) {
            String docBody = """
                {
                    "field": "doc %d body"
                }
                """.formatted(i);
            IndexOperation indexOp = IndexOperation.newBuilder().setIndex(index).setId(String.valueOf(i)).build();
            BulkRequestBody requestBody = BulkRequestBody.newBuilder()
                .setIndex(indexOp)
                .setDoc(com.google.protobuf.ByteString.copyFromUtf8(docBody))
                .build();
            requestBuilder.addRequestBody(requestBody);
        }
        DocumentServiceGrpc.DocumentServiceBlockingStub stub = DocumentServiceGrpc.newBlockingStub(channel);
        return stub.bulk(requestBuilder.build());
    }

    public static SearchResponse doMatchAll(ManagedChannel channel, String index, int size) {
        QueryContainer query = QueryContainer.newBuilder().setMatchAll(MatchAllQuery.newBuilder().build()).build();
        SearchRequestBody requestBody = SearchRequestBody.newBuilder().setSize(size).setQuery(query).build();
        SearchRequest searchRequest = SearchRequest.newBuilder().addIndex(index).setRequestBody(requestBody).build();
        SearchServiceGrpc.SearchServiceBlockingStub stub = SearchServiceGrpc.newBlockingStub(channel);
        return stub.search(searchRequest);
    }
}
