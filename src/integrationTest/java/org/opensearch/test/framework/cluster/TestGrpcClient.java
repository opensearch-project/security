package org.opensearch.test.framework.cluster;

import java.net.InetSocketAddress;
import javax.net.ssl.SSLContext;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.protobufs.SearchRequest;
import org.opensearch.protobufs.SearchResponse;
import org.opensearch.protobufs.services.SearchServiceGrpc;

import io.grpc.ChannelCredentials;
import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.TlsChannelCredentials;
import io.grpc.netty.shaded.io.netty.handler.ssl.util.InsecureTrustManagerFactory;

public class TestGrpcClient {
    private static final Logger log = LogManager.getLogger(TestRestClient.class);

    Metadata.Key<String> AUTHORIZATION_KEY = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);

    private InetSocketAddress nodeHttpAddress;
    private String authorizationHeader;
    private SSLContext sslContext;

    public TestGrpcClient(InetSocketAddress nodeHttpAddress, String authorizationHeader, SSLContext sslContext) {
        this.nodeHttpAddress = nodeHttpAddress;
        this.authorizationHeader = authorizationHeader;
        this.sslContext = sslContext;
    }

    public SearchResponse search(SearchRequest request) {
        SearchServiceGrpc.SearchServiceBlockingStub client = client();
        Metadata md = new Metadata();

        md.put(AUTHORIZATION_KEY, authorizationHeader);
        // client = MetadataUtils.attachHeaders(client, md);
        return client.search(request);
    }

    private SearchServiceGrpc.SearchServiceBlockingStub client() {
        ChannelCredentials credentials = TlsChannelCredentials.newBuilder()
            // You can use your own certificate here .trustManager(new File("cert.pem"))
            .trustManager(InsecureTrustManagerFactory.INSTANCE.getTrustManagers())
            .build();
        ManagedChannel channel = Grpc.newChannelBuilderForAddress(nodeHttpAddress.getHostString(), nodeHttpAddress.getPort(), credentials)
            .build();
        return SearchServiceGrpc.newBlockingStub(channel);
    }
}
