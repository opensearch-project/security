package org.opensearch.test.framework.cluster;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLContext;

import org.apache.hc.core5.http.Header;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.protobufs.SearchRequest;
import org.opensearch.protobufs.SearchResponse;
import org.opensearch.protobufs.services.SearchServiceGrpc;

import io.grpc.ChannelCredentials;
import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.TlsChannelCredentials;
import io.grpc.netty.shaded.io.netty.handler.ssl.util.InsecureTrustManagerFactory;

public class TestGrpcClient {
    private static final Logger log = LogManager.getLogger(TestRestClient.class);

    private InetSocketAddress nodeHttpAddress;
    private List<Header> headers = new ArrayList<>();
    private SSLContext sslContext;

    private final InetAddress sourceInetAddress;

    public TestGrpcClient(InetSocketAddress nodeHttpAddress, List<Header> headers, SSLContext sslContext, InetAddress sourceInetAddress) {
        this.nodeHttpAddress = nodeHttpAddress;
        this.headers.addAll(headers);
        this.sslContext = sslContext;
        this.sourceInetAddress = sourceInetAddress;
    }

    public SearchResponse search(SearchRequest request) {
        SearchServiceGrpc.SearchServiceBlockingStub client = client();
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
