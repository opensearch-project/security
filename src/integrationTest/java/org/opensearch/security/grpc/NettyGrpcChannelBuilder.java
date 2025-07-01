package org.opensearch.security.grpc;

import javax.net.ssl.SSLException;
import java.io.File;

import io.netty.handler.ssl.ClientAuth;

import io.grpc.ManagedChannel;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.ApplicationProtocolConfig;
import io.grpc.netty.shaded.io.netty.handler.ssl.ApplicationProtocolNames;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContextBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslProvider;
import io.grpc.netty.shaded.io.netty.handler.ssl.util.InsecureTrustManagerFactory;

import org.opensearch.core.common.transport.TransportAddress;

import static io.grpc.internal.GrpcUtil.NOOP_PROXY_DETECTOR;

public class NettyGrpcChannelBuilder {
    private ClientAuth clientAuth = null;
    private TransportAddress addr;
    SslContextBuilder sslContextBuilder = null;

    private static final ApplicationProtocolConfig CLIENT_ALPN = new ApplicationProtocolConfig(
            ApplicationProtocolConfig.Protocol.ALPN,
            ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
            ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
            ApplicationProtocolNames.HTTP_2
    );

    NettyGrpcChannelBuilder() {
        // Default options required for gRPC clients
        this.sslContextBuilder = SslContextBuilder.forClient()
            .sslProvider(SslProvider.JDK)
            .applicationProtocolConfig(CLIENT_ALPN)
            .trustManager(InsecureTrustManagerFactory.INSTANCE);
    }

    public ManagedChannel build() throws SSLException {
        NettyChannelBuilder channelBuilder = NettyChannelBuilder
                .forAddress(addr.getAddress(), addr.getPort())
                .proxyDetector(NOOP_PROXY_DETECTOR);

        if (clientAuth == null) {
            return channelBuilder.usePlaintext().build();
        }

        switch (clientAuth) {
            case ClientAuth.NONE -> channelBuilder.usePlaintext();
            case ClientAuth.OPTIONAL, ClientAuth.REQUIRE ->
                channelBuilder.sslContext(this.sslContextBuilder.build());
        }

        return channelBuilder.build();
    }

    /**
     * Set server address.
     */
    public NettyGrpcChannelBuilder setAddress(TransportAddress addr) {
        this.addr = addr;
        return this;
    }

    /**
     * Configure key store by filepath of .pem key.
     * Required for mTLS/client auth required configurations.
     */
    public NettyGrpcChannelBuilder keyManager(String privateKeyPath, String certChainPath) {
        this.sslContextBuilder.keyManager(new File(certChainPath), new File(privateKeyPath));
        return this;
    }

    /**
     * Set client auth mode.
     * No client auth set gives plaintext connection.
     */
    public NettyGrpcChannelBuilder clientAuth(ClientAuth clientAuth) {
        this.clientAuth = clientAuth;
        return this;
    }
}
