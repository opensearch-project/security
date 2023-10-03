package org.opensearch.security.filter;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.net.ssl.SSLEngine;

import org.opensearch.http.netty4.Netty4HttpChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;

import io.netty.handler.ssl.SslHandler;

public class OpenSearchRequest implements SecurityRequest {

    protected final RestRequest underlyingRequest;

    OpenSearchRequest(final RestRequest request) {
        underlyingRequest = request;
    }

    @Override
    public Map<String, List<String>> getHeaders() {
        return underlyingRequest.getHeaders();
    }

    @Override
    public SSLEngine getSSLEngine() {
        if (underlyingRequest == null
            || underlyingRequest.getHttpChannel() == null
            || !(underlyingRequest.getHttpChannel() instanceof Netty4HttpChannel)) {
            return null;
        }

        final Netty4HttpChannel httpChannel = (Netty4HttpChannel) underlyingRequest.getHttpChannel();
        SslHandler sslhandler = (SslHandler) httpChannel.getNettyChannel().pipeline().get("ssl_http");
        if (sslhandler == null && httpChannel.inboundPipeline() != null) {
            sslhandler = (SslHandler) httpChannel.inboundPipeline().get("ssl_http");
        }

        return sslhandler != null ? sslhandler.engine() : null;
    }

    @Override
    public String path() {
        return underlyingRequest.path();
    }

    @Override
    public Method method() {
        return underlyingRequest.method();
    }

    @Override
    public Optional<InetSocketAddress> getRemoteAddress() {
        return Optional.ofNullable(this.underlyingRequest.getHttpChannel().getRemoteAddress());
    }

    @Override
    public String uri() {
        return underlyingRequest.uri();
    }

    @Override
    public Map<String, String> params() {
        return underlyingRequest.params();
    }

    public RestRequest breakEncapsulationForRequest() {
        return underlyingRequest;
    }
}
