package org.opensearch.security.filter;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.net.ssl.SSLEngine;

import org.opensearch.http.netty4.Netty4HttpChannel;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;

import io.netty.handler.codec.http.HttpRequest;

public class SecurityRequestFactory {

    public static SecurityRequest from() {
        return null;
    }

    public static SecurityRequest from(final RestRequest request, final RestChannel channel) {
        return new SecurityRestRequest(request, channel);
    }

    protected static class SecurityRestRequest implements SecurityRequest {
        private final RestRequest underlyingRequest;
        private final RestChannel underlyingChannel;
        SecurityRestRequest(final RestRequest request, final RestChannel channel) {
            underlyingRequest = request;
            underlyingChannel = channel;
        }

        @Override
        public Map<String, List<String>> getHeaders() {
            return underlyingRequest.getHeaders();
        }

        @Override
        public SSLEngine getSSLEngine() {
            // TODO: this doesn't seem properly handled

            throw new UnsupportedOperationException("Unimplemented method 'getSSLEngine'");
        }

        @Override
        public RestChannel getRestChannel() {
            return underlyingChannel;
        }

        @Override
        public CharSequence path() {
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
        public boolean sourcedFromNetty() {
            return underlyingRequest.getHttpChannel() instanceof Netty4HttpChannel;
        }

        @Override
        public String uri() {
            return underlyingRequest.uri();
        }

        @Override
        public Optional<RestRequest> asRestRequest() {
            return Optional.of(underlyingRequest);
        }

        @Override
        public boolean paramAsBoolean(String string, boolean b) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'paramAsBoolean'");
        }

        @Override
        public String param(String jwtUrlParameter) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'param'");
        }
    }


    protected static class NettyRequest implements SecurityRequest {
        @Override
        public Map<String, List<String>> getHeaders() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'getHeaders'");
        }

        @Override
        public SSLEngine getSSLEngine() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'getSSLEngine'");
        }

        @Override
        public RestChannel getRestChannel() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'getRestChannel'");
        }

        @Override
        public CharSequence path() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'path'");
        }

        @Override
        public Method method() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'method'");
        }

        @Override
        public Optional<InetSocketAddress> getRemoteAddress() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'getRemoteAddress'");
        }

        @Override
        public boolean sourcedFromNetty() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'sourcedFromNetty'");
        }

        @Override
        public String uri() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'uri'");
        }

        @Override
        public Optional<RestRequest> asRestRequest() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'asRestRequest'");
        }

        @Override
        public boolean paramAsBoolean(String string, boolean b) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'paramAsBoolean'");
        }

        @Override
        public String param(String jwtUrlParameter) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'param'");
        }

    }
}
