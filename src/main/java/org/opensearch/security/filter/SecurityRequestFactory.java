package org.opensearch.security.filter;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.net.ssl.SSLEngine;

import org.opensearch.http.netty4.Netty4HttpChannel;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;

import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.ssl.SslHandler;

public class SecurityRequestFactory {

    public static SecurityRequest from(final HttpRequest request) {
        return new SecurityNettyRequest(request);
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

        // @Override
        // public RestChannel getRestChannel() {
        //     return underlyingChannel;
        // }

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
        public Map<String, String> params() {
            return underlyingRequest.params();
        }
    }

    protected static class SecurityNettyRequest implements SecurityRequest {
        private final HttpRequest underlyingRequset;

        protected SecurityNettyRequest(final HttpRequest request) {
            underlyingRequset = request;
        }

        @Override
        public Map<String, List<String>> getHeaders() {
            final Map<String,List<String>> headerMap = new HashMap<>();
            underlyingRequset.headers().forEach(entry -> headerMap.put(entry.getKey(), List.of(entry.getValue())));
            return headerMap;
        }

        @Override
        public SSLEngine getSSLEngine() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'getSSLEngine'");
        }

        // @Override
        // public RestChannel getRestChannel() {
        //     // TODO Auto-generated method stub
        //     throw new UnsupportedOperationException("Unimplemented method 'getRestChannel'");
        // }

        @Override
        public String path() {
            return underlyingRequset.uri();
        }

        @Override
        public Method method() {
            if (underlyingRequset.method() == HttpMethod.CONNECT) {
                return Method.CONNECT;
            } else if (underlyingRequset.method() == HttpMethod.DELETE) {
                return Method.DELETE;
            } else if (underlyingRequset.method() == HttpMethod.GET) {
                return Method.GET;
            } else if (underlyingRequset.method() == HttpMethod.HEAD) {
                return Method.HEAD;
            } else if (underlyingRequset.method() == HttpMethod.OPTIONS) {
                return Method.OPTIONS;
            } else if (underlyingRequset.method() == HttpMethod.PATCH) {
                return Method.PATCH;
            } else if (underlyingRequset.method() == HttpMethod.POST) {
                return Method.POST;
            } else if (underlyingRequset.method() == HttpMethod.PUT) {
                return Method.PUT;
            } else if (underlyingRequset.method() == HttpMethod.TRACE) {
                return Method.TRACE;
            }
            return null;
        }

        @Override
        public Optional<InetSocketAddress> getRemoteAddress() {
            return Optional.empty();
        }

        @Override
        public boolean sourcedFromNetty() {
            return true;
        }

        @Override
        public String uri() {
            return underlyingRequset.uri();
        }

        @Override
        public Optional<RestRequest> asRestRequest() {
            return Optional.empty();
        }

        @Override
        public Map<String, String> params() {
            //TODO: Support this?
            return null;
        }
    }
}
