package org.opensearch.security.filter;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLEngine;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.collect.Tuple;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.http.netty4.Netty4HttpChannel;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;

import io.netty.handler.ssl.SslHandler;

public class SecurityRequestFactory {

    public static SecurityRequestChannel from() {
        return null;
    }

    public static SecurityRequestChannel from(final RestRequest request, final RestChannel channel) {
        return new SecurityRestRequest(request, channel);
    }

    public static class SecurityRestRequest implements SecurityRequestChannel {

        private final Logger log = LogManager.getLogger(SecurityRestRequest.class);

        private AtomicBoolean hasCompleted = new AtomicBoolean(false);
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

        // @Override
        // public boolean sourcedFromNetty() {
        //     return underlyingRequest.getHttpChannel() instanceof Netty4HttpChannel;
        // }

        @Override
        public String uri() {
            return underlyingRequest.uri();
        }

        @Override
        public Map<String, String> params() {
            return underlyingRequest.params();
        }

        @Override
        public boolean hasCompleted() {
            return hasCompleted.get();
        }

        @Override
        public boolean completeWithResponse(int statusCode, Map<String, String> headers, String body) {
            try {
                final BytesRestResponse restResponse = new BytesRestResponse(RestStatus.fromCode(statusCode), body);
                headers.forEach(restResponse::addHeader);
                underlyingChannel.sendResponse(restResponse);
               
                return true;
            } catch (final Exception e) {
                log.error("Error when attempting to send response", e);
                throw new RuntimeException(e);
            } finally {
                hasCompleted.set(true);
            }
        }

        /**
         * Breaks the encapustion of the interface to get access to the underlying RestRequest / RestChannel.
         */
        public Tuple<RestRequest, RestChannel> breakEncapsulation() {
            return Tuple.tuple(underlyingRequest, underlyingChannel);
        }

        /** Marks a request completed */
        public void markCompleted() {
            hasCompleted.set(true);
        }
    }

    protected static class NettyRequest implements SecurityRequestChannel {
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
        public String path() {
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
        public String uri() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'uri'");
        }

        @Override
        public Map<String, String> params() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'params'");
        }

        @Override
        public boolean hasCompleted() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'hasCompleted'");
        }

        @Override
        public boolean completeWithResponse(int statusCode, Map<String, String> headers, String body) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'completeWithResponse'");
        }
    }
}
