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

package org.opensearch.security.filter;

import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

import javax.net.ssl.SSLEngine;

import io.netty.handler.ssl.SslHandler;
import org.opensearch.http.netty4.Netty4HttpChannel;
import org.opensearch.rest.RestRequest.Method;

import io.netty.handler.codec.http.HttpRequest;
import org.opensearch.rest.RestUtils;

/**
 * Wraps the functionality of HttpRequest for use in the security plugin
 */
public class NettyRequest implements SecurityRequest {

    protected final HttpRequest underlyingRequest;
    protected final Netty4HttpChannel underlyingChannel;

    NettyRequest(final HttpRequest request, final Netty4HttpChannel channel) {
        this.underlyingRequest = request;
        this.underlyingChannel = channel;
    }

    @Override
    public Map<String, List<String>> getHeaders() {
        final Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        underlyingRequest.headers().forEach(h -> headers.put(h.getKey(), List.of(h.getValue())));
        return headers;
    }

    @Override
    public SSLEngine getSSLEngine() {
        // We look for Ssl_handler called `ssl_http` in the outbound pipeline of Netty channel first, and if its not
        // present we look for it in inbound channel. If its present in neither we return null, else we return the sslHandler.
        SslHandler sslhandler = (SslHandler) underlyingChannel.getNettyChannel().pipeline().get("ssl_http");
        if (sslhandler == null && underlyingChannel.inboundPipeline() != null) {
            sslhandler = (SslHandler) underlyingChannel.inboundPipeline().get("ssl_http");
        }

        return sslhandler != null ? sslhandler.engine() : null;
    }

    @Override
    public String path() {
        try {
            return new URL(underlyingRequest.uri()).getPath();
        } catch (final MalformedURLException e) {
            return "";
        }
    }

    @Override
    public Method method() {
        return Method.valueOf(underlyingRequest.method().name());
    }

    @Override
    public Optional<InetSocketAddress> getRemoteAddress() {
        return Optional.ofNullable(this.underlyingChannel.getRemoteAddress());
    }

    @Override
    public String uri() {
        return underlyingRequest.uri();
    }

    @Override
    public Map<String, String> params() {
        return params(underlyingRequest.uri());
    }

    private static Map<String, String> params(String uri) {
        // Sourced from
        // https://github.com/opensearch-project/OpenSearch/blob/main/server/src/main/java/org/opensearch/http/AbstractHttpServerTransport.java#L419-L422
        final Map<String, String> params = new HashMap<>();
        final int index = uri.indexOf(63);
        if (index >= 0) {
            try {
                RestUtils.decodeQueryString(uri, index + 1, params);
            } catch (IllegalArgumentException var4) {
                return Collections.emptyMap();
            }
        }

        return params;
    }
}
