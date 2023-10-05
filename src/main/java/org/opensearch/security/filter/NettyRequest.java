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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.net.ssl.SSLEngine;

import org.opensearch.rest.RestRequest.Method;

import io.netty.handler.codec.http.HttpRequest;

/**
 * Wraps the functionality of HttpRequest for use in the security plugin
 */
public class NettyRequest implements SecurityRequest {
    protected final HttpRequest underlyingRequest;

    NettyRequest(final HttpRequest request) {
        this.underlyingRequest = request;
    }

    @Override
    public Map<String, List<String>> getHeaders() {
        final Map<String, List<String>> headers = new HashMap<>();
        underlyingRequest.headers().forEach(h -> headers.put(h.getKey(), List.of(h.getValue())));
        return headers;
    }

    @Override
    public SSLEngine getSSLEngine() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getSSLEngine'");
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
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getRemoteAddress'");
    }

    @Override
    public String uri() {
        return underlyingRequest.uri();
    }

    @Override
    public Map<String, String> params() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'params'");
    }

}