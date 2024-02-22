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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.net.ssl.SSLEngine;

import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;

import io.netty.handler.ssl.SslHandler;

/**
 * Wraps the functionality of RestRequest for use in the security plugin
 */
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
        if (underlyingRequest == null || underlyingRequest.getHttpChannel() == null) {
            return null;
        }

        // We look for Ssl_handler called `ssl_http` in the outbound pipeline of Netty channel first, and if its not
        // present we look for it in inbound channel. If its present in neither we return null, else we return the sslHandler.
        return underlyingRequest.getHttpChannel().get("ssl_http", SslHandler.class).map(SslHandler::engine).orElse(null);
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
        return new HashMap<>(underlyingRequest.params()) {
            @Override
            public String get(Object key) {
                return underlyingRequest.param((String) key);
            }
        };
    }

    @Override
    public Set<String> getUnconsumedParams() {
        // params() Map consumes explict parameter access
        return Set.of();
    }

    /** Gets access to the underlying request object */
    public RestRequest breakEncapsulationForRequest() {
        return underlyingRequest;
    }
}
