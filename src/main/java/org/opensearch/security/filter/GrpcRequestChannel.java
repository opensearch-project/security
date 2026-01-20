/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.filter;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.net.ssl.SSLEngine;

import io.grpc.Metadata;
import io.grpc.ServerCall;
import org.opensearch.rest.RestRequest.Method;

/**
 * gRPC implementation of SecurityRequestChannel.
 */
public class GrpcRequestChannel implements SecurityRequestChannel {

    private final ServerCall<?, ?> serverCall;
    private final Map<String, List<String>> headers;
    private Optional<SecurityResponse> queuedResponse = Optional.empty();

    public GrpcRequestChannel(ServerCall<?, ?> serverCall, Metadata metadata) {
        this.serverCall = serverCall;
        this.headers = extractHeaders(metadata);
    }

    private Map<String, List<String>> extractHeaders(Metadata metadata) {
        Map<String, List<String>> headerMap = new HashMap<>();
        for (String key : metadata.keys()) {
            if (!key.endsWith("-bin")) { // Skip binary headers
                String value = metadata.get(Metadata.Key.of(key, Metadata.ASCII_STRING_MARSHALLER));
                if (value != null) {
                    headerMap.put(key, List.of(value));
                }
            }
        }
        return headerMap;
    }

    @Override
    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    @Override
    public SSLEngine getSSLEngine() {
        throw new UnsupportedOperationException("Client certificate authentication not supported for gRPC");
    }

    @Override
    public String path() {
        return serverCall.getMethodDescriptor().getFullMethodName();
    }

    @Override
    public Method method() {
        throw new UnsupportedOperationException("HTTP methods not applicable to gRPC");
    }

    @Override
    public Optional<InetSocketAddress> getRemoteAddress() {
        // TODO: gRPC ServerCall doesn't directly expose remote address
        // This would need to be extracted from call attributes if available
        return Optional.empty();
    }

    @Override
    public String uri() {
        return serverCall.getMethodDescriptor().getFullMethodName();
    }

    @Override
    public Map<String, String> params() {
        throw new UnsupportedOperationException("Query params not applicable to gRPC");
    }

    @Override
    public Set<String> getUnconsumedParams() {
        return Set.of(); // No parameters to track for gRPC
    }

    @Override
    public void queueForSending(SecurityResponse response) {
        this.queuedResponse = Optional.of(response);
    }

    @Override
    public Optional<SecurityResponse> getQueuedResponse() {
        return queuedResponse;
    }
}
