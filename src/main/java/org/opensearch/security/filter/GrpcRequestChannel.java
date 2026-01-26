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
import java.net.SocketAddress;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.net.ssl.SSLEngine;

import org.opensearch.rest.RestRequest.Method;

import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.Status;

/**
 * gRPC implementation of SecurityRequestChannel.
 * While the SecurityRequestChannel does not align perfectly with the gRPC protocol the usage is largely analogous.
 * Unsupported fields and concepts will throw exceptions to prevent unintended usage.
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

    /**
     * @return HTTP header map for this request.
     */
    @Override
    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    /**
     * Client certificate auth is not supported in this version.
     * This feature is still pending implementation.
     */
    @Override
    public SSLEngine getSSLEngine() {
        throw new UnsupportedOperationException("Client certificate authentication not supported for gRPC");
    }

    /**
     * gRPC does not support query parameters so there is essentially no distinction between URI and PATH.
     * Paths are based off of the service being invoked in gRPC and are named after the full service package name.
     * For example search requests use path "org.opensearch.protobufs.services.SearchService".
     */
    @Override
    public String path() {
        return serverCall.getMethodDescriptor().getFullMethodName();
    }

    @Override
    public String uri() {
        return serverCall.getMethodDescriptor().getFullMethodName();
    }

    /**
     * Methods are a REST concept and unsupported here.
     */
    @Override
    public Method method() {
        throw new UnsupportedOperationException("HTTP methods not applicable to gRPC");
    }

    /**
     * @return client address.
     */
    @Override
    public Optional<InetSocketAddress> getRemoteAddress() {
        try {
            SocketAddress remoteAddr = serverCall.getAttributes().get(Grpc.TRANSPORT_ATTR_REMOTE_ADDR);
            if (remoteAddr instanceof InetSocketAddress) {
                return Optional.of((InetSocketAddress) remoteAddr);
            }
        } catch (Exception e) {
            return Optional.empty();
        }
        return Optional.empty();
    }

    /**
     * Query params are a REST concept and always empty for gRPC requests.
     */
    @Override
    public Map<String, String> params() {
        return Collections.emptyMap();
    }

    @Override
    public Set<String> getUnconsumedParams() {
        return Set.of();
    }

    /**
     * @param response set an error response for this request.
     */
    @Override
    public void queueForSending(SecurityResponse response) {
        this.queuedResponse = Optional.of(response);
    }

    /**
     * Fetch queued SecurityResponse response.
     * Note the SecurityResponse encapsulates the REST response and HTTP error code.
     * Please see getQueuedResponseGrpcStatus for the purpose of returning a gRPC error and reason to clients.
     * @return return the queued response, if any.
     */
    @Override
    public Optional<SecurityResponse> getQueuedResponse() {
        return queuedResponse;
    }

    /**
     * Translate REST error code to gRPC status and include error body as description.
     * @return io.grpc.Status representation of SecurityResponse.
     */
    public io.grpc.Status getQueuedResponseGrpcStatus() {
        return queuedResponse.map(
            securityResponse -> mapToGrpcStatus(securityResponse.getStatus()).withDescription(securityResponse.getBody())
        ).orElse(Status.INTERNAL);
    }

    /**
     * Map HTTP status codes to gRPC Status enum.
     * Please find full HTTP -> gRPC mappings here:
     * https://github.com/opensearch-project/OpenSearch/issues/18926
     */
    private io.grpc.Status mapToGrpcStatus(int httpStatus) {
        return switch (httpStatus) {
            case 100, 101, 200, 201, 202, 203, 204, 205, 206 -> Status.OK;
            case 300, 301, 302, 303, 304, 305, 307, 411, 412, 417, 423, 424 -> Status.FAILED_PRECONDITION;
            case 400, 406, 414, 415, 421, 422 -> Status.INVALID_ARGUMENT;
            case 401, 407 -> Status.UNAUTHENTICATED;
            case 402, 403 -> Status.PERMISSION_DENIED;
            case 404, 410 -> Status.NOT_FOUND;
            case 405, 501, 505 -> Status.UNIMPLEMENTED;
            case 408, 504 -> Status.DEADLINE_EXCEEDED;
            case 409 -> Status.ABORTED;
            case 413, 416 -> Status.OUT_OF_RANGE;
            case 429, 507 -> Status.RESOURCE_EXHAUSTED;
            case 500 -> Status.INTERNAL;
            case 502, 503 -> Status.UNAVAILABLE;
            default -> Status.UNKNOWN;
        };
    }
}
