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

import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.tuple.Triple;
import io.netty.handler.codec.http.HttpRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.http.netty4.Netty4HttpChannel;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestResponse;

public class NettyRequestChannel extends NettyRequest implements SecurityRequestChannel {
    private final Logger log = LogManager.getLogger(NettyRequestChannel.class);

    private AtomicBoolean hasCompleted = new AtomicBoolean(false);
    private RestResponse capturedResponse;

    private final AtomicReference<Triple<Integer, Map<String, String>, String>> completedResult = new AtomicReference<>();

    NettyRequestChannel(final HttpRequest request, Netty4HttpChannel channel) {
        super(request, channel);
    }

    @Override
    public boolean hasResponse() {
        return hasCompleted.get();
    }

    @Override
    public RestResponse getCapturedResponse() {
        return capturedResponse;
    }

    @Override
    public boolean captureResponse(final SecurityResponse response) {

        if (hasResponse()) {
            throw new UnsupportedOperationException("A response has already been captured on this channel");
        }

        try {
            final BytesRestResponse restResponse = new BytesRestResponse(RestStatus.fromCode(response.getStatus()), response.getBody());
            if (response.getHeaders() != null) {
                response.getHeaders().forEach(restResponse::addHeader);
            }
            this.capturedResponse = restResponse;

            return true;
        } catch (final Exception e) {
            log.error("Error when attempting to capture response", e);
            throw new RuntimeException(e);
        } finally {
            hasCompleted.set(true);
        }
    }

    @Override
    public void sendResponseToChannel(RestChannel channel) {

        if (channel == null) {
            throw new UnsupportedOperationException("Channel was not defined");
        }

        if (!hasResponse()) {
            throw new UnsupportedOperationException("A response has not previously been captured");
        }

        try {
            channel.sendResponse(this.capturedResponse);
        } catch (final Exception e) {
            log.error("Error when attempting to send response", e);
            throw new RuntimeException(e);
        }
    }
}
