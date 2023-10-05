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
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;

public class NettyRequestChannel extends NettyRequest implements SecurityRequestChannel {

    private final Logger log = LogManager.getLogger(OpenSearchRequest.class);

    private AtomicBoolean hasCompleted = new AtomicBoolean(false);
    private final RestChannel underlyingChannel;

    NettyRequestChannel(final HttpRequest request, final RestChannel channel) {
        super(request);
        underlyingChannel = channel;
    }

    @Override
    public boolean hasCompleted() {
        return hasCompleted.get();
    }

    @Override
    public boolean completeWith(final SecurityResponse response) {

        if (underlyingChannel == null) {
            throw new UnsupportedOperationException("Channel was not defined");
        }

        if (hasCompleted()) {
            throw new UnsupportedOperationException("This channel has already completed");
        }

        try {
            final BytesRestResponse restResponse = new BytesRestResponse(RestStatus.fromCode(response.getStatus()), response.getBody());
            if (response.getHeaders() != null) {
                response.getHeaders().forEach(restResponse::addHeader);
            }
            underlyingChannel.sendResponse(restResponse);

            return true;
        } catch (final Exception e) {
            log.error("Error when attempting to send response", e);
            throw new RuntimeException(e);
        } finally {
            hasCompleted.set(true);
        }
    }

    /** Marks a request completed */
    public void markCompleted() {
        hasCompleted.set(true);
    }

    /** Gets access to the underlying channel object */
    public RestChannel breakEncapsulationForChannel() {
        return underlyingChannel;
    }
}