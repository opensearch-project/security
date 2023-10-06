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

import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;

public class OpenSearchRequestChannel extends OpenSearchRequest implements SecurityRequestChannel {

    private final Logger log = LogManager.getLogger(OpenSearchRequest.class);

    private final AtomicReference<SecurityResponse> responseRef = new AtomicReference<SecurityResponse>(null);
    private final AtomicBoolean hasCompleted = new AtomicBoolean(false);
    private final RestChannel underlyingChannel;

    OpenSearchRequestChannel(final RestRequest request, final RestChannel channel) {
        super(request);
        underlyingChannel = channel;
    }

    /** Gets access to the underlying channel object */
    public RestChannel breakEncapsulationForChannel() {
        return underlyingChannel;
    }

    @Override
    public void queueForSending(final SecurityResponse response) {
        if (underlyingChannel == null) {
            throw new UnsupportedOperationException("Channel was not defined");
        }

        if (hasCompleted.get()) {
            throw new UnsupportedOperationException("This channel has already completed");
        }

        if (getQueuedResponse().isPresent()) {
            throw new UnsupportedOperationException("Another response was already queued");
        }

        responseRef.set(response);
    }

    @Override
    public Optional<SecurityResponse> getQueuedResponse() {
        return Optional.ofNullable(responseRef.get());
    }

    @Override
    public boolean sendResponse() {
        if (underlyingChannel == null) {
            throw new UnsupportedOperationException("Channel was not defined");
        }

        if (hasCompleted.get()) {
            throw new UnsupportedOperationException("This channel has already completed");
        }

        if (getQueuedResponse().isEmpty()) {
            throw new UnsupportedOperationException("No response has been associated with this channel");
        }

        final SecurityResponse response = responseRef.get();

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
}
