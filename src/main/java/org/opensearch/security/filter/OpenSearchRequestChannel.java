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
import java.util.concurrent.atomic.AtomicReference;

import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;

public class OpenSearchRequestChannel extends OpenSearchRequest implements SecurityRequestChannel {

    private final AtomicReference<SecurityResponse> responseRef = new AtomicReference<SecurityResponse>(null);
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

        if (getQueuedResponse().isPresent()) {
            throw new UnsupportedOperationException("Another response was already queued");
        }

        responseRef.set(response);
    }

    @Override
    public Optional<SecurityResponse> getQueuedResponse() {
        return Optional.ofNullable(responseRef.get());
    }
}
