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

import org.opensearch.http.netty4.Netty4HttpChannel;

import io.netty.handler.codec.http.HttpRequest;

public class NettyRequestChannel extends NettyRequest implements SecurityRequestChannel {
    private final Logger log = LogManager.getLogger(NettyRequestChannel.class);

    private AtomicBoolean hasCompleted = new AtomicBoolean(false);
    private final AtomicReference<SecurityResponse> responseRef = new AtomicReference<SecurityResponse>(null);

    NettyRequestChannel(final HttpRequest request, Netty4HttpChannel channel) {
        super(request, channel);
    }

    @Override
    public void queueForSending(SecurityResponse response) {
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
}
