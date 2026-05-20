/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.transport;

import java.io.IOException;
import java.util.function.Supplier;

import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.transport.TransportResponse;
import org.opensearch.transport.TransportException;
import org.opensearch.transport.TransportResponseHandler;
import org.opensearch.transport.stream.StreamTransportResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

/**
 * Verifies that RestoringTransportResponseHandler delegates all interface methods
 * identically to the inner handler.
 */
public class RestoringTransportResponseHandlerTests {

    @Test
    public void testWrappedHandlerBehavesIdenticallyToInnerHandler() throws IOException {
        TestTransportResponseHandler innerHandler = new TestTransportResponseHandler(true, "search_worker");
        TransportResponseHandler<TransportResponse> wrappedHandler = getRestorableTransportResponseTransportResponseHandler(innerHandler);

        // Verify skipsDeserialization is forwarded (critical for Arrow Flight zero-copy)
        assertEquals(
            "skipsDeserialization must match inner handler",
            innerHandler.skipsDeserialization(),
            wrappedHandler.skipsDeserialization()
        );

        // Verify executor is forwarded
        assertEquals("executor must match inner handler", innerHandler.executor(), wrappedHandler.executor());

        // Verify read() forwards the StreamInput and returns the same response
        byte[] payload = new byte[] { 0x01, 0x42, (byte) 0xFF, 0x00, 0x7E, (byte) 0xAB };
        StreamInput streamInput = StreamInput.wrap(payload);
        TransportResponse readResult = wrappedHandler.read(streamInput);

        assertSame("read() must forward the exact StreamInput to inner handler", streamInput, innerHandler.lastReadInput);
        assertSame("read() must return the inner handler's response", innerHandler.readResponse, readResult);
    }

    private static TransportResponseHandler<TransportResponse> getRestorableTransportResponseTransportResponseHandler(
        TestTransportResponseHandler innerHandler
    ) {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        Supplier<ThreadContext.StoredContext> restorableContext = threadContext.newRestorableContext(true);
        SecurityInterceptor interceptor = new SecurityInterceptor(
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            () -> false,
            null
        );
        return interceptor.new RestoringTransportResponseHandler<>(innerHandler, restorableContext);
    }

    private static class TestTransportResponseHandler implements TransportResponseHandler<TransportResponse> {
        private final boolean skipsDeserialization;
        private final String executor;
        final TransportResponse readResponse = new TransportResponse.Empty();
        StreamInput lastReadInput;

        TestTransportResponseHandler(boolean skipsDeserialization, String executor) {
            this.skipsDeserialization = skipsDeserialization;
            this.executor = executor;
        }

        @Override
        public TransportResponse read(StreamInput in) throws IOException {
            lastReadInput = in;
            return readResponse;
        }

        @Override
        public boolean skipsDeserialization() {
            return skipsDeserialization;
        }

        @Override
        public void handleResponse(TransportResponse response) {}

        @Override
        public void handleStreamResponse(StreamTransportResponse<TransportResponse> response) {}

        @Override
        public void handleException(TransportException exp) {}

        @Override
        public String executor() {
            return executor;
        }
    }
}
