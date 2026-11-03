/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.transport.nativeprotocol;

import java.io.IOException;

import org.opensearch.Version;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.common.io.stream.Writeable;

/**
 * Serializes a transport request into the native wire format carried in Flight tickets, for use in integration tests.
 */
public final class RawTransportRequestSerializer {

    private RawTransportRequestSerializer() {}

    public static byte[] serialize(String action, Writeable request, long requestId) throws IOException {
        NativeOutboundMessage.Request message = new NativeOutboundMessage.Request(
            new ThreadContext(Settings.EMPTY),
            new String[0],
            request,
            Version.CURRENT,
            action,
            requestId,
            false,
            false
        );
        try (BytesStreamOutput out = new BytesStreamOutput()) {
            return BytesReference.toBytes(message.serialize(out));
        }
    }
}
