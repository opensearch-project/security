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
package org.opensearch.security.ssl.util;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;

import static org.opensearch.transport.NettyAllocator.getAllocator;

public class TLSUtilTests {

    public static final int TLS_MAJOR_VERSION = 3;
    public static final int TLS_MINOR_VERSION = 0;
    private static final ByteBufAllocator ALLOCATOR = getAllocator();

    @Before
    public void setup() {

    }

    @Test
    public void testSSLUtilSuccess() {
        // byte 20 to 24 are ssl headers
        for (int byteToSend = 20; byteToSend <= 24; byteToSend++) {
            ByteBuf buffer = ALLOCATOR.buffer(5);
            buffer.writeByte(byteToSend);
            buffer.writeByte(TLS_MAJOR_VERSION);
            buffer.writeByte(TLS_MINOR_VERSION);
            buffer.writeByte(100);
            Assert.assertTrue(TLSUtil.isTLS(buffer));
        }

    }

    @Test
    public void testSSLUtilWrongTLSVersion() {
        // byte 20 to 24 are ssl headers
        for (int byteToSend = 20; byteToSend <= 24; byteToSend++) {
            ByteBuf buffer = ALLOCATOR.buffer(5);
            buffer.writeByte(byteToSend);
            // setting invalid TLS version 100
            buffer.writeByte(100);
            buffer.writeByte(TLS_MINOR_VERSION);
            buffer.writeByte(100);
            Assert.assertFalse(TLSUtil.isTLS(buffer));
        }

    }

    @Test
    public void testSSLUtilInvalidContentLength() {
        // byte 20 to 24 are ssl headers
        for (int byteToSend = 20; byteToSend <= 24; byteToSend++) {
            ByteBuf buffer = ALLOCATOR.buffer(5);
            buffer.writeByte(byteToSend);
            buffer.writeByte(TLS_MAJOR_VERSION);
            buffer.writeByte(TLS_MINOR_VERSION);
            // setting content length as 0
            buffer.writeShort(0);
            Assert.assertFalse(TLSUtil.isTLS(buffer));
        }

    }
}
