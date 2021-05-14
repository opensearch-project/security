/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package org.opensearch.security.ssl.util;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.PooledByteBufAllocator;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class TLSUtilTests {

    public static final int TLS_MAJOR_VERSION = 3;
    public static final int TLS_MINOR_VERSION = 0;

    @Before
    public void setup() {

    }

    @Test
    public void testSSLUtilSuccess() {
        // byte 20 to 24 are ssl headers
        for (int byteToSend = 20; byteToSend <= 24; byteToSend++) {
            ByteBufAllocator alloc = PooledByteBufAllocator.DEFAULT;
            ByteBuf buffer = alloc.directBuffer(5);
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
            ByteBufAllocator alloc = PooledByteBufAllocator.DEFAULT;
            ByteBuf buffer = alloc.directBuffer(5);
            buffer.writeByte(byteToSend);
            //setting invalid TLS version 100
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
            ByteBufAllocator alloc = PooledByteBufAllocator.DEFAULT;
            ByteBuf buffer = alloc.directBuffer(5);
            buffer.writeByte(byteToSend);
            buffer.writeByte(TLS_MAJOR_VERSION);
            buffer.writeByte(TLS_MINOR_VERSION);
            //setting content length as 0
            buffer.writeShort(0);
            Assert.assertFalse(TLSUtil.isTLS(buffer));
        }

    }
}
