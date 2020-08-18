package com.amazon.opendistroforelasticsearch.security.ssl.util;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.PooledByteBufAllocator;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class SSLUtilTests {

    public static final int TLS_MAJOR_VERSION = 3;
    public static final int TLS_MINOR_VERSION = 0;

    @Before
    public void setup() {

    }

    @Test
    public void testSSLUtilSuccess() {
        SSLUtil util = new SSLUtil();
        // byte 20 to 24 are ssl headers
        for (int byteToSend = 20; byteToSend <= 24; byteToSend++) {
            ByteBufAllocator alloc = PooledByteBufAllocator.DEFAULT;
            ByteBuf buffer = alloc.directBuffer(5);
            buffer.writeByte(byteToSend);
            buffer.writeByte(TLS_MAJOR_VERSION);
            buffer.writeByte(TLS_MINOR_VERSION);
            buffer.writeByte(100);
            Assert.assertTrue(util.isTLS(buffer));
        }

    }

    @Test
    public void testSSLUtilWrongTLSVersion() {
        SSLUtil util = new SSLUtil();
        // byte 20 to 24 are ssl headers
        for (int byteToSend = 20; byteToSend <= 24; byteToSend++) {
            ByteBufAllocator alloc = PooledByteBufAllocator.DEFAULT;
            ByteBuf buffer = alloc.directBuffer(5);
            buffer.writeByte(byteToSend);
            //setting invalid TLS version 100
            buffer.writeByte(100);
            buffer.writeByte(TLS_MINOR_VERSION);
            buffer.writeByte(100);
            Assert.assertFalse(util.isTLS(buffer));
        }

    }

    @Test
    public void testSSLUtilInvalidContentLength() {
        SSLUtil util = new SSLUtil();
        // byte 20 to 24 are ssl headers
        for (int byteToSend = 20; byteToSend <= 24; byteToSend++) {
            ByteBufAllocator alloc = PooledByteBufAllocator.DEFAULT;
            ByteBuf buffer = alloc.directBuffer(5);
            buffer.writeByte(byteToSend);
            buffer.writeByte(TLS_MAJOR_VERSION);
            buffer.writeByte(TLS_MINOR_VERSION);
            //setting content length as 0
            buffer.writeByte(0);
            Assert.assertFalse(util.isTLS(buffer));
        }

    }
}
