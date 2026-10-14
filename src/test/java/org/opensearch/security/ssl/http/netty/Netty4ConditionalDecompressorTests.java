/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.ssl.http.netty;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.GZIPOutputStream;

import org.junit.Test;

import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpVersion;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class Netty4ConditionalDecompressorTests {

    private static FullHttpRequest requestWithBody(final CharSequence contentEncoding, final byte[] body) {
        final FullHttpRequest request = new DefaultFullHttpRequest(
            HttpVersion.HTTP_1_1,
            HttpMethod.POST,
            "/_bulk",
            Unpooled.wrappedBuffer(body)
        );
        request.headers().set(HttpHeaderNames.CONTENT_ENCODING, contentEncoding);
        request.headers().set(HttpHeaderNames.CONTENT_LENGTH, body.length);
        return request;
    }

    private static EmbeddedChannel authenticatedChannel() {
        final EmbeddedChannel channel = new EmbeddedChannel(new Netty4ConditionalDecompressor());
        channel.attr(Netty4HttpRequestHeaderVerifier.SHOULD_DECOMPRESS).set(Boolean.TRUE);
        return channel;
    }

    @Test
    public void zstdContentIsPassedThroughUndecoded() {
        final EmbeddedChannel channel = authenticatedChannel();
        final byte[] body = "not really zstd".getBytes(StandardCharsets.UTF_8);

        assertTrue(channel.writeInbound(requestWithBody(HttpHeaderValues.ZSTD, body)));

        final FullHttpRequest passedThrough = channel.readInbound();
        try {
            assertEquals(HttpHeaderValues.ZSTD.toString(), passedThrough.headers().get(HttpHeaderNames.CONTENT_ENCODING));
            assertArrayEquals(body, ByteBufUtil.getBytes(passedThrough.content()));
        } finally {
            passedThrough.release();
        }
        assertFalse(channel.finish());
    }

    @Test
    public void gzipContentIsStillDecompressedWhenAuthenticated() throws IOException {
        final EmbeddedChannel channel = authenticatedChannel();
        final byte[] body = "{\"field\":\"value\"}".getBytes(StandardCharsets.UTF_8);
        final ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(compressed)) {
            gzip.write(body);
        }

        assertTrue(channel.writeInbound(requestWithBody(HttpHeaderValues.GZIP, compressed.toByteArray())));

        final HttpRequest decodedRequest = channel.readInbound();
        assertNotEquals(HttpHeaderValues.GZIP.toString(), decodedRequest.headers().get(HttpHeaderNames.CONTENT_ENCODING));
        final ByteArrayOutputStream decoded = new ByteArrayOutputStream();
        Object msg;
        while ((msg = channel.readInbound()) != null) {
            final HttpContent content = (HttpContent) msg;
            decoded.write(ByteBufUtil.getBytes(content.content()));
            content.release();
        }
        assertArrayEquals(body, decoded.toByteArray());
        assertFalse(channel.finish());
    }
}
