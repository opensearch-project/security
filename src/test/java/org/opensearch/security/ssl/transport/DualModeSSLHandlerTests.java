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
package org.opensearch.security.ssl.transport;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.security.ssl.SecurityKeyStore;
import org.opensearch.security.ssl.util.SSLConnectionTestUtil;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.ssl.SslHandler;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import static org.opensearch.transport.NettyAllocator.getAllocator;

public class DualModeSSLHandlerTests {

    public static final int TLS_MAJOR_VERSION = 3;
    public static final int TLS_MINOR_VERSION = 0;
    private static final ByteBufAllocator ALLOCATOR = getAllocator();

    private SecurityKeyStore securityKeyStore;
    private ChannelPipeline pipeline;
    private ChannelHandlerContext ctx;
    private SslHandler sslHandler;

    @Before
    public void setup() {
        pipeline = Mockito.mock(ChannelPipeline.class);
        ctx = Mockito.mock(ChannelHandlerContext.class);
        Mockito.when(ctx.pipeline()).thenReturn(pipeline);

        securityKeyStore = Mockito.mock(SecurityKeyStore.class);
        sslHandler = Mockito.mock(SslHandler.class);
    }

    @Test
    public void testInvalidMessage() throws Exception {
        DualModeSSLHandler handler = new DualModeSSLHandler(securityKeyStore);

        handler.decode(ctx, ALLOCATOR.buffer(4), null);
        // ensure pipeline is not fetched and manipulated
        Mockito.verify(ctx, Mockito.times(0)).pipeline();
    }

    @Test
    public void testValidTLSMessage() throws Exception {
        DualModeSSLHandler handler = new DualModeSSLHandler(securityKeyStore, sslHandler);

        ByteBuf buffer = ALLOCATOR.buffer(6);
        buffer.writeByte(20);
        buffer.writeByte(TLS_MAJOR_VERSION);
        buffer.writeByte(TLS_MINOR_VERSION);
        buffer.writeByte(100);
        buffer.writeByte(0);
        buffer.writeByte(0);

        handler.decode(ctx, buffer, null);
        // ensure ssl handler is added
        Mockito.verify(ctx, Mockito.times(1)).pipeline();
        Mockito.verify(pipeline, Mockito.times(1)).addAfter("port_unification_handler", "ssl_server", sslHandler);
        Mockito.verify(pipeline, Mockito.times(1)).remove(handler);
    }

    @Test
    public void testNonTLSMessage() throws Exception {
        DualModeSSLHandler handler = new DualModeSSLHandler(securityKeyStore, sslHandler);

        ByteBuf buffer = ALLOCATOR.buffer(6);

        for (int i = 0; i < 6; i++) {
            buffer.writeByte(1);
        }

        handler.decode(ctx, buffer, null);
        // ensure ssl handler is added
        Mockito.verify(ctx, Mockito.times(1)).pipeline();
        Mockito.verify(pipeline, Mockito.times(0)).addAfter("port_unification_handler", "ssl_server", sslHandler);
        Mockito.verify(pipeline, Mockito.times(1)).remove(handler);
    }

    @Test
    public void testDualModeClientHelloMessage() throws Exception {
        ChannelFuture channelFuture = Mockito.mock(ChannelFuture.class);
        Mockito.when(ctx.writeAndFlush(Mockito.any())).thenReturn(channelFuture);
        Mockito.when(channelFuture.addListener(Mockito.any())).thenReturn(channelFuture);

        ByteBuf buffer = ALLOCATOR.buffer(6);
        buffer.writeCharSequence(SSLConnectionTestUtil.DUAL_MODE_CLIENT_HELLO_MSG, StandardCharsets.UTF_8);

        DualModeSSLHandler handler = new DualModeSSLHandler(securityKeyStore, sslHandler);
        List<Object> decodedObjs = new ArrayList<>();
        handler.decode(ctx, buffer, decodedObjs);

        ArgumentCaptor<ByteBuf> serverHelloReplyBuffer = ArgumentCaptor.forClass(ByteBuf.class);
        Mockito.verify(ctx, Mockito.times(1)).writeAndFlush(serverHelloReplyBuffer.capture());

        String actualReply = serverHelloReplyBuffer.getValue().getCharSequence(0, 6, StandardCharsets.UTF_8).toString();
        Assert.assertEquals(SSLConnectionTestUtil.DUAL_MODE_SERVER_HELLO_MSG, actualReply);
    }
}
