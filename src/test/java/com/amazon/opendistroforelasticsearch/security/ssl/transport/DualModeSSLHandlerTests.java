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
package com.amazon.opendistroforelasticsearch.security.ssl.transport;

import com.amazon.opendistroforelasticsearch.security.ssl.OpenDistroSecurityKeyStore;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLConnectionTestUtil;
import com.amazon.opendistroforelasticsearch.security.ssl.util.TLSUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.ssl.SslHandler;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

public class DualModeSSLHandlerTests {

    public static final int TLS_MAJOR_VERSION = 3;
    public static final int TLS_MINOR_VERSION = 0;

    private OpenDistroSecurityKeyStore openDistroSecurityKeyStore;
    private ChannelPipeline pipeline;
    private ChannelHandlerContext ctx;
    private SslHandler sslHandler;

    @Before
    public void setup() {
        pipeline = Mockito.mock(ChannelPipeline.class);
        ctx = Mockito.mock(ChannelHandlerContext.class);
        Mockito.when(ctx.pipeline()).thenReturn(pipeline);

        openDistroSecurityKeyStore = Mockito.mock(OpenDistroSecurityKeyStore.class);
        sslHandler = Mockito.mock(SslHandler.class);
    }

    @Test
    public void testInvalidMessage() throws Exception {
        DualModeSSLHandler handler = new DualModeSSLHandler(openDistroSecurityKeyStore);

        ByteBufAllocator alloc = PooledByteBufAllocator.DEFAULT;
        handler.decode(ctx, alloc.directBuffer(4), null);
        // ensure pipeline is not fetched and manipulated
        Mockito.verify(ctx, Mockito.times(0)).pipeline();
    }

    @Test
    public void testValidTLSMessage() throws Exception {
        DualModeSSLHandler handler = new DualModeSSLHandler(openDistroSecurityKeyStore, sslHandler);

        ByteBufAllocator alloc = PooledByteBufAllocator.DEFAULT;
        ByteBuf buffer = alloc.directBuffer(6);
        buffer.writeByte(20);
        buffer.writeByte(TLS_MAJOR_VERSION);
        buffer.writeByte(TLS_MINOR_VERSION);
        buffer.writeByte(100);
        buffer.writeByte(0);
        buffer.writeByte(0);

        handler.decode(ctx, buffer, null);
        // ensure ssl handler is added
        Mockito.verify(ctx, Mockito.times(1)).pipeline();
        Mockito.verify(pipeline, Mockito.times(1))
                .addAfter("port_unification_handler", "ssl_server", sslHandler);
        Mockito.verify(pipeline,
                Mockito.times(1)).remove(handler);
    }

    @Test
    public void testNonTLSMessage() throws Exception {
        DualModeSSLHandler handler = new DualModeSSLHandler(openDistroSecurityKeyStore, sslHandler);

        ByteBufAllocator alloc = PooledByteBufAllocator.DEFAULT;
        ByteBuf buffer = alloc.directBuffer(6);

        for (int i = 0; i < 6; i++) {
            buffer.writeByte(1);
        }

        handler.decode(ctx, buffer, null);
        // ensure ssl handler is added
        Mockito.verify(ctx, Mockito.times(1)).pipeline();
        Mockito.verify(pipeline, Mockito.times(0))
                .addAfter("port_unification_handler", "ssl_server", sslHandler);
        Mockito.verify(pipeline,
                Mockito.times(1)).remove(handler);
    }

    @Test
    public void testDualModeClientHelloMessage() throws Exception {
        ChannelFuture channelFuture = Mockito.mock(ChannelFuture.class);
        Mockito.when(ctx.writeAndFlush(Mockito.any())).thenReturn(channelFuture);
        Mockito.when(channelFuture.addListener(Mockito.any())).thenReturn(channelFuture);

        ByteBufAllocator alloc = PooledByteBufAllocator.DEFAULT;
        ByteBuf buffer = alloc.directBuffer(6);
        buffer.writeCharSequence(SSLConnectionTestUtil.DUAL_MODE_CLIENT_HELLO_MSG, StandardCharsets.UTF_8);

        DualModeSSLHandler handler = new DualModeSSLHandler(openDistroSecurityKeyStore, sslHandler);
        List<Object> decodedObjs = new ArrayList<>();
        handler.decode(ctx, buffer, decodedObjs);

        ArgumentCaptor<ByteBuf> serverHelloReplyBuffer = ArgumentCaptor.forClass(ByteBuf.class);
        Mockito.verify(ctx, Mockito.times(1)).writeAndFlush(serverHelloReplyBuffer.capture());

        String actualReply = serverHelloReplyBuffer.getValue().getCharSequence(0, 6, StandardCharsets.UTF_8).toString();
        Assert.assertEquals(SSLConnectionTestUtil.DUAL_MODE_SERVER_HELLO_MSG, actualReply);
    }
}
