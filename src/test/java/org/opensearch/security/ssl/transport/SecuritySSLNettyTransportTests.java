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

import java.util.Collections;

import org.apache.logging.log4j.Logger;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.Version;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.common.network.NetworkService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.PageCacheRecycler;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.indices.breaker.CircuitBreakerService;
import org.opensearch.security.ssl.SecurityKeyStore;
import org.opensearch.security.ssl.SslExceptionHandler;
import org.opensearch.security.ssl.transport.SecuritySSLNettyTransport.SSLClientChannelInitializer;
import org.opensearch.security.ssl.transport.SecuritySSLNettyTransport.SSLServerChannelInitializer;
import org.opensearch.telemetry.tracing.Tracer;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.FakeTcpChannel;
import org.opensearch.transport.SharedGroupFactory;
import org.opensearch.transport.TcpChannel;

import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.DecoderException;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SecuritySSLNettyTransportTests {

    @Mock
    private Version version;
    @Mock
    private ThreadPool threadPool;
    @Mock
    private PageCacheRecycler pageCacheRecycler;
    @Mock
    private NamedWriteableRegistry namedWriteableRegistry;
    @Mock
    private CircuitBreakerService circuitBreakerService;
    @Mock
    private Tracer trace;
    @Mock
    private SecurityKeyStore ossks;
    @Mock
    private SslExceptionHandler sslExceptionHandler;
    @Mock
    private DiscoveryNode discoveryNode;

    // This initializes all the above mocks
    @Rule
    public MockitoRule rule = MockitoJUnit.rule();

    private NetworkService networkService;
    private SharedGroupFactory sharedGroupFactory;
    private Logger mockLogger;
    private SSLConfig sslConfig;
    private SecuritySSLNettyTransport securitySSLNettyTransport;
    Throwable testCause = new Throwable("Test Cause");

    @Before
    public void setup() {

        networkService = new NetworkService(Collections.emptyList());
        sharedGroupFactory = new SharedGroupFactory(Settings.EMPTY);

        sslConfig = new SSLConfig(Settings.EMPTY);
        mockLogger = mock(Logger.class);

        securitySSLNettyTransport = spy(
            new SecuritySSLNettyTransport(
                Settings.EMPTY,
                version,
                threadPool,
                networkService,
                pageCacheRecycler,
                namedWriteableRegistry,
                circuitBreakerService,
                ossks,
                sslExceptionHandler,
                sharedGroupFactory,
                sslConfig,
                trace
            )
        );
    }

    @Test
    public void OnException_withNullChannelShouldThrowException() {

        OpenSearchSecurityException exception = new OpenSearchSecurityException("The provided TCP channel is invalid");
        assertThrows(OpenSearchSecurityException.class, () -> securitySSLNettyTransport.onException(null, exception));
    }

    @Test
    public void OnException_withClosedChannelShouldThrowException() {

        TcpChannel channel = new FakeTcpChannel();
        channel.close();
        OpenSearchSecurityException exception = new OpenSearchSecurityException("The provided TCP channel is invalid");
        assertThrows(OpenSearchSecurityException.class, () -> securitySSLNettyTransport.onException(channel, exception));
    }

    @Test
    public void OnException_withNullExceptionShouldSucceed() {

        TcpChannel channel = new FakeTcpChannel();
        securitySSLNettyTransport.onException(channel, null);
        verify(securitySSLNettyTransport, times(1)).onException(channel, null);
        channel.close();
    }

    @Test
    public void OnException_withDecoderExceptionShouldGetCause() {

        when(securitySSLNettyTransport.getLogger()).thenReturn(mockLogger);
        DecoderException exception = new DecoderException("Test Exception", testCause);
        TcpChannel channel = new FakeTcpChannel();
        securitySSLNettyTransport.onException(channel, exception);
        verify(mockLogger, times(1)).error("Exception during establishing a SSL connection: " + exception.getCause(), exception.getCause());
    }

    @Test
    public void getServerChannelInitializer_shouldReturnValidServerChannel() {

        ChannelHandler channelHandler = securitySSLNettyTransport.getServerChannelInitializer("test-server-channel");
        assertThat(channelHandler, is(notNullValue()));
        assertThat(channelHandler, is(instanceOf(SSLServerChannelInitializer.class)));
    }

    @Test
    public void getClientChannelInitializer_shouldReturnValidClientChannel() {
        ChannelHandler channelHandler = securitySSLNettyTransport.getClientChannelInitializer(discoveryNode);
        assertThat(channelHandler, is(notNullValue()));
        assertThat(channelHandler, is(instanceOf(SSLClientChannelInitializer.class)));
    }

    @Test
    public void exceptionWithServerChannelHandlerContext_nonNullDecoderExceptionShouldGetCause() throws Exception {
        when(securitySSLNettyTransport.getLogger()).thenReturn(mockLogger);
        Throwable exception = new DecoderException("Test Exception", testCause);
        ChannelHandlerContext ctx = mock(ChannelHandlerContext.class);
        securitySSLNettyTransport.getServerChannelInitializer(discoveryNode.getName()).exceptionCaught(ctx, exception);
        verify(mockLogger, times(1)).error("Exception during establishing a SSL connection: " + exception.getCause(), exception.getCause());
    }

    @Test
    public void exceptionWithServerChannelHandlerContext_nonNullCauseOnlyShouldNotGetCause() throws Exception {
        when(securitySSLNettyTransport.getLogger()).thenReturn(mockLogger);
        Throwable exception = new OpenSearchSecurityException("Test Exception", testCause);
        ChannelHandlerContext ctx = mock(ChannelHandlerContext.class);
        securitySSLNettyTransport.getServerChannelInitializer(discoveryNode.getName()).exceptionCaught(ctx, exception);
        verify(mockLogger, times(1)).error("Exception during establishing a SSL connection: " + exception, exception);
    }

    @Test
    public void exceptionWithClientChannelHandlerContext_nonNullDecoderExceptionShouldGetCause() throws Exception {
        when(securitySSLNettyTransport.getLogger()).thenReturn(mockLogger);
        Throwable exception = new DecoderException("Test Exception", testCause);
        ChannelHandlerContext ctx = mock(ChannelHandlerContext.class);
        securitySSLNettyTransport.getClientChannelInitializer(discoveryNode).exceptionCaught(ctx, exception);
        verify(mockLogger, times(1)).error("Exception during establishing a SSL connection: " + exception.getCause(), exception.getCause());
    }

    @Test
    public void exceptionWithClientChannelHandlerContext_nonNullCauseOnlyShouldNotGetCause() throws Exception {
        when(securitySSLNettyTransport.getLogger()).thenReturn(mockLogger);
        Throwable exception = new OpenSearchSecurityException("Test Exception", testCause);
        ChannelHandlerContext ctx = mock(ChannelHandlerContext.class);
        securitySSLNettyTransport.getClientChannelInitializer(discoveryNode).exceptionCaught(ctx, exception);
        verify(mockLogger, times(1)).error("Exception during establishing a SSL connection: " + exception, exception);
    }
}
