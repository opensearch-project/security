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

import io.netty.handler.codec.DecoderException;
import net.bytebuddy.implementation.bytecode.Throw;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
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

import org.apache.logging.log4j.Logger;
import io.netty.channel.ChannelHandler;
import org.mockito.Mock;
import org.opensearch.transport.TcpChannel;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.opensearch.common.inject.matcher.Matchers.any;

public class SecuritySSLNettyTransportTests {

    @Mock
    private Version version;
    @Mock
    private ThreadPool threadPool;
    @Mock
    private NetworkService networkService;
    @Mock
    private PageCacheRecycler pageCacheRecycler;
    @Mock
    private NamedWriteableRegistry namedWriteableRegistry;
    @Mock
    private CircuitBreakerService circuitBreakerService;
    @Mock
    private SharedGroupFactory sharedGroupFactory;
    @Mock
    private Tracer trace;
    @Mock
    private SecurityKeyStore ossks;

    private SslExceptionHandler sslExceptionHandler;
    @Mock
    private DiscoveryNode discoveryNode;
    private Logger mockLogger;
    private SSLConfig sslConfig;
    private SecuritySSLNettyTransport securitySSLNettyTransport;
    Throwable testCause = new Throwable("Test Cause");

    @Before
    public void setup() {

        sslConfig = new SSLConfig(Settings.EMPTY);
        sslExceptionHandler = mock(SslExceptionHandler.class);
        mockLogger = mock(Logger.class);

        securitySSLNettyTransport = spy(new SecuritySSLNettyTransport(
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
        ));
    }

    @Test
    public void OnException_withNullChannelShouldThrowException() {

        NullPointerException exception = new NullPointerException("Test Exception");
        Assert.assertThrows(NullPointerException.class, () -> securitySSLNettyTransport.onException(null, exception));
    }

    @Test
    public void OnException_withNullExceptionShouldSucceed() {

        TcpChannel channel = new FakeTcpChannel();
        securitySSLNettyTransport.onException(channel, null);
        verify(securitySSLNettyTransport, times(1)).onException(channel, null);
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
}
