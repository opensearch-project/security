/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.transport;

import java.io.IOException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.Version;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.transport.TransportResponse;
import org.opensearch.security.ssl.SslExceptionHandler;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.transport.SSLConfig;
import org.opensearch.security.ssl.transport.SecuritySSLRequestHandler;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportChannel;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportRequestHandler;

import org.mockito.ArgumentMatchers;
import org.mockito.InOrder;
import org.mockito.Mock;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SecuritySSLRequestHandlerTests {

    @Mock
    TransportRequestHandler<TransportRequest> actualHandler;
    @Mock
    SSLConfig sslConfig;
    ThreadPool threadPool;
    SslExceptionHandler sslExceptionHandler;
    Settings settings;
    SecuritySSLRequestHandler<TransportRequest> securitySSLRequestHandler;
    String testAction;

    @Mock
    private PrincipalExtractor principalExtractor;

    @Before
    public void setUp() {
        settings = Settings.builder()
            .put("node.name", SecurityInterceptorTests.class.getSimpleName())
            .put("request.headers.default", "1")
            .build();
        threadPool = new ThreadPool(settings);
        testAction = "test_action";
        sslExceptionHandler = mock(SslExceptionHandler.class);
        securitySSLRequestHandler = new SecuritySSLRequestHandler<>(
            testAction,
            actualHandler,
            threadPool,
            principalExtractor,
            sslConfig,
            sslExceptionHandler
        );
        doNothing().when(sslExceptionHandler)
            .logError(any(Exception.class), any(TransportRequest.class), any(String.class), any(Task.class), anyInt());
    }

    @Test
    public void testUseJDKSerializationHeaderIsSetOnMessageReceived() throws Exception {
        TransportRequest transportRequest = mock(TransportRequest.class);
        TransportChannel transportChannel = mock(TransportChannel.class);
        Task task = mock(Task.class);
        doNothing().when(transportChannel).sendResponse(ArgumentMatchers.any(Exception.class));
        when(transportChannel.getVersion()).thenReturn(Version.V_2_10_0);
        when(transportChannel.getChannelType()).thenReturn("transport");

        Assert.assertThrows(Exception.class, () -> securitySSLRequestHandler.messageReceived(transportRequest, transportChannel, task));
        Assert.assertTrue(threadPool.getThreadContext().getTransient(ConfigConstants.USE_JDK_SERIALIZATION));

        threadPool.getThreadContext().stashContext();
        when(transportChannel.getVersion()).thenReturn(Version.V_2_11_0);
        Assert.assertThrows(Exception.class, () -> securitySSLRequestHandler.messageReceived(transportRequest, transportChannel, task));
        Assert.assertFalse(threadPool.getThreadContext().getTransient(ConfigConstants.USE_JDK_SERIALIZATION));

        threadPool.getThreadContext().stashContext();
        when(transportChannel.getVersion()).thenReturn(Version.V_2_13_0);
        Assert.assertThrows(Exception.class, () -> securitySSLRequestHandler.messageReceived(transportRequest, transportChannel, task));
        Assert.assertFalse(threadPool.getThreadContext().getTransient(ConfigConstants.USE_JDK_SERIALIZATION));

        threadPool.getThreadContext().stashContext();
        when(transportChannel.getVersion()).thenReturn(Version.V_2_14_0);
        Assert.assertThrows(Exception.class, () -> securitySSLRequestHandler.messageReceived(transportRequest, transportChannel, task));
        Assert.assertTrue(threadPool.getThreadContext().getTransient(ConfigConstants.USE_JDK_SERIALIZATION));
    }

    @Test
    public void testUseJDKSerializationHeaderIsSetWithWrapperChannel() throws Exception {
        TransportRequest transportRequest = mock(TransportRequest.class);
        TransportChannel transportChannel = mock(TransportChannel.class);
        TransportChannel wrappedChannel = new WrappedTransportChannel(transportChannel);
        Task task = mock(Task.class);
        doNothing().when(transportChannel).sendResponse(ArgumentMatchers.any(Exception.class));
        when(transportChannel.getVersion()).thenReturn(Version.V_2_10_0);
        when(transportChannel.getChannelType()).thenReturn("other");

        Assert.assertThrows(Exception.class, () -> securitySSLRequestHandler.messageReceived(transportRequest, wrappedChannel, task));
        Assert.assertTrue(threadPool.getThreadContext().getTransient(ConfigConstants.USE_JDK_SERIALIZATION));

        threadPool.getThreadContext().stashContext();
        when(transportChannel.getVersion()).thenReturn(Version.V_2_11_0);
        Assert.assertThrows(Exception.class, () -> securitySSLRequestHandler.messageReceived(transportRequest, wrappedChannel, task));
        Assert.assertFalse(threadPool.getThreadContext().getTransient(ConfigConstants.USE_JDK_SERIALIZATION));

        threadPool.getThreadContext().stashContext();
        when(transportChannel.getVersion()).thenReturn(Version.V_2_13_0);
        Assert.assertThrows(Exception.class, () -> securitySSLRequestHandler.messageReceived(transportRequest, wrappedChannel, task));
        Assert.assertFalse(threadPool.getThreadContext().getTransient(ConfigConstants.USE_JDK_SERIALIZATION));

        threadPool.getThreadContext().stashContext();
        when(transportChannel.getVersion()).thenReturn(Version.V_2_14_0);
        Assert.assertThrows(Exception.class, () -> securitySSLRequestHandler.messageReceived(transportRequest, wrappedChannel, task));
        Assert.assertTrue(threadPool.getThreadContext().getTransient(ConfigConstants.USE_JDK_SERIALIZATION));
    }

    @Test
    public void testUseJDKSerializationHeaderIsSetAfterGetInnerChannel() throws Exception {
        TransportRequest transportRequest = mock(TransportRequest.class);
        TransportChannel transportChannel = mock(TransportChannel.class);
        WrappedTransportChannel wrappedChannel = mock(WrappedTransportChannel.class);
        Task task = mock(Task.class);
        when(wrappedChannel.getInnerChannel()).thenReturn(transportChannel);
        when(wrappedChannel.getChannelType()).thenReturn("other");
        doNothing().when(transportChannel).sendResponse(ArgumentMatchers.any(Exception.class));
        when(transportChannel.getVersion()).thenReturn(Version.V_2_10_0);

        Assert.assertThrows(Exception.class, () -> securitySSLRequestHandler.messageReceived(transportRequest, wrappedChannel, task));
        Assert.assertTrue(threadPool.getThreadContext().getTransient(ConfigConstants.USE_JDK_SERIALIZATION));

        InOrder inOrder = inOrder(wrappedChannel, transportChannel);

        inOrder.verify(wrappedChannel).getInnerChannel();
        inOrder.verify(transportChannel).getVersion();
    }

    public class WrappedTransportChannel implements TransportChannel {

        private TransportChannel inner;

        public WrappedTransportChannel(TransportChannel inner) {
            this.inner = inner;
        }

        @Override
        public String getProfileName() {
            return "WrappedTransportChannelProfileName";
        }

        public TransportChannel getInnerChannel() {
            return this.inner;
        }

        @Override
        public void sendResponse(TransportResponse response) throws IOException {
            inner.sendResponse(response);
        }

        @Override
        public void sendResponse(Exception e) throws IOException {

        }

        @Override
        public String getChannelType() {
            return "WrappedTransportChannelType";
        }
    }
}
