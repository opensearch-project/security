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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.opensearch.Version;
import org.opensearch.common.settings.Settings;
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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doNothing;
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
        when(transportChannel.getVersion()).thenReturn(Version.V_3_0_0);
        Assert.assertThrows(Exception.class, () -> securitySSLRequestHandler.messageReceived(transportRequest, transportChannel, task));
        Assert.assertFalse(threadPool.getThreadContext().getTransient(ConfigConstants.USE_JDK_SERIALIZATION));
    }
}
