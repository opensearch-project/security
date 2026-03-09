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

package org.opensearch.security.filter;

import java.nio.file.Path;
import java.util.*;

import org.junit.Before;
import org.junit.Test;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.*;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.CompatConfig;
import org.opensearch.security.privileges.RestLayerPrivilegesEvaluator;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.http.netty.Netty4HttpRequestHeaderVerifier;
import org.opensearch.telemetry.tracing.Span;
import org.opensearch.telemetry.tracing.TracerContextStorage;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.node.NodeClient;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class SecurityRestFilterUnitTests {

    SecurityRestFilter sf;
    RestHandler testRestHandler;
    ThreadPool threadPool;

    class TestRestHandler implements RestHandler {

        @Override
        public void handleRequest(RestRequest request, RestChannel channel, NodeClient client) throws Exception {
            channel.sendResponse(new BytesRestResponse(RestStatus.OK, BytesRestResponse.TEXT_CONTENT_TYPE, BytesArray.EMPTY));
        }
    }

    @Before
    public void setUp() throws NoSuchMethodException {
        testRestHandler = new TestRestHandler();

        ThreadPool tp = spy(new ThreadPool(Settings.builder().put("node.name", "mock").build()));
        this.threadPool = tp;
        doReturn(new ThreadContext(Settings.EMPTY)).when(tp).getThreadContext();

        sf = new SecurityRestFilter(
            mock(BackendRegistry.class),
            mock(RestLayerPrivilegesEvaluator.class),
            mock(AuditLog.class),
            tp,
            mock(PrincipalExtractor.class),
            Settings.EMPTY,
            mock(Path.class),
            mock(CompatConfig.class)
        );
    }

    /**
     * Tests to ensure that the output of {@link SecurityRestFilter#wrap} is an instance of AuthczRestHandler
     */
    @Test
    public void testSecurityRestFilterWrap() throws Exception {
        AdminDNs adminDNs = mock(AdminDNs.class);

        RestHandler wrappedRestHandler = sf.wrap(testRestHandler, adminDNs, new HashSet<>(), new HashSet<>());

        assertTrue(wrappedRestHandler instanceof SecurityRestFilter.AuthczRestHandler);
        assertFalse(wrappedRestHandler instanceof TestRestHandler);
    }

    @Test
    public void testDoesCallDelegateOnSuccessfulAuthorization() throws Exception {
        SecurityRestFilter filterSpy = spy(sf);
        AdminDNs adminDNs = mock(AdminDNs.class);

        RestHandler testRestHandlerSpy = spy(testRestHandler);
        RestHandler wrappedRestHandler = filterSpy.wrap(testRestHandlerSpy, adminDNs, new HashSet<>(), new HashSet<>());

        doReturn(false).when(filterSpy).userIsSuperAdmin(any(), any());

        wrappedRestHandler.handleRequest(mock(RestRequest.class), mock(RestChannel.class), mock(NodeClient.class));

        verify(testRestHandlerSpy).handleRequest(any(), any(), any());
    }

    // unit tests for restPathMatches are in RestPathMatchesTests.java

    //Test that current_span transient is preserved after context restoration.
    @Test
    public void testCurrentSpanTransientPreservedAfterRestore() throws Exception {
        ThreadContext threadContext = threadPool.getThreadContext();
        // Handler verifies span is present
        RestHandler testHandler = (request, channel, client) -> {
            assertNotNull("CURRENT_SPAN should be preserved",
                    threadContext.getTransient(TracerContextStorage.CURRENT_SPAN));
        };

        Set<String> transientsToCopy = new HashSet<>(List.of(TracerContextStorage.CURRENT_SPAN));
        RestHandler wrappedRestHandler = sf.wrap(testHandler, mock(AdminDNs.class), new HashSet<>(), transientsToCopy);
        RestRequest request = addRelevantMocksAndGetRequest(threadContext);

        threadContext.putTransient(TracerContextStorage.CURRENT_SPAN, mock(Span.class));
        wrappedRestHandler.handleRequest(request, mock(RestChannel.class), mock(NodeClient.class));

        assertNotNull("current_span should be preserved after handleRequest completes",
                threadContext.getTransient(TracerContextStorage.CURRENT_SPAN));

    }

    // Current span is present in context ,not in transientsToCopy, hence we should NOT find it later
    @Test
    public void testCurrentSpanTransientNotPreservedAfterRestore() throws Exception {
        ThreadContext threadContext = threadPool.getThreadContext();

        // Handler verifies span is absent
        RestHandler testHandler = (request, channel, client) -> {
            assertNull("CURRENT_SPAN should NOT be preserved",
                    threadContext.getTransient(TracerContextStorage.CURRENT_SPAN));
        };

        Set<String> transientsToCopy = new HashSet<>();
        RestHandler wrappedRestHandler = sf.wrap(testHandler, mock(AdminDNs.class), new HashSet<>(), transientsToCopy);
        RestRequest request = addRelevantMocksAndGetRequest(threadContext);

        threadContext.putTransient(TracerContextStorage.CURRENT_SPAN, mock(Span.class));

        wrappedRestHandler.handleRequest(request, mock(RestChannel.class), mock(NodeClient.class));
        assertNull("current_span should NOT be preserved after handleRequest completes as its not present in transientsToCopy",
                threadContext.getTransient(TracerContextStorage.CURRENT_SPAN));
    }


    @SuppressWarnings("unchecked")
    private RestRequest addRelevantMocksAndGetRequest(ThreadContext threadContext ) {
        // Mock Netty attributes
        RestRequest request = mock(RestRequest.class);
        org.opensearch.http.HttpChannel httpChannel = mock(org.opensearch.http.HttpChannel.class);
        io.netty.channel.Channel nettyChannel = mock(io.netty.channel.Channel.class);

        doReturn(httpChannel).doReturn(httpChannel).doReturn(null).when(request).getHttpChannel();
        doReturn(Optional.of(nettyChannel)).when(httpChannel).get("channel", io.netty.channel.Channel.class);

        io.netty.util.Attribute<ThreadContext.StoredContext> contextAttr = mock(io.netty.util.Attribute.class);
        io.netty.util.Attribute<SecurityResponse> earlyResponseAttr = mock(io.netty.util.Attribute.class);
        doReturn(contextAttr).when(nettyChannel).attr(Netty4HttpRequestHeaderVerifier.CONTEXT_TO_RESTORE);
        doReturn(earlyResponseAttr).when(nettyChannel).attr(Netty4HttpRequestHeaderVerifier.EARLY_RESPONSE);
        doReturn(null).when(earlyResponseAttr).getAndSet(null);

        ThreadContext.StoredContext storedContext = threadContext.newStoredContext(true);
        doReturn(storedContext).when(contextAttr).getAndSet(null);
        return request;
    }
}
