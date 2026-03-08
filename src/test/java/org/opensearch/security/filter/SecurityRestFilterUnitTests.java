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
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.CompatConfig;
import org.opensearch.security.privileges.RestLayerPrivilegesEvaluator;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.telemetry.tracing.Span;
import org.opensearch.telemetry.tracing.TracerContextStorage;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.node.NodeClient;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class SecurityRestFilterUnitTests {

    SecurityRestFilter sf;
    RestHandler testRestHandler;

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

    /**
     * Test that current_span transient is preserved after context restoration.
     * We have avoided static mock here hence, we are just checking if our fix helps with the bug
     */
    @Test
    public void testCurrentSpanTransientPreservedAfterRestore() throws Exception {
        ThreadPool tp = spy(new ThreadPool(Settings.builder().put("node.name", "mock").build()));
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        doReturn(threadContext).when(tp).getThreadContext();

        Span mockSpan = mock(Span.class);

        Set<String> transientsToCopy = new HashSet<>(List.of(TracerContextStorage.CURRENT_SPAN));
        // Create a stored context without current_span (simulates stashContext clearing it)
        ThreadContext.StoredContext storedContext = threadContext.newStoredContext(false);

        // Now add current_span to the current context (simulates it being set after stash)
        threadContext.putTransient(TracerContextStorage.CURRENT_SPAN, mockSpan);

        // Save the span before restore
        Map<String, Object> trasients = null;
        for (String transientValue : transientsToCopy) {
            final Object value = threadContext.getTransient(transientValue);
            if (value != null) {
                if (trasients == null) {
                    trasients = new HashMap<>();
                }
                trasients.put(transientValue, value);
            }
        }

        // Restore the stored context (this wipes current_span)
        storedContext.restore();

        // Apply the fix: restore current_span if it was wiped
        if(trasients != null) {
            for (Map.Entry<String, Object> transientVal : trasients.entrySet()) {
                threadContext.putTransient(transientVal.getKey(), transientVal.getValue());
            }
        }

        assertNotNull("current_span should be preserved", threadContext.getTransient(TracerContextStorage.CURRENT_SPAN));
    }

}
