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
import java.util.HashSet;
import java.util.concurrent.TimeUnit;

import org.apache.lucene.tests.util.LuceneTestCase;
import org.junit.After;
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
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.node.NodeClient;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

public class SecurityRestFilterUnitTests extends LuceneTestCase {

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
    public void setupSecurityRestFilter() throws NoSuchMethodException {
        testRestHandler = new TestRestHandler();

        threadPool = spy(new ThreadPool(Settings.builder().put("node.name", "mock").build()));
        doReturn(new ThreadContext(Settings.EMPTY)).when(threadPool).getThreadContext();

        sf = new SecurityRestFilter(
            mock(BackendRegistry.class),
            mock(RestLayerPrivilegesEvaluator.class),
            mock(AuditLog.class),
            threadPool,
            mock(PrincipalExtractor.class),
            Settings.EMPTY,
            mock(Path.class),
            mock(CompatConfig.class)
        );
    }

    @After
    public void shutdownThreadPool() {
        ThreadPool.terminate(threadPool, 10, TimeUnit.SECONDS);
    }

    /**
     * Tests to ensure that the output of {@link SecurityRestFilter#wrap} is an instance of AuthczRestHandler
     */
    @Test
    public void testSecurityRestFilterWrap() throws Exception {
        AdminDNs adminDNs = mock(AdminDNs.class);

        RestHandler wrappedRestHandler = sf.wrap(testRestHandler, adminDNs, new HashSet<>());

        assertTrue(wrappedRestHandler instanceof SecurityRestFilter.AuthczRestHandler);
        assertFalse(wrappedRestHandler instanceof TestRestHandler);
    }

    @Test
    public void testDoesCallDelegateOnSuccessfulAuthorization() throws Exception {
        SecurityRestFilter filterSpy = spy(sf);
        AdminDNs adminDNs = mock(AdminDNs.class);

        RestHandler testRestHandlerSpy = spy(testRestHandler);
        RestHandler wrappedRestHandler = filterSpy.wrap(testRestHandlerSpy, adminDNs, new HashSet<>());

        doReturn(false).when(filterSpy).userIsSuperAdmin(any(), any());

        wrappedRestHandler.handleRequest(mock(RestRequest.class), mock(RestChannel.class), mock(NodeClient.class));

        verify(testRestHandlerSpy).handleRequest(any(), any(), any());
    }

    // unit tests for restPathMatches are in RestPathMatchesTests.java

    // --- Tests for sanitizeRequestId ---

    @Test
    public void testSanitizeRequestIdNullGeneratesId() {
        String result = SecurityRestFilter.sanitizeRequestId(null);
        assertNotNull(result);
        // UUIDs.base64UUID() produces a 22-char base64-encoded ID (not standard UUID format)
        assertTrue(result.length() > 0);
    }

    @Test
    public void testSanitizeRequestIdEmptyGeneratesId() {
        String result = SecurityRestFilter.sanitizeRequestId("");
        assertNotNull(result);
        assertTrue(result.length() > 0);
    }

    @Test
    public void testSanitizeRequestIdPreservesValidInput() {
        String result = SecurityRestFilter.sanitizeRequestId("my-trace-id-123");
        assertEquals("my-trace-id-123", result);
    }

    @Test
    public void testSanitizeRequestIdExactly128CharsPreserved() {
        String input = "a".repeat(128);
        String result = SecurityRestFilter.sanitizeRequestId(input);
        assertEquals(128, result.length());
        assertEquals(input, result);
    }

    @Test
    public void testSanitizeRequestIdOver128CharsNotTruncated() {
        // No truncation — core's http.request_id.max_length validates before header reaches us
        String input = "b".repeat(200);
        String result = SecurityRestFilter.sanitizeRequestId(input);
        assertEquals(200, result.length());
        assertEquals(input, result);
    }

    @Test
    public void testSanitizeRequestIdStripsControlChars() {
        String result = SecurityRestFilter.sanitizeRequestId("valid\u0000id\u001F\nhere");
        assertEquals("valididhere", result);
    }

    @Test
    public void testSanitizeRequestIdAllControlCharsReturnsNull() {
        // Input entirely control characters → empty after stripping → null (not UUID)
        // Prevents different nodes from generating different IDs for the same request
        String result = SecurityRestFilter.sanitizeRequestId("\u0000\u0001\u0002\n\r\t");
        assertNull(result);
    }

    @Test
    public void testSanitizeRequestIdStripsControlCharsPreservesLength() {
        // 5 control chars + 200 valid chars → strip → 200 chars (no truncation)
        String input = "\u0000\u0001\u0002\u0003\u0004" + "c".repeat(200);
        String result = SecurityRestFilter.sanitizeRequestId(input);
        assertEquals(200, result.length());
        assertEquals("c".repeat(200), result);
    }

}
