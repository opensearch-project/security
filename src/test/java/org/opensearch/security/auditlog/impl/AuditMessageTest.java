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

package org.opensearch.security.auditlog.impl;

import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.junit.Before;
import org.junit.Test;

import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.collect.Tuple;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.http.HttpChannel;
import org.opensearch.http.HttpRequest;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.filter.SecurityRequestFactory;
import org.opensearch.security.securityconf.impl.CType;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuditMessageTest {

    private static final Map<String, List<String>> TEST_REST_HEADERS = ImmutableMap.of(
        "authorization",
        ImmutableList.of("test-1"),
        "Authorization",
        ImmutableList.of("test-2"),
        "AuThOrIzAtIoN",
        ImmutableList.of("test-3"),
        "test-header",
        ImmutableList.of("test-4")
    );

    private static final Map<String, String> TEST_TRANSPORT_HEADERS = ImmutableMap.of(
        "authorization",
        "test-1",
        "Authorization",
        "test-2",
        "AuThOrIzAtIoN",
        "test-3",
        "test-header",
        "test-4"
    );

    private AuditMessage message;
    private AuditConfig auditConfig;

    @Before
    public void setUp() {
        final ClusterService clusterServiceMock = mock(ClusterService.class);
        when(clusterServiceMock.localNode()).thenReturn(mock(DiscoveryNode.class));
        when(clusterServiceMock.getClusterName()).thenReturn(mock(ClusterName.class));
        auditConfig = mock(AuditConfig.class);
        final AuditConfig.Filter auditFilter = mock(AuditConfig.Filter.class);
        when(auditConfig.getFilter()).thenReturn(auditFilter);
        message = new AuditMessage(AuditCategory.AUTHENTICATED, clusterServiceMock, AuditLog.Origin.REST, AuditLog.Origin.REST);
    }

    @Test
    public void testAuthorizationRestHeadersAreFiltered() {
        when(auditConfig.getFilter().shouldExcludeHeader("test-header")).thenReturn(false);
        message.addRestHeaders(TEST_REST_HEADERS, true, auditConfig.getFilter());
        assertEquals(message.getAsMap().get(AuditMessage.REST_REQUEST_HEADERS), ImmutableMap.of("test-header", ImmutableList.of("test-4")));
    }

    @Test
    public void testCustomRestHeadersAreFiltered() {
        when(auditConfig.getFilter().shouldExcludeHeader("test-header")).thenReturn(true);
        message.addRestHeaders(TEST_REST_HEADERS, true, auditConfig.getFilter());
        assertEquals(message.getAsMap().get(AuditMessage.REST_REQUEST_HEADERS), Map.of());
    }

    @Test
    public void testRestHeadersNull() {
        message.addRestHeaders(null, true, null);
        assertNull(message.getAsMap().get(AuditMessage.REST_REQUEST_HEADERS));
        message.addRestHeaders(Collections.emptyMap(), true, null);
        assertNull(message.getAsMap().get(AuditMessage.REST_REQUEST_HEADERS));
    }

    @Test
    public void testRestHeadersAreNotFiltered() {
        when(auditConfig.getFilter().shouldExcludeHeader("test-header")).thenReturn(false);
        message.addRestHeaders(TEST_REST_HEADERS, false, null);
        assertEquals(message.getAsMap().get(AuditMessage.REST_REQUEST_HEADERS), TEST_REST_HEADERS);
    }

    @Test
    public void testTransportHeadersNull() {
        message.addTransportHeaders(null, true);
        assertNull(message.getAsMap().get(AuditMessage.TRANSPORT_REQUEST_HEADERS));
        message.addTransportHeaders(Collections.emptyMap(), true);
        assertNull(message.getAsMap().get(AuditMessage.TRANSPORT_REQUEST_HEADERS));
    }

    @Test
    public void testTransportHeadersAreFiltered() {
        message.addTransportHeaders(TEST_TRANSPORT_HEADERS, true);
        assertEquals(message.getAsMap().get(AuditMessage.TRANSPORT_REQUEST_HEADERS), ImmutableMap.of("test-header", "test-4"));
    }

    @Test
    public void testTransportHeadersAreNotFiltered() {
        message.addTransportHeaders(TEST_TRANSPORT_HEADERS, false);
        assertEquals(message.getAsMap().get(AuditMessage.TRANSPORT_REQUEST_HEADERS), TEST_TRANSPORT_HEADERS);
    }

    @Test
    public void testBCryptHashIsRedacted() {
        final String internalUsersDocId = CType.INTERNALUSERS.toLCString();
        final String hash1 = "$2y$12$gpTlsqv8yYsbR7P.fFbZ5uYXxUmGY4oLYeJNOMiz23ByrRMNFgBGm";
        final String hash2 = "$2y$12$tPnP6XpeRuBTPXBG1XVJCOsZ4xi6eRs4yFnrbynyoWnYJmfAxTNZ6";

        // does not perform redaction for non-internal user doc
        message.addSecurityConfigContentToRequestBody(hash1, "test-doc");
        assertEquals(hash1, message.getAsMap().get(AuditMessage.REQUEST_BODY));

        // test hash redaction
        message.addSecurityConfigContentToRequestBody(hash1, internalUsersDocId);
        assertEquals("__HASH__", message.getAsMap().get(AuditMessage.REQUEST_BODY));

        // test hash redaction in string
        message.addSecurityConfigContentToRequestBody("Hash " + hash2 + " is redacted", internalUsersDocId);
        assertEquals("Hash __HASH__ is redacted", message.getAsMap().get(AuditMessage.REQUEST_BODY));

        // test hash redaction inline without spaces
        message.addSecurityConfigContentToRequestBody("Inline hash" + hash2 + "is redacted", internalUsersDocId);
        assertEquals("Inline hash__HASH__is redacted", message.getAsMap().get(AuditMessage.REQUEST_BODY));

        // test map redaction
        message.addSecurityConfigWriteDiffSource("Diff is " + hash2, internalUsersDocId);
        assertEquals("Diff is __HASH__", message.getAsMap().get(AuditMessage.COMPLIANCE_DIFF_CONTENT));

        // test tuple redaction
        final ByteBuffer[] byteBuffers = new ByteBuffer[] { ByteBuffer.wrap(("Hash in tuple is " + hash1).getBytes()) };
        BytesReference ref = BytesReference.fromByteBuffers(byteBuffers);
        message.addSecurityConfigTupleToRequestBody(new Tuple<>(XContentType.JSON, ref), internalUsersDocId);
        assertEquals("Hash in tuple is __HASH__", message.getAsMap().get(AuditMessage.REQUEST_BODY));
    }

    @Test
    public void testRequestBodyLoggingWithInvalidSourceOrContentTypeParam() {
        when(auditConfig.getFilter().shouldLogRequestBody()).thenReturn(true);

        HttpRequest httpRequest = mock(HttpRequest.class);

        // No content or Source paramater
        when(httpRequest.uri()).thenReturn("");
        when(httpRequest.content()).thenReturn(new BytesArray(new byte[0]));

        RestRequest restRequest = RestRequest.request(mock(NamedXContentRegistry.class), httpRequest, mock(HttpChannel.class));
        SecurityRequest request = SecurityRequestFactory.from(restRequest);

        message.addRestRequestInfo(request, auditConfig.getFilter());
        assertNull(message.getAsMap().get(AuditMessage.REQUEST_BODY));

        // No source parameter, content present but Invalid content-type header
        when(httpRequest.uri()).thenReturn("");
        when(httpRequest.content()).thenReturn(new BytesArray(new byte[1]));

        restRequest = RestRequest.request(mock(NamedXContentRegistry.class), httpRequest, mock(HttpChannel.class));
        request = SecurityRequestFactory.from(restRequest);

        message.addRestRequestInfo(request, auditConfig.getFilter());
        assertEquals("ERROR: Unable to generate request body", message.getAsMap().get(AuditMessage.REQUEST_BODY));

        // No content, source parameter present but Invalid source-content-type parameter
        when(httpRequest.uri()).thenReturn("/aaaa?source=request_body");
        when(httpRequest.content()).thenReturn(new BytesArray(new byte[0]));

        restRequest = RestRequest.request(mock(NamedXContentRegistry.class), httpRequest, mock(HttpChannel.class));
        request = SecurityRequestFactory.from(restRequest);

        message.addRestRequestInfo(request, auditConfig.getFilter());
        assertEquals("ERROR: Unable to generate request body", message.getAsMap().get(AuditMessage.REQUEST_BODY));
    }
}
