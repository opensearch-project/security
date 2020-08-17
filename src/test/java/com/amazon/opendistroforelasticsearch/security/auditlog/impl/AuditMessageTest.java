/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.auditlog.impl;

import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.service.ClusterService;
import org.junit.Before;
import org.junit.Test;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuditMessageTest {

    private static final Map<String, List<String>> TEST_REST_HEADERS = ImmutableMap.of(
            "authorization", ImmutableList.of("test-1"),
            "Authorization", ImmutableList.of("test-2"),
            "AuThOrIzAtIoN", ImmutableList.of("test-3"),
            "test-header", ImmutableList.of("test-4")
    );

    private static final Map<String, String> TEST_TRANSPORT_HEADERS = ImmutableMap.of(
            "authorization", "test-1",
            "Authorization", "test-2",
            "AuThOrIzAtIoN","test-3",
            "test-header", "test-4"
    );

    private AuditMessage message;

    @Before
    public void setUp() {
        final ClusterService clusterServiceMock = mock(ClusterService.class);
        when(clusterServiceMock.localNode()).thenReturn(mock(DiscoveryNode.class));
        when(clusterServiceMock.getClusterName()).thenReturn(mock(ClusterName.class));
        message = new AuditMessage(AuditCategory.AUTHENTICATED,
                clusterServiceMock,
                AuditLog.Origin.REST,
                AuditLog.Origin.REST);
    }

    @Test
    public void testRestHeadersAreFiltered() {
        message.addRestHeaders(TEST_REST_HEADERS, true);
        assertEquals(message.getAsMap().get(AuditMessage.REST_REQUEST_HEADERS), ImmutableMap.of("test-header", ImmutableList.of("test-4")));
    }

    @Test
    public void testRestHeadersNull() {
        message.addRestHeaders(null, true);
        assertNull(message.getAsMap().get(AuditMessage.REST_REQUEST_HEADERS));
        message.addRestHeaders(Collections.emptyMap(), true);
        assertNull(message.getAsMap().get(AuditMessage.REST_REQUEST_HEADERS));
    }

    @Test
    public void testRestHeadersAreNotFiltered() {
        message.addRestHeaders(TEST_REST_HEADERS, false);
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
}
