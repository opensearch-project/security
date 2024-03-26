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

import org.junit.Test;

import org.opensearch.http.netty4.Netty4HttpChannel;

import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpVersion;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

public class SecurityRestUtilsTests {

    @Test
    public void testShouldSkipAuthentication_positive() {
        FullHttpRequest request1 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.OPTIONS, "/");
        NettyRequestChannel requestChannel1 = new NettyRequestChannel(request1, mock(Netty4HttpChannel.class));

        assertTrue(SecurityRestUtils.shouldSkipAuthentication(requestChannel1));

        FullHttpRequest request2 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/_plugins/_security/health");
        NettyRequestChannel requestChannel2 = new NettyRequestChannel(request2, mock(Netty4HttpChannel.class));

        assertTrue(SecurityRestUtils.shouldSkipAuthentication(requestChannel2));

        FullHttpRequest request3 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/_plugins/_security/whoami");
        NettyRequestChannel requestChannel3 = new NettyRequestChannel(request3, mock(Netty4HttpChannel.class));

        assertTrue(SecurityRestUtils.shouldSkipAuthentication(requestChannel3));
    }

    @Test
    public void testShouldSkipAuthentication_negative() {
        FullHttpRequest request1 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/");
        NettyRequestChannel requestChannel1 = new NettyRequestChannel(request1, mock(Netty4HttpChannel.class));

        assertFalse(SecurityRestUtils.shouldSkipAuthentication(requestChannel1));

        FullHttpRequest request2 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/_cluster/health");
        NettyRequestChannel requestChannel2 = new NettyRequestChannel(request2, mock(Netty4HttpChannel.class));

        assertFalse(SecurityRestUtils.shouldSkipAuthentication(requestChannel2));

        FullHttpRequest request3 = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/my-index/_search");
        NettyRequestChannel requestChannel3 = new NettyRequestChannel(request3, mock(Netty4HttpChannel.class));

        assertFalse(SecurityRestUtils.shouldSkipAuthentication(requestChannel3));
    }

    @Test
    public void testGetRawPath() {
        String rawPathWithParams = "/_cluster/health?pretty";
        String rawPathWithoutParams = "/my-index/search";

        String path1 = SecurityRestUtils.path(rawPathWithParams);
        String path2 = SecurityRestUtils.path(rawPathWithoutParams);

        assertTrue("/_cluster/health".equals(path1));
        assertTrue("/my-index/search".equals(path2));
    }
}
