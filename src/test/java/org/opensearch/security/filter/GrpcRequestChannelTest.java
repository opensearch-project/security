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

import java.util.List;
import java.util.Map;

import org.junit.Test;

import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.ServerCall;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class GrpcRequestChannelTest {

    private static class TestMarshaller<T> implements MethodDescriptor.Marshaller<T> {
        @Override
        public java.io.InputStream stream(T value) {
            return new java.io.ByteArrayInputStream(new byte[0]);
        }

        @Override
        public T parse(java.io.InputStream stream) {
            return null;
        }
    }

    private ServerCall<Object, Object> createMockServerCall(String methodName) {
        @SuppressWarnings("unchecked")
        ServerCall<Object, Object> serverCall = mock(ServerCall.class);

        // Create a real MethodDescriptor instead of mocking
        MethodDescriptor<Object, Object> methodDescriptor = MethodDescriptor.newBuilder()
            .setType(MethodDescriptor.MethodType.UNARY)
            .setFullMethodName(methodName)
            .setRequestMarshaller(new TestMarshaller<>())
            .setResponseMarshaller(new TestMarshaller<>())
            .build();

        when(serverCall.getMethodDescriptor()).thenReturn(methodDescriptor);
        return serverCall;
    }

    @Test
    public void testHeaderExtraction() {
        ServerCall<Object, Object> serverCall = createMockServerCall("org.opensearch.protobufs.services.DocumentService/Bulk");

        Metadata metadata = new Metadata();
        Metadata.Key<String> authKey = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
        Metadata.Key<String> jwtKey = Metadata.Key.of("jwt-auth", Metadata.ASCII_STRING_MARSHALLER);
        metadata.put(authKey, "Bearer token123");
        metadata.put(jwtKey, "Bearer jwt456");

        // Create GrpcRequestChannel
        GrpcRequestChannel channel = new GrpcRequestChannel(serverCall, metadata);

        // Test header extraction
        Map<String, List<String>> headers = channel.getHeaders();
        assertNotNull(headers);
        assertEquals("Bearer token123", headers.get("authorization").get(0));
        assertEquals("Bearer jwt456", headers.get("jwt-auth").get(0));

        // Test header() method
        assertEquals("Bearer token123", channel.header("authorization"));
        assertEquals("Bearer jwt456", channel.header("jwt-auth"));
    }

    @Test
    public void testPathAndUri() {
        ServerCall<Object, Object> serverCall = createMockServerCall("org.opensearch.protobufs.services.DocumentService/Bulk");

        Metadata metadata = new Metadata();
        GrpcRequestChannel channel = new GrpcRequestChannel(serverCall, metadata);

        assertEquals("org.opensearch.protobufs.services.DocumentService/Bulk", channel.path());
        assertEquals("org.opensearch.protobufs.services.DocumentService/Bulk", channel.uri());
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testGetSSLEngineThrowsException() {
        ServerCall<Object, Object> serverCall = createMockServerCall("test.Service/Method");
        Metadata metadata = new Metadata();
        GrpcRequestChannel channel = new GrpcRequestChannel(serverCall, metadata);

        channel.getSSLEngine();
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testMethodThrowsException() {
        ServerCall<Object, Object> serverCall = createMockServerCall("test.Service/Method");
        Metadata metadata = new Metadata();
        GrpcRequestChannel channel = new GrpcRequestChannel(serverCall, metadata);

        channel.method();
    }

    @Test
    public void testEmptyParams() {
        ServerCall<Object, Object> serverCall = createMockServerCall("test.Service/Method");
        Metadata metadata = new Metadata();
        GrpcRequestChannel channel = new GrpcRequestChannel(serverCall, metadata);

        assertTrue(channel.params().isEmpty());
        assertTrue(channel.getUnconsumedParams().isEmpty());
    }

    @Test
    public void testRemoteAddressEmpty() {
        ServerCall<Object, Object> serverCall = createMockServerCall("test.Service/Method");
        Metadata metadata = new Metadata();
        GrpcRequestChannel channel = new GrpcRequestChannel(serverCall, metadata);

        assertTrue(channel.getRemoteAddress().isEmpty());
    }

    @Test
    public void testSecurityRequestFactory() {
        ServerCall<Object, Object> serverCall = createMockServerCall("test.Service/Method");

        Metadata metadata = new Metadata();
        Metadata.Key<String> testKey = Metadata.Key.of("test-header", Metadata.ASCII_STRING_MARSHALLER);
        metadata.put(testKey, "test-value");

        // Test factory method
        SecurityRequestChannel channel = SecurityRequestFactory.from(serverCall, metadata);

        assertNotNull(channel);
        assertTrue(channel instanceof GrpcRequestChannel);
        assertEquals("test.Service/Method", channel.path());
        assertEquals("test-value", channel.header("test-header"));
    }
}
