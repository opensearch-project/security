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

package org.opensearch.security.dlic.rest.api;

import java.io.IOException;
import java.util.stream.Collectors;

import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.dlic.rest.validation.ValidationResult;

import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class RequestHandlersBuilderTest {

    @Mock
    RestChannel channel;

    @Mock
    RestRequest request;

    @Mock
    Client client;

    @Captor
    ArgumentCaptor<BytesRestResponse> responseArgumentCaptor;

    @Test
    public void checkPermissionsForAllMethodsOnDemand() throws IOException {
        var requestHandlers = new RequestHandler.RequestHandlersBuilder().withAccessHandler(r -> false)
            .withSaveOrUpdateConfigurationHandler((client, configuration, indexResponseOnSucessActionListener) -> {})
            .add(RestRequest.Method.PATCH, (channel, request, client) -> {})
            .add(RestRequest.Method.POST, RequestHandler.methodNotImplementedHandler)
            .add(RestRequest.Method.PUT, (channel, request, client) -> {})
            .onGetRequest(request -> ValidationResult.success(null))
            .verifyAccessForAllMethods()
            .onChangeRequest(RestRequest.Method.DELETE, request -> ValidationResult.success(null))
            .build();

        for (final var method : RequestHandler.RequestHandlersBuilder.SUPPORTED_METHODS) {
            when(request.method()).thenReturn(method);
            when(channel.newBuilder()).thenReturn(XContentFactory.jsonBuilder());
            requestHandlers.get(method).handle(channel, request, client);
            verify(channel).sendResponse(responseArgumentCaptor.capture());
            final var responseBytes = responseArgumentCaptor.getValue();
            final var json = DefaultObjectMapper.readTree(responseBytes.content().utf8ToString());
            if (method == RestRequest.Method.POST) {
                assertEquals(RestStatus.NOT_IMPLEMENTED.name(), json.get("status").asText());
            } else {
                assertEquals(RestStatus.FORBIDDEN.name(), json.get("status").asText());
            }
            reset(channel);
        }
    }

    @Test
    public void overrideDefaultHandlers() {
        var requestHandlers = new RequestHandler.RequestHandlersBuilder().withAccessHandler(r -> true)
            .withSaveOrUpdateConfigurationHandler((client, configuration, indexResponseOnSucessActionListener) -> {})
            .override(RestRequest.Method.PATCH, (channel, request, client) -> {})
            .build();

        assertNotEquals(RequestHandler.methodNotImplementedHandler, requestHandlers.get(RestRequest.Method.PATCH));

        requestHandlers = new RequestHandler.RequestHandlersBuilder().withAccessHandler(r -> true)
            .withSaveOrUpdateConfigurationHandler((client, configuration, indexResponseOnSucessActionListener) -> {})
            .add(RestRequest.Method.POST, RequestHandler.methodNotImplementedHandler)
            .add(RestRequest.Method.PATCH, (channel, request, client) -> {})
            .add(RestRequest.Method.DELETE, (channel, request, client) -> {})
            .add(RestRequest.Method.POST, (channel, request, client) -> {})
            .build();

        assertNotEquals(RequestHandler.methodNotImplementedHandler, requestHandlers.get(RestRequest.Method.POST));

        requestHandlers = new RequestHandler.RequestHandlersBuilder().withAccessHandler(r -> true)
            .withSaveOrUpdateConfigurationHandler((client, configuration, indexResponseOnSucessActionListener) -> {})
            .add(RestRequest.Method.DELETE, RequestHandler.methodNotImplementedHandler)
            .add(RestRequest.Method.POST, (channel, request, client) -> {})
            .add(RestRequest.Method.PATCH, (channel, request, client) -> {})
            .add(RestRequest.Method.DELETE, (channel, request, client) -> {})
            .build();
        assertNotEquals(RequestHandler.methodNotImplementedHandler, requestHandlers.get(RestRequest.Method.DELETE));
    }

    @Test
    public void allSupportedMethodsNotImplementedByDefault() {
        final var requestHandlers = new RequestHandler.RequestHandlersBuilder().withAccessHandler(r -> true)
            .withSaveOrUpdateConfigurationHandler((client, configuration, indexResponseOnSucessActionListener) -> {})
            .build();

        assertEquals(
            RequestHandler.RequestHandlersBuilder.SUPPORTED_METHODS.stream().sorted().collect(Collectors.toList()),
            requestHandlers.keySet().stream().sorted().collect(Collectors.toList())
        );
        requestHandlers.forEach(
            ((method, requestOperationHandler) -> assertEquals(RequestHandler.methodNotImplementedHandler, requestOperationHandler))
        );
    }

    @Test
    public void failsForNullRequestHandlers() {
        final var requestHandlersBuilder = new RequestHandler.RequestHandlersBuilder();
        assertThrows(
            NullPointerException.class,
            () -> requestHandlersBuilder.onChangeRequest(null, request -> ValidationResult.success(null))
        );
        assertThrows(NullPointerException.class, () -> requestHandlersBuilder.onChangeRequest(RestRequest.Method.PATCH, null));
        assertThrows(NullPointerException.class, () -> requestHandlersBuilder.onChangeRequest(RestRequest.Method.PUT, null));
        assertThrows(NullPointerException.class, () -> requestHandlersBuilder.onChangeRequest(RestRequest.Method.DELETE, null));
        assertThrows(NullPointerException.class, () -> requestHandlersBuilder.onGetRequest(null));
    }

    @Test
    public void failsForUnsupportedMethods() {
        final var requestHandlersBuilder = new RequestHandler.RequestHandlersBuilder();
        assertThrows(
            IllegalArgumentException.class,
            () -> requestHandlersBuilder.add(RestRequest.Method.CONNECT, RequestHandler.methodNotImplementedHandler)
        );
        assertThrows(
            IllegalArgumentException.class,
            () -> requestHandlersBuilder.override(RestRequest.Method.OPTIONS, RequestHandler.methodNotImplementedHandler)
        );
    }

    @Test
    public void failsForUnsupportedMethodsForCreateOrUpdateHandler() {
        final var requestHandlersBuilder = new RequestHandler.RequestHandlersBuilder();
        assertThrows(IllegalArgumentException.class, () -> requestHandlersBuilder.onChangeRequest(RestRequest.Method.OPTIONS, r -> null));
        assertThrows(IllegalArgumentException.class, () -> requestHandlersBuilder.onChangeRequest(RestRequest.Method.GET, r -> null));
    }

    @Test
    public void failsForNullHandlers() {
        final var requestHandlersBuilder = new RequestHandler.RequestHandlersBuilder();
        assertThrows(NullPointerException.class, () -> requestHandlersBuilder.withAccessHandler(null));
        assertThrows(NullPointerException.class, () -> requestHandlersBuilder.withSaveOrUpdateConfigurationHandler(null));
    }

    @Test
    public void buildFailsIfHandlersNotSet() {
        final var requestHandlersBuilder = new RequestHandler.RequestHandlersBuilder();
        requestHandlersBuilder.override(RestRequest.Method.DELETE, (channel, request, client) -> {});

        assertThrows(NullPointerException.class, requestHandlersBuilder::build);

        requestHandlersBuilder.withAccessHandler(r -> true);
        assertThrows(NullPointerException.class, requestHandlersBuilder::build);

        requestHandlersBuilder.withAccessHandler(r -> true);
        requestHandlersBuilder.withSaveOrUpdateConfigurationHandler((client, configuration, indexResponseOnSucessActionListener) -> {});
        requestHandlersBuilder.build();
    }

}
