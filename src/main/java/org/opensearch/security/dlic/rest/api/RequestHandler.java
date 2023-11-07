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
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Predicate;

import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.common.CheckedFunction;
import org.opensearch.common.TriConsumer;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;

import static org.opensearch.security.dlic.rest.api.Responses.created;
import static org.opensearch.security.dlic.rest.api.Responses.forbidden;
import static org.opensearch.security.dlic.rest.api.Responses.methodNotImplemented;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.Responses.response;

@FunctionalInterface
public interface RequestHandler {

    RequestHandler methodNotImplementedHandler = (channel, request, client) -> methodNotImplemented(channel, request.method());

    RequestHandler accessDeniedHandler = (channel, request, client) -> forbidden(channel, "Access denied");

    void handle(final RestChannel channel, final RestRequest request, final Client client) throws IOException;

    final class RequestHandlersBuilder {

        static final Set<RestRequest.Method> SUPPORTED_METHODS = Set.of(
            RestRequest.Method.DELETE,
            RestRequest.Method.GET,
            RestRequest.Method.PATCH,
            RestRequest.Method.POST,
            RestRequest.Method.PUT
        );

        static final Set<RestRequest.Method> ON_CHANGE_REQUEST = Set.of(
            RestRequest.Method.DELETE,
            RestRequest.Method.PATCH,
            RestRequest.Method.PUT
        );

        private TriConsumer<
            Client,
            SecurityDynamicConfiguration<?>,
            AbstractApiAction.OnSucessActionListener<IndexResponse>> saveOrUpdateConfigurationHandler;

        private Predicate<RestRequest> accessHandler;

        private boolean checkPermissions = false;

        final Map<RestRequest.Method, RequestHandler> requestHandlers = new HashMap<>();

        RequestHandlersBuilder() {
            SUPPORTED_METHODS.forEach(method -> requestHandlers.put(method, methodNotImplementedHandler));
        }

        public RequestHandlersBuilder verifyAccessForAllMethods() {
            this.checkPermissions = true;
            final var handlers = build();
            handlers.forEach(this::add);
            return this;
        }

        public RequestHandlersBuilder allMethodsNotImplemented() {
            final var handlers = build();
            handlers.forEach((method, requestHandler) -> add(method, methodNotImplementedHandler));
            return this;
        }

        public RequestHandlersBuilder add(final RestRequest.Method method, RequestHandler requestHandler) {
            if (!SUPPORTED_METHODS.contains(method)) {
                throw new IllegalArgumentException("Unsupported HTTP method " + method + ". Supported are: " + SUPPORTED_METHODS);
            }
            if (checkPermissions && requestHandler != methodNotImplementedHandler) {
                requestHandlers.put(method, (channel, request, client) -> {
                    if (accessHandler.test(request)) {
                        requestHandler.handle(channel, request, client);
                    } else {
                        accessDeniedHandler.handle(channel, request, client);
                    }
                });
            } else {
                requestHandlers.put(method, requestHandler);
            }
            return this;
        }

        public RequestHandlersBuilder override(final RestRequest.Method method, RequestHandler requestOperationHandler) {
            add(method, requestOperationHandler);
            return this;
        }

        public RequestHandlersBuilder withAccessHandler(final Predicate<RestRequest> accessHandler) {
            this.accessHandler = Objects.requireNonNull(accessHandler, "accessHandler can't be null");
            return this;
        }

        RequestHandlersBuilder withSaveOrUpdateConfigurationHandler(
            final TriConsumer<
                Client,
                SecurityDynamicConfiguration<?>,
                AbstractApiAction.OnSucessActionListener<IndexResponse>> saveOrUpdateConfigurationHandler
        ) {
            this.saveOrUpdateConfigurationHandler = Objects.requireNonNull(
                saveOrUpdateConfigurationHandler,
                "saveOrUpdateConfigurationHandler can't be null"
            );
            return this;
        }

        public RequestHandlersBuilder onGetRequest(
            final CheckedFunction<RestRequest, ValidationResult<SecurityConfiguration>, IOException> mapper
        ) {
            Objects.requireNonNull(mapper, "onGetRequest request handler can't be null");
            add(
                RestRequest.Method.GET,
                (channel, request, client) -> mapper.apply(request)
                    .valid(securityConfiguration -> ok(channel, securityConfiguration.configuration()))
                    .error((status, toXContent) -> response(channel, status, toXContent))
            );
            return this;
        }

        public RequestHandlersBuilder onChangeRequest(
            final RestRequest.Method method,
            final CheckedFunction<RestRequest, ValidationResult<SecurityConfiguration>, IOException> mapper
        ) {
            Objects.requireNonNull(method, "method can't be null");
            Objects.requireNonNull(mapper, "onChangeRequest handler can't be null");
            if (!ON_CHANGE_REQUEST.contains(method)) {
                throw new IllegalArgumentException("Unsupported HTTP method " + method + ". Supported are: " + ON_CHANGE_REQUEST);
            }
            switch (method) {
                case PATCH:
                    add(
                        method,
                        (channel, request, client) -> mapper.apply(request)
                            .valid(
                                securityConfiguration -> saveOrUpdateConfigurationHandler.apply(
                                    client,
                                    securityConfiguration.configuration(),
                                    new AbstractApiAction.OnSucessActionListener<>(channel) {
                                        @Override
                                        public void onResponse(IndexResponse indexResponse) {
                                            if (securityConfiguration.maybeEntityName().isPresent()) {
                                                ok(channel, "'" + securityConfiguration.entityName() + "' updated.");
                                            } else {
                                                ok(channel, "Resource updated.");
                                            }
                                        }
                                    }
                                )
                            )
                            .error((status, toXContent) -> response(channel, status, toXContent))
                    );
                    break;
                case PUT:
                    add(method, (channel, request, client) -> mapper.apply(request).valid(securityConfiguration -> {
                        saveOrUpdateConfigurationHandler.apply(
                            client,
                            securityConfiguration.configuration(),
                            new AbstractApiAction.OnSucessActionListener<>(channel) {
                                @Override
                                public void onResponse(IndexResponse response) {
                                    if (securityConfiguration.entityExists()) {
                                        ok(channel, "'" + securityConfiguration.entityName() + "' updated.");
                                    } else {
                                        created(channel, "'" + securityConfiguration.entityName() + "' created.");
                                    }
                                }
                            }
                        );
                    }).error((status, toXContent) -> response(channel, status, toXContent)));
                    break;
                case DELETE:
                    Objects.requireNonNull(mapper, "onDeleteRequest request handler can't be null");
                    add(
                        RestRequest.Method.DELETE,
                        (channel, request, client) -> mapper.apply(request)
                            .valid(
                                securityConfiguration -> saveOrUpdateConfigurationHandler.apply(
                                    client,
                                    securityConfiguration.configuration(),
                                    new AbstractApiAction.OnSucessActionListener<>(channel) {
                                        @Override
                                        public void onResponse(IndexResponse response) {
                                            ok(channel, "'" + securityConfiguration.entityName() + "' deleted.");
                                        }
                                    }
                                )
                            )
                            .error((status, toXContent) -> response(channel, status, toXContent))
                    );
                    break;
            }
            return this;
        }

        public void configureRequestHandlers(final Consumer<RequestHandlersBuilder> requestHandlersBuilderHandler) {
            requestHandlersBuilderHandler.accept(this);
        }

        public Map<RestRequest.Method, RequestHandler> build() {
            Objects.requireNonNull(accessHandler, "accessHandler hasn't been set");
            Objects.requireNonNull(saveOrUpdateConfigurationHandler, "saveOrUpdateConfigurationHandler hasn't been set");
            return Map.copyOf(requestHandlers);
        }

    }

}
