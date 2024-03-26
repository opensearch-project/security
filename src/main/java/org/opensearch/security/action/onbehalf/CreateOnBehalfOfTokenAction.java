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

package org.opensearch.security.action.onbehalf;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.client.node.NodeClient;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.identity.tokens.OnBehalfOfClaims;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.security.identity.SecurityTokenManager;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.support.Utils.PLUGIN_API_ROUTE_PREFIX;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class CreateOnBehalfOfTokenAction extends BaseRestHandler {

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(new NamedRoute.Builder().method(POST).path("/generateonbehalfoftoken").uniqueName("security:obo/create").build()),
        PLUGIN_API_ROUTE_PREFIX
    );

    public static final long OBO_DEFAULT_EXPIRY_SECONDS = 5 * 60;
    public static final long OBO_MAX_EXPIRY_SECONDS = 10 * 60;
    public static final String DEFAULT_SERVICE = "self-issued";

    private static final Logger LOG = LogManager.getLogger(CreateOnBehalfOfTokenAction.class);

    private final SecurityTokenManager securityTokenManager;

    public CreateOnBehalfOfTokenAction(final SecurityTokenManager securityTokenManager) {
        this.securityTokenManager = securityTokenManager;
    }

    @Override
    public String getName() {
        return getClass().getSimpleName();
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client) throws IOException {
        switch (request.method()) {
            case POST:
                return handlePost(request, client);
            default:
                throw new IllegalArgumentException(request.method() + " not supported");
        }
    }

    private RestChannelConsumer handlePost(final RestRequest request, final NodeClient client) throws IOException {
        return new RestChannelConsumer() {
            @Override
            public void accept(final RestChannel channel) throws Exception {
                final XContentBuilder builder = channel.newBuilder();
                BytesRestResponse response;
                try {
                    if (!securityTokenManager.issueOnBehalfOfTokenAllowed()) {
                        channel.sendResponse(
                            new BytesRestResponse(
                                RestStatus.BAD_REQUEST,
                                "The OnBehalfOf token generating API has been disabled, see {link to doc} for more information on this feature." /* TODO: Update the link to the documentation website */
                            )
                        );
                        return;
                    }

                    final Map<String, Object> requestBody = request.contentOrSourceParamParser().map();

                    validateRequestParameters(requestBody);

                    long tokenDuration = parseAndValidateDurationSeconds(requestBody.get(InputParameters.DURATION.paramName));
                    tokenDuration = Math.min(tokenDuration, OBO_MAX_EXPIRY_SECONDS);

                    final String description = (String) requestBody.getOrDefault(InputParameters.DESCRIPTION.paramName, null);
                    final String service = (String) requestBody.getOrDefault(InputParameters.SERVICE.paramName, DEFAULT_SERVICE);
                    final var token = securityTokenManager.issueOnBehalfOfToken(null, new OnBehalfOfClaims(service, tokenDuration));

                    builder.startObject();
                    builder.field("user", token.getSubject());
                    builder.field("authenticationToken", token.getCompleteToken());
                    builder.field("durationSeconds", token.getExpiresInSeconds());
                    builder.endObject();

                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final IllegalArgumentException iae) {
                    builder.startObject().field("error", iae.getMessage()).endObject();
                    response = new BytesRestResponse(RestStatus.BAD_REQUEST, builder);
                } catch (final Exception exception) {
                    LOG.error("Unexpected error occurred: ", exception);

                    builder.startObject().field("error", "An unexpected error occurred. Please check the input and try again.").endObject();

                    response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                }
                builder.close();
                channel.sendResponse(response);
            }
        };
    }

    private enum InputParameters {
        DURATION("durationSeconds"),
        DESCRIPTION("description"),
        SERVICE("service");

        final String paramName;

        private InputParameters(final String paramName) {
            this.paramName = paramName;
        }
    }

    private void validateRequestParameters(final Map<String, Object> requestBody) throws IllegalArgumentException {
        for (final String key : requestBody.keySet()) {
            Arrays.stream(InputParameters.values())
                .filter(param -> param.paramName.equalsIgnoreCase(key))
                .findAny()
                .orElseThrow(() -> new IllegalArgumentException("Unrecognized parameter: " + key));
        }
    }

    private long parseAndValidateDurationSeconds(final Object durationObj) throws IllegalArgumentException {
        if (durationObj == null) {
            return OBO_DEFAULT_EXPIRY_SECONDS;
        }

        if (durationObj instanceof Integer) {
            return (Integer) durationObj;
        } else if (durationObj instanceof String) {
            try {
                return Long.parseLong((String) durationObj);
            } catch (final NumberFormatException ignored) {}
        }
        throw new IllegalArgumentException("durationSeconds must be a number.");
    }
}
