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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.greenrobot.eventbus.Subscribe;

import org.opensearch.client.node.NodeClient;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.authtoken.jwt.JwtVendor;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class CreateOnBehalfOfTokenAction extends BaseRestHandler {

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(new NamedRoute.Builder().method(POST).path("/generateonbehalfoftoken").uniqueName("security:obo/create").build()),
        "/_plugins/_security/api"
    );

    private JwtVendor vendor;
    private final ThreadPool threadPool;
    private final ClusterService clusterService;

    private ConfigModel configModel;

    public static final Integer OBO_DEFAULT_EXPIRY_SECONDS = 5 * 60;
    public static final Integer OBO_MAX_EXPIRY_SECONDS = 10 * 60;

    public static final String DEFAULT_SERVICE = "self-issued";

    protected final Logger log = LogManager.getLogger(this.getClass());

    @Subscribe
    public void onConfigModelChanged(ConfigModel configModel) {
        this.configModel = configModel;
    }

    @Subscribe
    public void onDynamicConfigModelChanged(DynamicConfigModel dcm) {
        Settings settings = dcm.getDynamicOnBehalfOfSettings();

        Boolean enabled = Boolean.parseBoolean(settings.get("enabled"));
        String signingKey = settings.get("signing_key");
        String encryptionKey = settings.get("encryption_key");

        if (!Boolean.FALSE.equals(enabled) && signingKey != null && encryptionKey != null) {
            this.vendor = new JwtVendor(settings, Optional.empty());
        } else {
            this.vendor = null;
        }
    }

    public CreateOnBehalfOfTokenAction(final Settings settings, final ThreadPool threadPool, final ClusterService clusterService) {
        this.threadPool = threadPool;
        this.clusterService = clusterService;
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
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        switch (request.method()) {
            case POST:
                return handlePost(request, client);
            default:
                throw new IllegalArgumentException(request.method() + " not supported");
        }
    }

    private RestChannelConsumer handlePost(RestRequest request, NodeClient client) throws IOException {
        return new RestChannelConsumer() {
            @Override
            public void accept(RestChannel channel) throws Exception {
                final XContentBuilder builder = channel.newBuilder();
                BytesRestResponse response;
                try {
                    if (vendor == null) {
                        channel.sendResponse(
                            new BytesRestResponse(
                                RestStatus.SERVICE_UNAVAILABLE,
                                "The OnBehalfOf token generating API has been disabled, see {link to doc} for more information on this feature." /* TODO: Update the link to the documentation website */
                            )
                        );
                        return;
                    }

                    final String clusterIdentifier = clusterService.getClusterName().value();

                    final Map<String, Object> requestBody = request.contentOrSourceParamParser().map();

                    validateRequestParameters(requestBody);

                    Integer tokenDuration = parseAndValidateDurationSeconds(requestBody.get("durationSeconds"));
                    tokenDuration = Math.min(tokenDuration, OBO_MAX_EXPIRY_SECONDS);

                    final String description = (String) requestBody.getOrDefault("description", null);

                    final String service = (String) requestBody.getOrDefault("service", DEFAULT_SERVICE);
                    final User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                    Set<String> mappedRoles = mapRoles(user);

                    builder.startObject();
                    builder.field("user", user.getName());

                    final String token = vendor.createJwt(
                        clusterIdentifier,
                        user.getName(),
                        service,
                        tokenDuration,
                        mappedRoles.stream().collect(Collectors.toList()),
                        user.getRoles().stream().collect(Collectors.toList()),
                        false
                    );
                    builder.field("authenticationToken", token);
                    builder.field("durationSeconds", tokenDuration);
                    builder.endObject();

                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (IllegalArgumentException iae) {
                    builder.startObject().field("error", iae.getMessage()).endObject();
                    response = new BytesRestResponse(RestStatus.BAD_REQUEST, builder);
                } catch (final Exception exception) {
                    log.error("Unexpected error occurred: ", exception);

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

    private Set<String> mapRoles(final User user) {
        return this.configModel.mapSecurityRoles(user, null);
    }

    private void validateRequestParameters(Map<String, Object> requestBody) throws IllegalArgumentException {
        for (String key : requestBody.keySet()) {
            Arrays.stream(InputParameters.values())
                .filter(param -> param.paramName.equalsIgnoreCase(key))
                .findAny()
                .orElseThrow(() -> new IllegalArgumentException("Unrecognized parameter: " + key));
        }
    }

    private Integer parseAndValidateDurationSeconds(Object durationObj) throws IllegalArgumentException {
        if (durationObj == null) {
            return OBO_DEFAULT_EXPIRY_SECONDS;
        }

        if (durationObj instanceof Integer) {
            return (Integer) durationObj;
        } else if (durationObj instanceof String) {
            try {
                return Integer.parseInt((String) durationObj);
            } catch (NumberFormatException ignored) {}
        }
        throw new IllegalArgumentException("durationSeconds must be an integer.");
    }
}
