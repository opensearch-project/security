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

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.function.LongSupplier;
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
import org.opensearch.security.identity.SecurityTokenManager;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.security.user.UserService;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.rest.RestRequest.Method.POST;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class CreateOnBehalfOfTokenAction extends BaseRestHandler {

    private static final List<Route> routes = addRoutesPrefix(
        ImmutableList.of(new NamedRoute.Builder().method(POST).path("/generateonbehalfoftoken").uniqueName("security:obo/create").build()),
        "/_plugins/_security/api"
    );

    private SecurityTokenManager securityTokenManager;
    private final ThreadPool threadPool;
    private final ClusterService clusterService;
    private final UserService userService;
    private final Settings settings;
    private final Optional<LongSupplier> longSupplier;

    private ConfigModel configModel;

    private DynamicConfigModel dcm;

    public static final Integer OBO_DEFAULT_EXPIRY_SECONDS = 5 * 60;
    public static final Integer OBO_MAX_EXPIRY_SECONDS = 10 * 60;

    public static final String DEFAULT_SERVICE = "self-issued";

    protected final Logger log = LogManager.getLogger(this.getClass());

    private static final Set<String> RECOGNIZED_PARAMS = new HashSet<>(
        Arrays.asList("durationSeconds", "description", "roleSecurityMode", "service")
    );

    @Subscribe
    public void onConfigModelChanged(ConfigModel configModel) {
        this.configModel = configModel;
    }

    @Subscribe
    public void onDynamicConfigModelChanged(DynamicConfigModel dcm) {
        this.dcm = dcm;

        Settings settings = dcm.getDynamicOnBehalfOfSettings();

        Boolean enabled = Boolean.parseBoolean(settings.get("enabled"));
        String signingKey = settings.get("signing_key");
        String encryptionKey = settings.get("encryption_key");

        if (!Boolean.FALSE.equals(enabled) && signingKey != null && encryptionKey != null) {
            this.securityTokenManager = new SecurityTokenManager(clusterService, threadPool, userService, longSupplier, settings);
        } else {
            this.securityTokenManager = null;
        }
    }

    public CreateOnBehalfOfTokenAction(final Settings settings, final ThreadPool threadPool, final ClusterService clusterService, Optional<LongSupplier> longSupplier, UserService userService) {
        this.threadPool = threadPool;
        this.clusterService = clusterService;
        this.userService = userService;
        this.settings = settings;
        this.longSupplier = longSupplier;
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
                    if (securityTokenManager == null) {
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

                    final String description = (String) requestBody.getOrDefault("description", null);
                    final Long tokenDuration = Long.valueOf(Optional.ofNullable(requestBody.get("durationSeconds"))
                        .map(value -> (String) value)
                        .map(Integer::parseInt)
                        .map(value -> Math.min(value, OBO_MAX_EXPIRY_SECONDS)) // Max duration seconds are 600
                        .orElse(OBO_DEFAULT_EXPIRY_SECONDS)); // Fallback to default

                    final Boolean roleSecurityMode = Optional.ofNullable(requestBody.get("roleSecurityMode"))
                        .map(value -> (Boolean) value)
                        .orElse(true); // Default to false if null

                    final String service = (String) requestBody.getOrDefault("service", DEFAULT_SERVICE);
                    final User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                    Set<String> mappedRoles = mapRoles(user);

                    builder.startObject();
                    builder.field("user", user.getName());

                    final String token = securityTokenManager.createJwt(
                        clusterIdentifier,
                        user.getName(),
                        service,
                        tokenDuration,
                        Set.copyOf(mappedRoles),
                        Set.copyOf(user.getRoles()),
                        roleSecurityMode
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

    private Set<String> mapRoles(final User user) {
        return this.configModel.mapSecurityRoles(user, null);
    }

    private void validateRequestParameters(Map<String, Object> requestBody) throws IllegalArgumentException {
        for (String key : requestBody.keySet()) {
            if (!RECOGNIZED_PARAMS.contains(key)) {
                throw new IllegalArgumentException("Unrecognized parameter: " + key);
            }
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
