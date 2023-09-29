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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableList;
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

    private DynamicConfigModel dcm;

    public static final Integer OBO_DEFAULT_EXPIRY_SECONDS = 5 * 60;
    public static final Integer OBO_MAX_EXPIRY_SECONDS = 10 * 60;

    public static final String TOKEN_SERVICE_DEFAULT_TYPE = "self-issued";

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
                    final String description = (String) requestBody.getOrDefault("description", null);

                    final Integer tokenDuration = Optional.ofNullable(requestBody.get("durationSeconds"))
                        .map(value -> (String) value)
                        .map(Integer::parseInt)
                        .map(value -> Math.min(value, OBO_MAX_EXPIRY_SECONDS)) // Max duration seconds are 600
                        .orElse(OBO_DEFAULT_EXPIRY_SECONDS); // Fallback to default

                    final Boolean isRoleEncrypted = Optional.ofNullable(requestBody.get("isRoleEncrypted"))
                        .map(value -> (Boolean) value)
                        .orElse(true); // Default to false if null

                    final String service = (String) requestBody.getOrDefault("service", TOKEN_SERVICE_DEFAULT_TYPE);
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
                        isRoleEncrypted
                    );
                    builder.field("authenticationToken", token);
                    builder.field("durationSeconds", tokenDuration);
                    builder.endObject();

                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception exception) {
                    builder.startObject().field("error", exception.toString()).endObject();

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

}
