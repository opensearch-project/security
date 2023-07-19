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
import org.opensearch.common.transport.TransportAddress;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.authtoken.jwt.JwtVendor;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class CreateOnBehalfOfTokenAction extends BaseRestHandler {

    private JwtVendor vendor;
    private final ThreadPool threadPool;
    private final ClusterService clusterService;

    private ConfigModel configModel;

    private DynamicConfigModel dcm;

    @Subscribe
    public void onConfigModelChanged(ConfigModel configModel) {
        this.configModel = configModel;
    }

    @Subscribe
    public void onDynamicConfigModelChanged(DynamicConfigModel dcm) {
        this.dcm = dcm;
        if (dcm.getDynamicOnBehalfOfSettings().get("signing_key") != null
            && dcm.getDynamicOnBehalfOfSettings().get("encryption_key") != null) {
            this.vendor = new JwtVendor(dcm.getDynamicOnBehalfOfSettings(), Optional.empty());
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
        return addRoutesPrefix(ImmutableList.of(new Route(Method.POST, "/user/onbehalfof")));
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
                            new BytesRestResponse(RestStatus.SERVICE_UNAVAILABLE, "on_behalf_of configuration is not being configured")
                        );
                        return;
                    }

                    final String clusterIdentifier = clusterService.getClusterName().value();

                    final Map<String, Object> requestBody = request.contentOrSourceParamParser().map();
                    final String reason = (String) requestBody.getOrDefault("reason", null);

                    final Integer tokenDuration = Optional.ofNullable(requestBody.get("duration"))
                        .map(value -> (String) value)
                        .map(Integer::parseInt)
                        .map(value -> Math.min(value, 10 * 60)) // Max duration is 10 minutes
                        .orElse(5 * 60); // Fallback to default of 5 minutes;

                    final String service = (String) requestBody.getOrDefault("service", "self-issued");
                    final User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                    final TransportAddress caller = threadPool.getThreadContext()
                        .getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
                    Set<String> mappedRoles = mapRoles(user, caller);

                    builder.startObject();
                    builder.field("user", user.getName());

                    final String token = vendor.createJwt(
                        clusterIdentifier,
                        user.getName(),
                        service,
                        tokenDuration,
                        mappedRoles.stream().collect(Collectors.toList()),
                        user.getRoles().stream().collect(Collectors.toList())
                    );
                    builder.field("onBehalfOfToken", token);
                    builder.field("duration", tokenDuration + " seconds");
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

    public Set<String> mapRoles(final User user, final TransportAddress caller) {
        return this.configModel.mapSecurityRoles(user, caller);
    }

}
