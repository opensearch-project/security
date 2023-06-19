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
import org.opensearch.common.settings.Settings;
import org.opensearch.common.transport.TransportAddress;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.rest.RestStatus;
import org.opensearch.security.authtoken.jwt.JwtVendor;
import org.opensearch.security.securityconf.ConfigModel;
import org.opensearch.security.securityconf.DynamicConfigModel;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

public class CreateOnBehalfOfToken extends BaseRestHandler {

    private JwtVendor vendor;
    private final ThreadPool threadPool;

    private ConfigModel configModel;

    private DynamicConfigModel dcm;

    @Subscribe
    public void onConfigModelChanged(ConfigModel configModel) {
        this.configModel = configModel;
    }

    @Subscribe
    public void onDynamicConfigModelChanged(DynamicConfigModel dcm) {
        this.dcm = dcm;
        this.vendor = new JwtVendor(dcm.getDynamicOnBehalfOfSettings(), Optional.empty());
    }

    public CreateOnBehalfOfToken(final Settings settings, final ThreadPool threadPool) {
        this.threadPool = threadPool;
    }

    @Override
    public String getName() {
        return getClass().getSimpleName();
    }

    @Override
    public List<Route> routes() {
        return addRoutesPrefix(
                ImmutableList.of(
                        new Route(Method.POST, "/user/onbehalfof")
                )
        );
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
                    final Map<String, Object> requestBody = request.contentOrSourceParamParser().map();
                    final String reason = (String)requestBody.getOrDefault("reason", null);

                    final Integer tokenDuration = Optional.ofNullable(requestBody.get("duration"))
                            .map(value -> (String)value)
                            .map(Integer::parseInt)
                            .map(value -> Math.min(value, 72 * 3600)) // Max duration is 72 hours
                            .orElse(24 * 3600); // Fallback to default;

                    final String source = "self-issued";
                    final User user = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                    final TransportAddress caller = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
                    Set<String> mappedRoles = mapRoles(user, caller);

                    builder.startObject();
                    builder.field("user", user.getName());
                    final String token = vendor.createJwt(/* TODO: Update the issuer to represent the cluster */"OpenSearch",
                            user.getName(),
                            source,
                            tokenDuration,
                            mappedRoles.stream().collect(Collectors.toList()),
                            user.getRoles().stream().collect(Collectors.toList()));
                    builder.field("onBehalfOfToken", token);
                    builder.field("duration", tokenDuration);
                    builder.endObject();

                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception exception) {
                    System.out.println(exception.toString());
                    builder.startObject()
                            .field("error", exception.toString())
                            .endObject();

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
