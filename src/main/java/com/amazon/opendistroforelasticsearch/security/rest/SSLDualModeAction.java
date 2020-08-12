package com.amazon.opendistroforelasticsearch.security.rest;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.google.common.collect.ImmutableList;
import org.elasticsearch.action.admin.cluster.settings.ClusterUpdateSettingsRequest;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.*;

import java.io.IOException;
import java.util.List;

import static org.elasticsearch.rest.RestRequest.Method.GET;
import static org.elasticsearch.rest.RestRequest.Method.PUT;

public class SSLDualModeAction extends BaseRestHandler {

    ClusterSettings clusterSettings;
    Settings settings;

    private static final List<Route> routes = ImmutableList.of(
            new Route(GET, "/_opendistro/_security/ssl_dual_mode"),
            new Route(PUT, "/_opendistro/_security/ssl_dual_mode/_disable")
    );

    private static final Settings DISABLE_SSL_DUAL_MODE = Settings.builder()
            .put(ConfigConstants.OPENDISTRO_SECURITY_SSL_DUAL_MODE_ENABLED, false)
            .build();

    public SSLDualModeAction(Settings settings, ClusterSettings clusterSettings) {
        this.settings = settings;
        this.clusterSettings = clusterSettings;
    }

    @Override
    public String getName() {
        return "ssl_dual_mode";
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return new RestChannelConsumer() {
            @Override
            public void accept(RestChannel restChannel) throws Exception {
                restChannel.request().content();
                XContentBuilder builder = restChannel.newBuilder();
                BytesRestResponse response = null;

                switch (request.method()) {
                    case GET:
                        builder.startObject();
                        builder.field("enabled", settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_SSL_DUAL_MODE_ENABLED, false));
                        builder.endObject();
                        builder.close();
                        break;
                    case PUT:
                        ClusterUpdateSettingsRequest clusterUpdateSettingsRequest = new ClusterUpdateSettingsRequest();
                        clusterUpdateSettingsRequest.persistentSettings(DISABLE_SSL_DUAL_MODE);
                        client.admin().cluster().updateSettings(clusterUpdateSettingsRequest).actionGet().isAcknowledged();
                        builder.startObject();
                        builder.field("enabled", settings.getAsBoolean(ConfigConstants.OPENDISTRO_SECURITY_SSL_DUAL_MODE_ENABLED, false));
                        builder.endObject();
                        builder.close();
                        break;
                }

                response = new BytesRestResponse(RestStatus.OK, builder);
                restChannel.sendResponse(response);

            }
        };
    }
}
