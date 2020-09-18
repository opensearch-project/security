/*
 * Portions Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.amazon.opendistroforelasticsearch.security.rest;

import com.amazon.opendistroforelasticsearch.security.ssl.transport.OpenDistroSSLDualModeConfig;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.cluster.settings.ClusterUpdateSettingsRequest;
import org.elasticsearch.action.admin.cluster.settings.ClusterUpdateSettingsResponse;
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

    private static final String RESPONSE_ENABLED_FIELD = "enabled";
    private static final String RESPONSE_ERROR_FIELD = "error";

    private ClusterSettings clusterSettings;
    private Settings settings;

    private static final Logger logger = LogManager.getLogger(SSLDualModeAction.class);

    private static final List<Route> routes = ImmutableList.of(
            // gets the current status of ssl dual mode
            new Route(GET, "/_opendistro/_security/ssl_dual_mode"),
            // disables ssl dual mode
            new Route(PUT, "/_opendistro/_security/ssl_dual_mode/_disable"),
            // enables ssl dual mode
            new Route(PUT, "/_opendistro/_security/ssl_dual_mode/_enable")
    );

    public SSLDualModeAction(final Settings settings, final ClusterSettings clusterSettings) {
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

                switch (request.method()) {
                    case GET:
                        boolean dualModeEnabled = OpenDistroSSLDualModeConfig.getInstance().isDualModeEnabled();
                        BytesRestResponse response = getDualModeResponse(restChannel, dualModeEnabled);
                        restChannel.sendResponse(response);
                        break;
                    case PUT:
                        try {
                            final boolean enableDualMode;
                            if (request.path().endsWith("_enable")) {
                                enableDualMode = true;
                            } else {
                                enableDualMode = false;
                            }

                            Settings dualModeSetting = Settings.builder()
                                .put(ConfigConstants.OPENDISTRO_SECURITY_SSL_DUAL_MODE_ENABLED, enableDualMode)
                                .build();

                            ClusterUpdateSettingsRequest clusterUpdateSettingsRequest = new ClusterUpdateSettingsRequest();
                            clusterUpdateSettingsRequest.persistentSettings(dualModeSetting);
                            client.admin()
                                .cluster()
                                .updateSettings(clusterUpdateSettingsRequest, new ActionListener<ClusterUpdateSettingsResponse>() {
                                    @Override
                                    public void onResponse(ClusterUpdateSettingsResponse clusterUpdateSettingsResponse) {
                                        restChannel.sendResponse(getDualModeResponse(restChannel, enableDualMode));
                                    }

                                    @Override
                                    public void onFailure(Exception e) {
                                        BytesRestResponse response = getErrorMessageResponse(restChannel,
                                            String.format("Unable to apply opendistro ssl dual mode settings due to %s", e.getMessage()));
                                        restChannel.sendResponse(response);
                                    }
                                });
                        } catch (Exception e) {
                            logger.error("Unable to update open distro SSL dual mode settings", e);
                            response = getErrorMessageResponse(restChannel,
                                    String.format("Unable to apply opendistro ssl dual mode settings due to %s", e.getMessage()));
                            restChannel.sendResponse(response);
                        }
                        break;
                }

            }
        };
    }

    private BytesRestResponse getErrorMessageResponse(final RestChannel restChannel, final String errorMessage) {
        XContentBuilder builder;
        try {
            builder = restChannel.newBuilder();
            builder.startObject();
            builder.field(RESPONSE_ERROR_FIELD, errorMessage);
            builder.endObject();
            builder.close();
        } catch (IOException e) {
            logger.error("Unable to generate response", e);
            throw new ElasticsearchException(e);
        }
        return new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
    }

    private BytesRestResponse getDualModeResponse(final RestChannel restChannel, final boolean enabled) {
        XContentBuilder builder;
        try {
            builder = restChannel.newBuilder();
            builder.startObject();
            builder.field(RESPONSE_ENABLED_FIELD, enabled);
            builder.endObject();
            builder.close();
        } catch (IOException e) {
            logger.error("Unable to generate response", e);
            throw new ElasticsearchException(e);
        }
        return new BytesRestResponse(RestStatus.OK, builder);
    }
}
