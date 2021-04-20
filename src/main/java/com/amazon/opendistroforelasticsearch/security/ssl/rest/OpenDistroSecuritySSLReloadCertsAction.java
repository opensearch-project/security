/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.ssl.rest;

import com.amazon.opendistroforelasticsearch.security.DefaultObjectMapper;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils;
import com.amazon.opendistroforelasticsearch.security.ssl.OpenDistroSecurityKeyStore;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.opensearch.client.Client;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestStatus;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import static org.opensearch.rest.RestRequest.Method.PUT;


/**
 * Rest API action to reload SSL certificates.
 * Can be used to reload SSL certificates that are about to expire without restarting OpenSearch node.
 * This API assumes that new certificates are in the same location specified by the security configurations in opensearch.yml
 * (https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/tls/)
 * To keep sensitive certificate reload secure, this API will only allow hot reload
 * with certificates issued by the same Issuer and Subject DN and SAN with expiry dates after the current one.
 * Currently this action serves PUT request for /_opendistro/_security/ssl/http/reloadcerts or /_opendistro/_security/ssl/transport/reloadcerts endpoint
 */
public class OpenDistroSecuritySSLReloadCertsAction extends BaseRestHandler {
    private static final List<Route> routes = Collections.singletonList(
            new Route(PUT, "_opendistro/_security/api/ssl/{certType}/reloadcerts/")
    );

    private final Settings settings;
    private final OpenDistroSecurityKeyStore odsks;
    private final ThreadContext threadContext;
    private final AdminDNs adminDns;

    public OpenDistroSecuritySSLReloadCertsAction(final Settings settings,
                                                  final RestController restController,
                                                  final OpenDistroSecurityKeyStore odsks,
                                                  final ThreadPool threadPool,
                                                  final AdminDNs adminDns) {
        super();
        this.settings = settings;
        this.odsks = odsks;
        this.adminDns = adminDns;
        this.threadContext = threadPool.getThreadContext();
    }

    @Override
    public List<Route> routes() {
        return routes;
    }

    /**
     * PUT request to reload SSL Certificates.
     *
     * Sample request:
     * PUT _opendistro/_security/api/ssl/transport/reloadcerts
     * PUT _opendistro/_security/api/ssl/http/reloadcerts
     *
     * NOTE: No request body is required. We will assume new certificates are loaded in the paths specified in your opensearch.yml file
     * (https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/tls/)
     *
     * Sample response:
     * { "message": "updated http certs" }
     *
     * @param request request to be served
     * @param client client
     * @throws IOException
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return new RestChannelConsumer() {

            final String certType = request.param("certType").toLowerCase().trim();

            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder();
                BytesRestResponse response = null;

                // Check for Super admin user
                final User user = (User) threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                if(user ==null||!adminDns.isAdmin(user)) {
                    response = new BytesRestResponse(RestStatus.FORBIDDEN, "");
                } else {
                    try {
                        builder.startObject();
                        if (odsks != null) {
                            switch (certType) {
                                case "http":
                                    odsks.initHttpSSLConfig();
                                    builder.field("message", "updated http certs");
                                    builder.endObject();
                                    response = new BytesRestResponse(RestStatus.OK, builder);
                                    break;
                                case "transport":
                                    odsks.initTransportSSLConfig();
                                    builder.field("message", "updated transport certs");
                                    builder.endObject();
                                    response = new BytesRestResponse(RestStatus.OK, builder);
                                    break;
                                default:
                                    builder.field("message", "invalid uri path, please use /_opendistro/_security/api/ssl/http/reload or " +
                                        "/_opendistro/_security/api/ssl/transport/reload");
                                    builder.endObject();
                                    response = new BytesRestResponse(RestStatus.FORBIDDEN, builder);
                                    break;
                            }
                        } else {
                            builder.field("message", "keystore is not initialized");
                            builder.endObject();
                            response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                        }
                    } catch (final Exception e1) {
                        builder = channel.newBuilder();
                        builder.startObject();
                        builder.field("error", e1.toString());
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                    } finally {
                        if (builder != null) {
                            builder.close();
                        }
                    }
                }
                channel.sendResponse(response);
            }
        };
    }

    @Override
    public String getName() {
        return "SSL Cert Reload Action";
    }
}
