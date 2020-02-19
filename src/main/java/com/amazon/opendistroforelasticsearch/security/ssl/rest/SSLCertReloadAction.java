package com.amazon.opendistroforelasticsearch.security.ssl.rest;

import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.ssl.OpenDistroSecurityKeyStore;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;
import static org.elasticsearch.rest.RestRequest.Method.PUT;


/**
 * Rest API action to reinitialize SSL certificates.
 * Can be used to replace SSL certificates that are about to expire without restarting ES node.
 * This API assumes that any new certificates are in the same location specified by the security configurations in elasticsearch.yml
 * (https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/tls/)
 * Currently this action serves PUT request for /_opendistro/_security/sslcerts/reload endpoint
 */
public class SSLCertReloadAction extends BaseRestHandler {

    private final Settings settings;
    private final OpenDistroSecurityKeyStore odsks;
    private final ThreadContext threadContext;
    private final AdminDNs adminDns;

    public SSLCertReloadAction(final Settings settings,
                               final RestController restController,
                               final OpenDistroSecurityKeyStore odsks,
                               final ThreadPool threadPool,
                               final AdminDNs adminDns) {
        super(settings);
        this.settings = settings;
        this.odsks = odsks;
        this.adminDns = adminDns;
        this.threadContext = threadPool.getThreadContext();
        restController.registerHandler(PUT, "/_opendistro/_security/sslcerts/reload", this);
    }

    /**
     * PUT request to reload SSL Certificates.
     *
     * Sample request:
     * PUT _opendistro/_security/nodecerts
     *
     * NOTE: No request body is required. We will assume new certificates are loaded in the paths specified in your elasticsearch.yml file
     * (https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/tls/)
     *
     * Sample response:
     * { "message": "updated certs successfully" }
     *
     * @param request request to be served
     * @param client client
     * @throws IOException
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return new RestChannelConsumer() {
            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder();
                BytesRestResponse response = null;
                // Check for Admin user
                final User user = (User)threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                if(user == null || !adminDns.isAdmin(user)) {
                    response = new BytesRestResponse(RestStatus.FORBIDDEN,"");
                } else {
                    try {
                        builder.startObject();
                        if (odsks != null) {
                            odsks.initSSLConfig();
                            builder.field("message", "updated certs successfully");
                        } else {
                            builder.field( "message", "keystore is not initialized");
                        }
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.OK, builder);
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
