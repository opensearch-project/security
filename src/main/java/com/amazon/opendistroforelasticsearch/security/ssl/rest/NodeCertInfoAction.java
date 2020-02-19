package com.amazon.opendistroforelasticsearch.security.ssl.rest;

import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.ssl.OpenDistroSecurityKeyStore;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import java.security.cert.X509Certificate;

import static org.elasticsearch.rest.RestRequest.Method.GET;

/**
 * Rest API action to get information SSL Transport certificates used for node to node encryption.
 * Currently this action serves GET request for /_opendistro/_security/nodecerts endpoint
 */
public class NodeCertInfoAction extends BaseRestHandler {

    private final Logger log = LogManager.getLogger(this.getClass());
    private Settings settings;
    private OpenDistroSecurityKeyStore odsks;
    private AdminDNs adminDns;
    private ThreadContext threadContext;

    public NodeCertInfoAction(final Settings settings,
                              final RestController restController,
                              final OpenDistroSecurityKeyStore odsks,
                              final ThreadPool threadPool,
                              final AdminDNs adminDns) {
        super(settings);
        this.settings = settings;
        this.odsks = odsks;
        this.adminDns = adminDns;
        this.threadContext = threadPool.getThreadContext();
        restController.registerHandler(GET, "/_opendistro/_security/nodecerts", this);
    }

    /**
     * GET request to fetch node certificate details
     *
     * Sample request:
     * GET _opendistro/_security/nodecerts
     *
     * Sample response:
     * {
     *   "node_cert_list" : [
     *     {
     *       "issuer_dn" : "CN=Example Com Inc. Signing CA, OU=Example Com Inc. Signing CA, O=Example Com Inc., DC=example, DC=com",
     *       "subject_dn" : "CN=node-0.example.com, OU=SSL, O=Test, L=Test, C=DE",
     *       "not_before" : "2018-05-05T14:37:09.000Z",
     *       "not_after" : "2028-05-02T14:37:09.000Z"
     *     }
     *   ]
     * }
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
                        // Check if keystore initialised
                        if (odsks != null) {
                            final X509Certificate[] localCertificates = odsks.getTransportCerts();
                            builder.startObject();
                            if (localCertificates != null) {
                                builder.startArray("node_cert_list");
                                for (X509Certificate localCertificate : localCertificates) {
                                    builder.startObject();
                                    builder.field("issuer_dn", localCertificate.getIssuerDN().getName());
                                    builder.field("subject_dn", localCertificate.getSubjectDN().toString());
                                    builder.field("not_before", localCertificate.getNotBefore());
                                    builder.field("not_after", localCertificate.getNotAfter());
                                    builder.endObject();
                                }
                                builder.endArray();
                            }
                            builder.endObject();
                        } else {
                            builder.field("message", "keystore is not initialized");
                        }

                        response = new BytesRestResponse(RestStatus.OK, builder);
                    } catch (final Exception e1) {
                        log.error("Error handle request " + e1, e1);
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
        return "Node Certificate Info Action";
    }
}
