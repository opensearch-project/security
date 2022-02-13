/*
 * Copyright OpenSearch Contributors
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

package org.opensearch.security.ssl.rest;

import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.ssl.SecurityKeyStore;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.user.User;
import com.google.common.collect.ImmutableMap;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.rest.RestStatus;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


/**
 * Rest API action to get SSL certificate information related to http and transport encryption.
 * Only super admin users are allowed to access this API.
 * Currently this action serves GET request for _opendistro/_security/api/ssl/certs endpoint
 */
public class SecuritySSLCertsInfoAction extends BaseRestHandler {
    private static final List<Route> routes = Collections.singletonList(
            new Route(Method.GET, "/_opendistro/_security/api/ssl/certs")
    );

    private final Logger log = LoggerFactory.getLogger(this.getClass());
    private Settings settings;
    private SecurityKeyStore odsks;
    private AdminDNs adminDns;
    private ThreadContext threadContext;

    public SecuritySSLCertsInfoAction(final Settings settings,
                                      final RestController restController,
                                      final SecurityKeyStore odsks,
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
     * GET request to fetch transport certificate details
     *
     * Sample request:
     * GET _opendistro/_security/api/ssl/certs
     *
     * Sample response:
     * {
     *   "http_certificates_list" : [
     *     {
     *       "issuer_dn" : "CN=Example Com Inc. Signing CA, OU=Example Com Inc. Signing CA, O=Example Com Inc., DC=example, DC=com",
     *       "subject_dn" : "CN=transport-0.example.com, OU=SSL, O=Test, L=Test, C=DE",
     *       "san", "[[2, node-0.example.com], [2, localhost], [7, 127.0.0.1], [8, 1.2.3.4.5.5]]",
     *       "not_before" : "2018-05-05T14:37:09.000Z",
     *       "not_after" : "2028-05-02T14:37:09.000Z"
     *     }
     *  "transport_certificates_list" : [
     *     {
     *       "issuer_dn" : "CN=Example Com Inc. Signing CA, OU=Example Com Inc. Signing CA, O=Example Com Inc., DC=example, DC=com",
     *       "subject_dn" : "CN=transport-0.example.com, OU=SSL, O=Test, L=Test, C=DE",
     *       "san", "[[2, node-0.example.com], [2, localhost], [7, 127.0.0.1], [8, 1.2.3.4.5.5]]",
     *       "not_before" : "2018-05-05T14:37:09.000Z",
     *       "not_after" : "2028-05-02T14:37:09.000Z"
     *      }
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

                // Check for Super admin user
                final User user = (User)threadContext.getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
                if(user == null || !adminDns.isAdmin(user)) {
                    response = new BytesRestResponse(RestStatus.FORBIDDEN, builder);
                } else {
                    try {
                        // Check if keystore initialised
                        if (odsks != null) {
                            builder.startObject();
                            builder.field("http_certificates_list", generateCertDetailList(odsks.getHttpCerts()));
                            builder.field("transport_certificates_list", generateCertDetailList(odsks.getTransportCerts()));
                            builder.endObject();
                            response = new BytesRestResponse(RestStatus.OK, builder);
                        } else {
                            builder.startObject();
                            builder.field("message", "keystore is not initialized");
                            builder.endObject();
                            response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                        }
                    } catch (final Exception e1) {
                        log.error("Error handle request ", e1);
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

            /**
             * Helper that construct list of certificate details.
             * @param certs list of certificates.
             * @return Array containing certificate details.
             */
            private List<Map<String, String>> generateCertDetailList(final X509Certificate[] certs) {
                if (certs == null) {
                    return null;
                }
                return Arrays.stream(certs)
                    .map(cert -> {
                        final String issuerDn = cert != null && cert.getIssuerX500Principal() != null ? cert.getIssuerX500Principal().getName(): "";
                        final String subjectDn = cert != null && cert.getSubjectX500Principal() != null ? cert.getSubjectX500Principal().getName(): "";

                        final String san = odsks.getSubjectAlternativeNames(cert);

                        final String notBefore = cert != null && cert.getNotBefore() != null ? cert.getNotBefore().toInstant().toString(): "";
                        final String notAfter = cert != null && cert.getNotAfter() != null ? cert.getNotAfter().toInstant().toString(): "";
                        return ImmutableMap.<String, String>builder()
                            .put("issuer_dn", issuerDn)
                            .put("subject_dn", subjectDn)
                            .put("san", san)
                            .put("not_before", notBefore)
                            .put("not_after", notAfter)
                            .build();
                    })
                    .collect(Collectors.toList());
            }
        };
    }

    @Override
    public String getName() {
        return "SSL Certificate Information Action";
    }
}
