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

package org.opensearch.security.dlic.rest.api;

import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.auditlog.AuditLog;
import org.opensearch.security.configuration.AdminDNs;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.dlic.rest.validation.RequestContentValidator;
import org.opensearch.security.privileges.PrivilegesEvaluator;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.ssl.SecurityKeyStore;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * Rest API action to get SSL certificate information related to http and transport encryption.
 * Only super admin users are allowed to access this API.
 * This action serves GET request for _plugins/_security/api/ssl/certs endpoint and
 * PUT _plugins/_security/api/ssl/{certType}/reloadcerts
 */
public class SecuritySSLCertsAction extends AbstractApiAction {
    private static final List<Route> ROUTES = addRoutesPrefix(
        ImmutableList.of(new Route(Method.GET, "/ssl/certs"), new Route(Method.PUT, "/ssl/{certType}/reloadcerts"))
    );

    private final Logger log = LogManager.getLogger(this.getClass());

    private final SecurityKeyStore securityKeyStore;

    private final boolean certificatesReloadEnabled;

    private final boolean httpsEnabled;

    public SecuritySSLCertsAction(
        final Settings settings,
        final Path configPath,
        final RestController controller,
        final Client client,
        final AdminDNs adminDNs,
        final ConfigurationRepository cl,
        final ClusterService cs,
        final PrincipalExtractor principalExtractor,
        final PrivilegesEvaluator privilegesEvaluator,
        final ThreadPool threadPool,
        final AuditLog auditLog,
        final SecurityKeyStore securityKeyStore,
        final boolean certificatesReloadEnabled
    ) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, privilegesEvaluator, threadPool, auditLog);
        this.securityKeyStore = securityKeyStore;
        this.certificatesReloadEnabled = certificatesReloadEnabled;
        this.httpsEnabled = settings.getAsBoolean(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true);
    }

    @Override
    protected boolean hasPermissionsToCreate(
        final SecurityDynamicConfiguration<?> dynamicConfigFactory,
        final Object content,
        final String resourceName
    ) {
        return true;
    }

    @Override
    public List<Route> routes() {
        return ROUTES;
    }

    @Override
    protected void handleApiRequest(final RestChannel channel, final RestRequest request, final Client client) throws IOException {
        switch (request.method()) {
            case GET:
                if (!restApiAdminPrivilegesEvaluator.isCurrentUserRestApiAdminFor(getEndpoint(), "certs")) {
                    forbidden(channel, "");
                    return;
                }
                handleGet(channel, request, client, null);
                break;
            case PUT:
                if (!restApiAdminPrivilegesEvaluator.isCurrentUserRestApiAdminFor(getEndpoint(), "reloadcerts")) {
                    forbidden(channel, "");
                    return;
                }
                if (!certificatesReloadEnabled) {
                    badRequestResponse(
                        channel,
                        String.format(
                            "no handler found for uri [%s] and method [%s]. In order to use SSL reload functionality set %s to true",
                            request.path(),
                            request.method(),
                            ConfigConstants.SECURITY_SSL_CERT_RELOAD_ENABLED
                        )
                    );
                    return;
                }
                handlePut(channel, request, client, null);
                break;
            default:
                notImplemented(channel, request.method());
                break;
        }
    }

    /**
     * GET request to fetch transport certificate details
     *
     * Sample request:
     * GET _plugins/_security/api/ssl/certs
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
    protected void handleGet(final RestChannel channel, final RestRequest request, final Client client, final JsonNode content)
        throws IOException {
        if (securityKeyStore == null) {
            noKeyStoreResponse(channel);
            return;
        }
        try (final XContentBuilder contentBuilder = channel.newBuilder()) {
            channel.sendResponse(
                new BytesRestResponse(
                    RestStatus.OK,
                    contentBuilder.startObject()
                        .field("http_certificates_list", httpsEnabled ? generateCertDetailList(securityKeyStore.getHttpCerts()) : null)
                        .field("transport_certificates_list", generateCertDetailList(securityKeyStore.getTransportCerts()))
                        .endObject()
                )
            );
        } catch (final Exception e) {
            internalErrorResponse(channel, e.getMessage());
            log.error("Error handle request ", e);
        }
    }

    /**
     * PUT request to reload SSL Certificates.
     *
     * Sample request:
     * PUT _opendistro/_security/api/ssl/transport/reloadcerts
     * PUT _opendistro/_security/api/ssl/http/reloadcerts
     *
     * NOTE: No request body is required. We will assume new certificates are loaded in the paths specified in your opensearch.yml file
     * (https://docs-beta.opensearch.org/docs/security/configuration/tls/)
     *
     * Sample response:
     * { "message": "updated http certs" }
     *
     * @param request request to be served
     * @param client client
     * @throws IOException
     */
    @Override
    protected void handlePut(final RestChannel channel, final RestRequest request, final Client client, final JsonNode content)
        throws IOException {
        if (securityKeyStore == null) {
            noKeyStoreResponse(channel);
            return;
        }
        final String certType = request.param("certType").toLowerCase().trim();
        try (final XContentBuilder contentBuilder = channel.newBuilder()) {
            switch (certType) {
                case "http":
                    if (!httpsEnabled) {
                        badRequestResponse(channel, "SSL for HTTP is disabled");
                        return;
                    }
                    securityKeyStore.initHttpSSLConfig();
                    channel.sendResponse(
                        new BytesRestResponse(
                            RestStatus.OK,
                            contentBuilder.startObject().field("message", "updated http certs").endObject()
                        )
                    );
                    break;
                case "transport":
                    securityKeyStore.initTransportSSLConfig();
                    channel.sendResponse(
                        new BytesRestResponse(
                            RestStatus.OK,
                            contentBuilder.startObject().field("message", "updated transport certs").endObject()
                        )
                    );
                    break;
                default:
                    forbidden(
                        channel,
                        "invalid uri path, please use /_plugins/_security/api/ssl/http/reload or "
                            + "/_plugins/_security/api/ssl/transport/reload"
                    );
                    break;
            }
        } catch (final Exception e) {
            log.error("Reload of certificates for {} failed", certType, e);
            try (final XContentBuilder contentBuilder = channel.newBuilder()) {
                channel.sendResponse(
                    new BytesRestResponse(
                        RestStatus.INTERNAL_SERVER_ERROR,
                        contentBuilder.startObject().field("error", e.toString()).endObject()
                    )
                );
            }
        }
    }

    private List<Map<String, String>> generateCertDetailList(final X509Certificate[] certs) {
        if (certs == null) {
            return null;
        }
        return Arrays.stream(certs).map(cert -> {
            final String issuerDn = cert != null && cert.getIssuerX500Principal() != null ? cert.getIssuerX500Principal().getName() : "";
            final String subjectDn = cert != null && cert.getSubjectX500Principal() != null ? cert.getSubjectX500Principal().getName() : "";

            final String san = securityKeyStore.getSubjectAlternativeNames(cert);

            final String notBefore = cert != null && cert.getNotBefore() != null ? cert.getNotBefore().toInstant().toString() : "";
            final String notAfter = cert != null && cert.getNotAfter() != null ? cert.getNotAfter().toInstant().toString() : "";
            return ImmutableMap.of(
                "issuer_dn",
                issuerDn,
                "subject_dn",
                subjectDn,
                "san",
                san,
                "not_before",
                notBefore,
                "not_after",
                notAfter
            );
        }).collect(Collectors.toList());
    }

    private void noKeyStoreResponse(final RestChannel channel) throws IOException {
        response(channel, RestStatus.OK, "keystore is not initialized");
    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.SSL;
    }

    @Override
    public String getName() {
        return "SSL Certificates Action";
    }

    @Override
    protected RequestContentValidator createValidator(final Object... params) {
        return null;
    }

    @Override
    protected void consumeParameters(RestRequest request) {
        request.param("certType");
    }

    @Override
    protected String getResourceName() {
        return null;
    }

    @Override
    protected CType getConfigName() {
        return null;
    }

}
