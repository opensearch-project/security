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
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestChannel;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.security.dlic.rest.validation.ValidationResult;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.ssl.SslContextHandler;
import org.opensearch.security.ssl.SslSettingsManager;
import org.opensearch.security.ssl.config.CertType;
import org.opensearch.security.ssl.config.Certificate;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.threadpool.ThreadPool;

import static org.opensearch.security.dlic.rest.api.Responses.badRequest;
import static org.opensearch.security.dlic.rest.api.Responses.badRequestMessage;
import static org.opensearch.security.dlic.rest.api.Responses.ok;
import static org.opensearch.security.dlic.rest.api.Responses.response;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.CERTS_INFO_ACTION;
import static org.opensearch.security.dlic.rest.api.RestApiAdminPrivilegesEvaluator.RELOAD_CERTS_ACTION;
import static org.opensearch.security.dlic.rest.support.Utils.addRoutesPrefix;

/**
 * Rest API action to get SSL certificate information related to http and transport encryption.
 * Only super admin users are allowed to access this API.
 * This action serves GET request for _plugins/_security/api/ssl/certs endpoint and
 * PUT _plugins/_security/api/ssl/{certType}/reloadcerts
 */
@Deprecated
public class SecuritySSLCertsApiAction extends AbstractApiAction {

    private final static Logger LOGGER = LogManager.getLogger(SecuritySSLCertsApiAction.class);

    private static final List<Route> ROUTES = addRoutesPrefix(
        ImmutableList.of(
            new DeprecatedRoute(Method.GET, "/ssl/certs", "[/ssl/certs] is a deprecated endpoint. Please use [/certificates] instead."),
            new Route(Method.PUT, "/ssl/{certType}/reloadcerts")
        )
    );

    private final SslSettingsManager sslSettingsManager;

    private final boolean certificatesReloadEnabled;

    public SecuritySSLCertsApiAction(
        final ClusterService clusterService,
        final ThreadPool threadPool,
        final SslSettingsManager sslSettingsManager,
        final boolean certificatesReloadEnabled,
        final SecurityApiDependencies securityApiDependencies
    ) {
        super(Endpoint.SSL, clusterService, threadPool, securityApiDependencies);
        this.sslSettingsManager = sslSettingsManager;
        this.certificatesReloadEnabled = certificatesReloadEnabled;
        this.requestHandlersBuilder.configureRequestHandlers(this::securitySSLCertsRequestHandlers);
    }

    @Override
    public List<Route> routes() {
        return ROUTES;
    }

    @Override
    public String getName() {
        return "SSL Certificates Action";
    }

    @Override
    protected void consumeParameters(RestRequest request) {
        request.param("certType");
    }

    @Override
    protected CType<?> getConfigType() {
        return null;
    }

    private void securitySSLCertsRequestHandlers(RequestHandler.RequestHandlersBuilder requestHandlersBuilder) {
        requestHandlersBuilder.withAccessHandler(this::accessHandler)
            .allMethodsNotImplemented()
            .verifyAccessForAllMethods()
            .override(
                Method.GET,
                (channel, request, client) -> withSecurityKeyStore().valid(ignore -> loadCertificates(channel))
                    .error((status, toXContent) -> response(channel, status, toXContent))
            )
            .override(Method.PUT, (channel, request, client) -> withSecurityKeyStore().valid(ignore -> {
                if (!certificatesReloadEnabled) {
                    badRequest(
                        channel,
                        String.format(
                            "no handler found for uri [%s] and method [%s]. In order to use SSL reload functionality set %s to true",
                            request.path(),
                            request.method(),
                            ConfigConstants.SECURITY_SSL_CERT_RELOAD_ENABLED
                        )
                    );
                } else {
                    reloadCertificates(channel, request);
                }
            }).error((status, toXContent) -> response(channel, status, toXContent)));
    }

    boolean accessHandler(final RestRequest request) {
        if (request.method() == Method.GET) {
            return securityApiDependencies.restApiAdminPrivilegesEvaluator().isCurrentUserAdminFor(endpoint, CERTS_INFO_ACTION);
        } else if (request.method() == Method.PUT) {
            return securityApiDependencies.restApiAdminPrivilegesEvaluator().isCurrentUserAdminFor(endpoint, RELOAD_CERTS_ACTION);
        } else {
            return false;
        }
    }

    ValidationResult<SslSettingsManager> withSecurityKeyStore() {
        if (sslSettingsManager == null) {
            return ValidationResult.error(RestStatus.OK, badRequestMessage("keystore is not initialized"));
        }
        return ValidationResult.success(sslSettingsManager);
    }

    protected void loadCertificates(final RestChannel channel) throws IOException {
        ok(
            channel,
            (builder, params) -> builder.startObject()
                .field(
                    "http_certificates_list",
                    generateCertDetailList(
                        sslSettingsManager.sslContextHandler(CertType.HTTP).map(SslContextHandler::keyMaterialCertificates).orElse(null)
                    )
                )
                .field(
                    "transport_certificates_list",
                    generateCertDetailList(
                        sslSettingsManager.sslContextHandler(CertType.TRANSPORT)
                            .map(SslContextHandler::keyMaterialCertificates)
                            .orElse(null)
                    )
                )
                .endObject()
        );
    }

    private List<Map<String, String>> generateCertDetailList(final Stream<Certificate> certs) {
        if (certs == null) {
            return null;
        }
        return certs.map(
            c -> ImmutableMap.of(
                "issuer_dn",
                c.issuer(),
                "subject_dn",
                c.subject(),
                "san",
                c.subjectAlternativeNames(),
                "not_before",
                c.notBefore(),
                "not_after",
                c.notAfter()
            )
        ).collect(Collectors.toList());
    }

    protected void reloadCertificates(final RestChannel channel, final RestRequest request) throws IOException {
        final String certType = request.param("certType").toLowerCase().trim();
        try {
            switch (certType) {
                case "http":
                    if (sslSettingsManager.sslConfiguration(CertType.HTTP).isPresent()) {
                        sslSettingsManager.reloadSslContext(CertType.HTTP);
                        ok(channel, (builder, params) -> builder.startObject().field("message", "updated http certs").endObject());
                    } else {
                        badRequest(channel, "SSL for HTTP is disabled");
                    }
                    break;
                case "transport":
                    sslSettingsManager.reloadSslContext(CertType.TRANSPORT);
                    sslSettingsManager.reloadSslContext(CertType.TRANSPORT_CLIENT);
                    ok(channel, (builder, params) -> builder.startObject().field("message", "updated transport certs").endObject());
                    break;
                default:
                    Responses.forbidden(
                        channel,
                        "invalid uri path, please use /_plugins/_security/api/ssl/http/reload or "
                            + "/_plugins/_security/api/ssl/transport/reload"
                    );
                    break;
            }
        } catch (final OpenSearchSecurityException e) {
            // LOGGER.error("Reload of certificates for {} failed", certType, e);
            throw new IOException(e);
        }
    }

}
