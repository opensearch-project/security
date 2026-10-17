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
package org.opensearch.security.ssl.util;

import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.filter.SecurityRequest;
import org.opensearch.security.ssl.transport.PrincipalExtractor;
import org.opensearch.security.support.WildcardMatcher;

public class HeaderClientCertResolver {
    private static final Logger log = LogManager.getLogger(HeaderClientCertResolver.class);

    public static SSLRequestHelper.SSLInfo maybeOverride(
        Settings settings,
        SecurityRequest request,
        X509Certificate[] x509Certs,
        String principal,
        PrincipalExtractor principalExtractor,
        String protocol,
        String cipher,
        X509Certificate[] localCerts
    ) {
        final String clientCertHeaderName = settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_HEADER_CERT_NAME, "x-client-cert");
        // SSLConfigConstants.SECURITY_SSL_HTTP_HEADER_CERT_ALLOWED_PROXY_PRINCIPLE configuration used to specify which principle can switch
        // user to header cert so its limited to external load balancer proxy , not all clients
        final WildcardMatcher allowedPrinciplesToAssumeHeaderCert = WildcardMatcher.from(
            settings.getAsList(SSLConfigConstants.SECURITY_SSL_HTTP_HEADER_CERT_ALLOWED_PROXY_PRINCIPLE)
        );

        final boolean allowRoleFromHeaderCert = Boolean.parseBoolean(
            settings.get(SSLConfigConstants.SECURITY_SSL_HTTP_USE_HEADER_CERT, "false")
        );

        String clientCert = request.header(clientCertHeaderName);
        // we want to make x509Certs is not null and has already been validated through handshake ,
        // only then we allow header based cert role assumption
        if (clientCert != null && allowRoleFromHeaderCert && x509Certs != null) {
            if (allowedPrinciplesToAssumeHeaderCert.test(principal)) {
                log.trace("Client Cert Encoded : {} ", clientCert);
                clientCert = URLDecoder.decode(clientCert, StandardCharsets.UTF_8);
                log.trace("Client Cert From Header : {} ", clientCert);

                byte[] decodedClientCert = clientCert.getBytes(StandardCharsets.UTF_8);

                CertificateFactory factory = null;
                try {
                    factory = CertificateFactory.getInstance("X.509");
                    X509Certificate[] x509HeaderCerts = new X509Certificate[1];
                    x509HeaderCerts[0] = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(decodedClientCert));
                    principal = principalExtractor == null
                        ? null
                        : principalExtractor.extractPrincipal(x509HeaderCerts[0], PrincipalExtractor.Type.HTTP);
                    // At this point if no exception in parsing, then replace original certs that were used in handshake validation to
                    // header
                    // cert
                    x509Certs = x509HeaderCerts;
                } catch (CertificateException e) {
                    log.error("Failed to parse  certificate from header", e);
                }
            }
        }
        return new SSLRequestHelper.SSLInfo(x509Certs, principal, protocol, cipher, localCerts);
    }
}
