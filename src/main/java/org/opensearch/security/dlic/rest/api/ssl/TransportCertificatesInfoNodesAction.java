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

package org.opensearch.security.dlic.rest.api.ssl;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;

import org.opensearch.action.FailedNodeException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.nodes.BaseNodeRequest;
import org.opensearch.action.support.nodes.TransportNodesAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.security.ssl.DefaultSecurityKeyStore;
import org.opensearch.security.ssl.util.SSLConfigConstants;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

public class TransportCertificatesInfoNodesAction extends TransportNodesAction<
    CertificatesInfoNodesRequest,
    CertificatesNodesResponse,
    TransportCertificatesInfoNodesAction.NodeRequest,
    CertificatesNodesResponse.CertificatesNodeResponse> {

    private final DefaultSecurityKeyStore securityKeyStore;

    private final boolean httpsEnabled;

    @Inject
    public TransportCertificatesInfoNodesAction(
        final Settings settings,
        final ThreadPool threadPool,
        final ClusterService clusterService,
        final TransportService transportService,
        final ActionFilters actionFilters,
        final DefaultSecurityKeyStore securityKeyStore
    ) {
        super(
            CertificatesActionType.NAME,
            threadPool,
            clusterService,
            transportService,
            actionFilters,
            CertificatesInfoNodesRequest::new,
            NodeRequest::new,
            ThreadPool.Names.GENERIC,
            CertificatesNodesResponse.CertificatesNodeResponse.class
        );
        this.httpsEnabled = settings.getAsBoolean(SSLConfigConstants.SECURITY_SSL_HTTP_ENABLED, true);
        this.securityKeyStore = securityKeyStore;
    }

    @Override
    protected CertificatesNodesResponse newResponse(
        CertificatesInfoNodesRequest request,
        List<CertificatesNodesResponse.CertificatesNodeResponse> nodeResponses,
        List<FailedNodeException> failures
    ) {
        return new CertificatesNodesResponse(clusterService.getClusterName(), nodeResponses, failures);
    }

    @Override
    protected NodeRequest newNodeRequest(final CertificatesInfoNodesRequest request) {
        return new NodeRequest(request);
    }

    @Override
    protected CertificatesNodesResponse.CertificatesNodeResponse newNodeResponse(final StreamInput in) throws IOException {
        return new CertificatesNodesResponse.CertificatesNodeResponse(in);
    }

    @Override
    protected CertificatesNodesResponse.CertificatesNodeResponse nodeOperation(final NodeRequest request) {
        final var sslCertRequest = request.sslCertsInfoNodesRequest;

        if (securityKeyStore == null) {
            return new CertificatesNodesResponse.CertificatesNodeResponse(
                clusterService.localNode(),
                new IllegalStateException("keystore is not initialized")
            );
        }
        try {
            return new CertificatesNodesResponse.CertificatesNodeResponse(
                clusterService.localNode(),
                loadCertificates(sslCertRequest.certificateType())
            );
        } catch (final Exception e) {
            return new CertificatesNodesResponse.CertificatesNodeResponse(clusterService.localNode(), e);
        }
    }

    protected CertificatesInfo loadCertificates(final CertificateType certificateType) {
        var httpCertificates = List.<CertificateInfo>of();
        var transportsCertificates = List.<CertificateInfo>of();
        if (CertificateType.isHttp(certificateType)) {
            httpCertificates = httpsEnabled ? certificatesDetails(securityKeyStore.getHttpCerts()) : List.of();
        }
        if (CertificateType.isTransport(certificateType)) {
            transportsCertificates = certificatesDetails(securityKeyStore.getTransportCerts());
        }
        return new CertificatesInfo(Map.of(CertificateType.HTTP, httpCertificates, CertificateType.TRANSPORT, transportsCertificates));
    }

    private List<CertificateInfo> certificatesDetails(final X509Certificate[] certs) {
        if (certs == null) {
            return null;
        }
        final var certificates = ImmutableList.<CertificateInfo>builder();
        for (final var c : certs) {
            certificates.add(CertificateInfo.from(c, securityKeyStore.getSubjectAlternativeNames(c)));
        }
        return certificates.build();
    }

    public static class NodeRequest extends BaseNodeRequest {

        CertificatesInfoNodesRequest sslCertsInfoNodesRequest;

        public NodeRequest(StreamInput in) throws IOException {
            super(in);
            sslCertsInfoNodesRequest = new CertificatesInfoNodesRequest(in);
        }

        NodeRequest(CertificatesInfoNodesRequest request) {
            this.sslCertsInfoNodesRequest = request;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            sslCertsInfoNodesRequest.writeTo(out);
        }
    }

}
