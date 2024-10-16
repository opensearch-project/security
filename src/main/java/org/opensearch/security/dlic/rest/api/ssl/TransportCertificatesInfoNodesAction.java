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
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.opensearch.action.FailedNodeException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.nodes.TransportNodesAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.security.ssl.SslContextHandler;
import org.opensearch.security.ssl.SslSettingsManager;
import org.opensearch.security.ssl.config.CertType;
import org.opensearch.security.ssl.config.Certificate;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportService;

public class TransportCertificatesInfoNodesAction extends TransportNodesAction<
    CertificatesInfoNodesRequest,
    CertificatesNodesResponse,
    TransportCertificatesInfoNodesAction.NodeRequest,
    CertificatesNodesResponse.CertificatesNodeResponse> {

    private final SslSettingsManager sslSettingsManager;

    @Inject
    public TransportCertificatesInfoNodesAction(
        final ThreadPool threadPool,
        final ClusterService clusterService,
        final TransportService transportService,
        final ActionFilters actionFilters,
        final SslSettingsManager sslSettingsManager
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
        this.sslSettingsManager = sslSettingsManager;
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
            httpCertificates = sslSettingsManager.sslContextHandler(CertType.HTTP)
                .map(SslContextHandler::keyMaterialCertificates)
                .map(this::certificatesDetails)
                .orElse(List.of());
        }
        if (CertificateType.isTransport(certificateType)) {
            transportsCertificates = sslSettingsManager.sslContextHandler(CertType.TRANSPORT)
                .map(SslContextHandler::keyMaterialCertificates)
                .map(this::certificatesDetails)
                .orElse(List.of());
        }
        return new CertificatesInfo(Map.of(CertificateType.HTTP, httpCertificates, CertificateType.TRANSPORT, transportsCertificates));
    }

    private List<CertificateInfo> certificatesDetails(final Stream<Certificate> certificateStream) {
        if (certificateStream == null) {
            return null;
        }
        return certificateStream.map(
            c -> new CertificateInfo(c.subject(), c.subjectAlternativeNames(), c.issuer(), c.notAfter(), c.notBefore())
        ).collect(Collectors.toList());
    }

    public static class NodeRequest extends TransportRequest {

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
