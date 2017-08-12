/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.action.licenseinfo;

import java.io.IOException;
import java.util.List;

import org.elasticsearch.action.FailedNodeException;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.nodes.BaseNodeRequest;
import org.elasticsearch.action.support.nodes.TransportNodesAction;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;

import com.floragunn.searchguard.configuration.IndexBaseConfigurationRepository;
import com.floragunn.searchguard.configuration.SearchGuardLicense;
import com.floragunn.searchguard.support.ReflectionHelper;

public class TransportLicenseInfoAction
extends
TransportNodesAction<LicenseInfoRequest, LicenseInfoResponse, TransportLicenseInfoAction.NodeConfigUpdateRequest, LicenseInfoNodeResponse> {

    private final IndexBaseConfigurationRepository configurationRepository;
    
    @Inject
    public TransportLicenseInfoAction(final Settings settings,
            final ThreadPool threadPool, final ClusterService clusterService, final TransportService transportService,
            final IndexBaseConfigurationRepository configurationRepository, final ActionFilters actionFilters, final IndexNameExpressionResolver indexNameExpressionResolver) {
        
        super(settings, LicenseInfoAction.NAME, threadPool, clusterService, transportService, actionFilters,
                indexNameExpressionResolver, LicenseInfoRequest::new, TransportLicenseInfoAction.NodeConfigUpdateRequest::new,
                ThreadPool.Names.MANAGEMENT, LicenseInfoNodeResponse.class);

        this.configurationRepository = configurationRepository;
    }

    public static class NodeConfigUpdateRequest extends BaseNodeRequest {

        LicenseInfoRequest request;

        public NodeConfigUpdateRequest() {
        }

        public NodeConfigUpdateRequest(final String nodeId, final LicenseInfoRequest request) {
            super(nodeId);
            this.request = request;
        }

        @Override
        public void readFrom(final StreamInput in) throws IOException {
            super.readFrom(in);
            request = new LicenseInfoRequest();
            request.readFrom(in);
        }

        @Override
        public void writeTo(final StreamOutput out) throws IOException {
            super.writeTo(out);
            request.writeTo(out);
        }
    }

    protected NodeConfigUpdateRequest newNodeRequest(final String nodeId, final LicenseInfoRequest request) {
        return new NodeConfigUpdateRequest(nodeId, request);
    }

    @Override
    protected LicenseInfoNodeResponse newNodeResponse() {
        return new LicenseInfoNodeResponse(clusterService.localNode(), null, null);
    }
    
    
    @Override
    protected LicenseInfoResponse newResponse(LicenseInfoRequest request, List<LicenseInfoNodeResponse> responses,
            List<FailedNodeException> failures) {
        return new LicenseInfoResponse(this.clusterService.getClusterName(), responses, failures);

    }
	
    @Override
    protected LicenseInfoNodeResponse nodeOperation(final NodeConfigUpdateRequest request) {
        final SearchGuardLicense license = configurationRepository.getLicense();
        return new LicenseInfoNodeResponse(clusterService.localNode(), license, ReflectionHelper.getModulesLoaded()); 
    }
}
