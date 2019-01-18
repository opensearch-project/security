/*
 * Copyright 2015-2017 floragunn GmbH
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

package com.amazon.opendistrosecurity.action.configupdate;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.elasticsearch.action.FailedNodeException;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.nodes.BaseNodeRequest;
import org.elasticsearch.action.support.nodes.TransportNodesAction;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;

import com.amazon.opendistrosecurity.auth.BackendRegistry;
import com.amazon.opendistrosecurity.configuration.ConfigurationRepository;
import com.amazon.opendistrosecurity.configuration.IndexBaseConfigurationRepository;
import com.amazon.opendistrosecurity.configuration.OpenDistroSecurityLicense;
import com.amazon.opendistrosecurity.support.LicenseHelper;

public class TransportConfigUpdateAction
extends
TransportNodesAction<ConfigUpdateRequest, ConfigUpdateResponse, TransportConfigUpdateAction.NodeConfigUpdateRequest, ConfigUpdateNodeResponse> {

    private final Provider<BackendRegistry> backendRegistry;
    private final ConfigurationRepository configurationRepository;
    
    @Inject
    public TransportConfigUpdateAction(final Settings settings,
            final ThreadPool threadPool, final ClusterService clusterService, final TransportService transportService,
            final IndexBaseConfigurationRepository configurationRepository, final ActionFilters actionFilters, final IndexNameExpressionResolver indexNameExpressionResolver,
            Provider<BackendRegistry> backendRegistry) {
        
        super(settings, ConfigUpdateAction.NAME, threadPool, clusterService, transportService, actionFilters,
                indexNameExpressionResolver, ConfigUpdateRequest::new, TransportConfigUpdateAction.NodeConfigUpdateRequest::new,
                ThreadPool.Names.MANAGEMENT, ConfigUpdateNodeResponse.class);

        this.configurationRepository = configurationRepository;
        this.backendRegistry = backendRegistry;
    }

    public static class NodeConfigUpdateRequest extends BaseNodeRequest {

        ConfigUpdateRequest request;

        public NodeConfigUpdateRequest() {
        }

        public NodeConfigUpdateRequest(final String nodeId, final ConfigUpdateRequest request) {
            super(nodeId);
            this.request = request;
        }

        @Override
        public void readFrom(final StreamInput in) throws IOException {
            super.readFrom(in);
            request = new ConfigUpdateRequest();
            request.readFrom(in);
        }

        @Override
        public void writeTo(final StreamOutput out) throws IOException {
            super.writeTo(out);
            request.writeTo(out);
        }
    }

    protected NodeConfigUpdateRequest newNodeRequest(final String nodeId, final ConfigUpdateRequest request) {
        return new NodeConfigUpdateRequest(nodeId, request);
    }

    @Override
    protected ConfigUpdateNodeResponse newNodeResponse() {
        return new ConfigUpdateNodeResponse(clusterService.localNode(), new String[0], null);
    }
    
    
    @Override
    protected ConfigUpdateResponse newResponse(ConfigUpdateRequest request, List<ConfigUpdateNodeResponse> responses,
            List<FailedNodeException> failures) {
        return new ConfigUpdateResponse(this.clusterService.getClusterName(), responses, failures);

    }
	
    @Override
    protected ConfigUpdateNodeResponse nodeOperation(final NodeConfigUpdateRequest request) {
        final Map<String, Settings> setn = configurationRepository.reloadConfiguration(Arrays.asList(request.request.getConfigTypes()));
        String licenseText = null;
        
        if(setn.get("config") != null) {
            licenseText = setn.get("config").get("opendistrosecurity.dynamic.license");
        }
        
        if(licenseText != null && !licenseText.isEmpty()) {
            try {
                final OpenDistroSecurityLicense license = new OpenDistroSecurityLicense(XContentHelper.convertToMap(XContentType.JSON.xContent(), LicenseHelper.validateLicense(licenseText), true), clusterService);
                
                if(!license.isValid()) {
                    logger.warn("License "+license.getUid()+" is invalid due to "+license.getMsgs());
                    //throw an exception here if loading of invalid license should be denied
                }
            } catch (Exception e) {
                logger.error("Invalid license",e);
                return new ConfigUpdateNodeResponse(clusterService.localNode(), new String[0], "Invalid license: "+e); 
            }
        }

        backendRegistry.get().invalidateCache();
        return new ConfigUpdateNodeResponse(clusterService.localNode(), setn.keySet().toArray(new String[0]), null); 
    }
}
