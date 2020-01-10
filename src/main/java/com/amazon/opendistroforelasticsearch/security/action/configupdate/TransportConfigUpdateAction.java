/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.action.configupdate;

import java.io.IOException;
import java.util.List;
import java.util.stream.Stream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.FailedNodeException;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.nodes.BaseNodeRequest;
import org.elasticsearch.action.support.nodes.TransportNodesAction;
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

import com.amazon.opendistroforelasticsearch.security.auth.BackendRegistry;
import com.amazon.opendistroforelasticsearch.security.configuration.ConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.securityconf.DynamicConfigFactory;
import com.amazon.opendistroforelasticsearch.security.securityconf.impl.CType;

public class TransportConfigUpdateAction
extends
TransportNodesAction<ConfigUpdateRequest, ConfigUpdateResponse, TransportConfigUpdateAction.NodeConfigUpdateRequest, ConfigUpdateNodeResponse> {

    protected Logger logger = LogManager.getLogger(getClass());
    private final Provider<BackendRegistry> backendRegistry;
    private final ConfigurationRepository configurationRepository;
    private DynamicConfigFactory dynamicConfigFactory;
    
    @Inject
    public TransportConfigUpdateAction(final Settings settings,
            final ThreadPool threadPool, final ClusterService clusterService, final TransportService transportService,
            final ConfigurationRepository configurationRepository, final ActionFilters actionFilters,
            Provider<BackendRegistry> backendRegistry, DynamicConfigFactory dynamicConfigFactory) {        
        super(ConfigUpdateAction.NAME, threadPool, clusterService, transportService, actionFilters,
                ConfigUpdateRequest::new, TransportConfigUpdateAction.NodeConfigUpdateRequest::new,
                ThreadPool.Names.MANAGEMENT, ConfigUpdateNodeResponse.class);

        this.configurationRepository = configurationRepository;
        this.backendRegistry = backendRegistry;
        this.dynamicConfigFactory = dynamicConfigFactory;
    }

    public static class NodeConfigUpdateRequest extends BaseNodeRequest {

        ConfigUpdateRequest request;

        public NodeConfigUpdateRequest(StreamInput in) throws IOException{
            super(in);
            request = new ConfigUpdateRequest(in);
        }

        public NodeConfigUpdateRequest(final ConfigUpdateRequest request) {
            this.request = request;
        }

        @Override
        public void writeTo(final StreamOutput out) throws IOException {
            super.writeTo(out);
            request.writeTo(out);
        }
    }

    @Override
    protected ConfigUpdateNodeResponse newNodeResponse(StreamInput in) throws IOException {
        return new ConfigUpdateNodeResponse(in);
    }
    
    @Override
    protected ConfigUpdateResponse newResponse(ConfigUpdateRequest request, List<ConfigUpdateNodeResponse> responses,
            List<FailedNodeException> failures) {
        return new ConfigUpdateResponse(this.clusterService.getClusterName(), responses, failures);

    }
	
    @Override
    protected ConfigUpdateNodeResponse nodeOperation(final NodeConfigUpdateRequest request) {
        configurationRepository.reloadConfiguration(CType.fromStringValues((request.request.getConfigTypes())));
        backendRegistry.get().invalidateCache();
        return new ConfigUpdateNodeResponse(clusterService.localNode(), request.request.getConfigTypes(), null);
    }

    @Override
    protected NodeConfigUpdateRequest newNodeRequest(ConfigUpdateRequest request) {
        return new NodeConfigUpdateRequest(request);
    }

}
