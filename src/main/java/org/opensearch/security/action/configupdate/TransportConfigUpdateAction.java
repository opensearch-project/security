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
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.action.configupdate;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.FailedNodeException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.nodes.TransportNodesAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.inject.Provider;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.security.auth.BackendRegistry;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportService;

public class TransportConfigUpdateAction extends TransportNodesAction<
    ConfigUpdateRequest,
    ConfigUpdateResponse,
    TransportConfigUpdateAction.NodeConfigUpdateRequest,
    ConfigUpdateNodeResponse> {

    protected Logger logger = LogManager.getLogger(getClass());
    private final Provider<BackendRegistry> backendRegistry;
    private final ConfigurationRepository configurationRepository;
    private DynamicConfigFactory dynamicConfigFactory;
    private static final Set<CType<?>> SELECTIVE_VALIDATION_TYPES = Set.of(CType.INTERNALUSERS);
    // Note: While INTERNALUSERS is used as a marker, the cache invalidation
    // applies to all user types (internal, LDAP, etc.)

    @Inject
    public TransportConfigUpdateAction(
        final Settings settings,
        final ThreadPool threadPool,
        final ClusterService clusterService,
        final TransportService transportService,
        final ConfigurationRepository configurationRepository,
        final ActionFilters actionFilters,
        Provider<BackendRegistry> backendRegistry,
        DynamicConfigFactory dynamicConfigFactory
    ) {
        super(
            ConfigUpdateAction.NAME,
            threadPool,
            clusterService,
            transportService,
            actionFilters,
            ConfigUpdateRequest::new,
            TransportConfigUpdateAction.NodeConfigUpdateRequest::new,
            ThreadPool.Names.MANAGEMENT,
            ConfigUpdateNodeResponse.class
        );

        this.configurationRepository = configurationRepository;
        this.backendRegistry = backendRegistry;
        this.dynamicConfigFactory = dynamicConfigFactory;
    }

    public static class NodeConfigUpdateRequest extends TransportRequest {

        ConfigUpdateRequest request;

        public NodeConfigUpdateRequest(StreamInput in) throws IOException {
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
    protected ConfigUpdateResponse newResponse(
        ConfigUpdateRequest request,
        List<ConfigUpdateNodeResponse> responses,
        List<FailedNodeException> failures
    ) {
        return new ConfigUpdateResponse(this.clusterService.getClusterName(), responses, failures);

    }

    @Override
    protected ConfigUpdateNodeResponse nodeOperation(final NodeConfigUpdateRequest request) {
        final var configupdateRequest = request.request;
        if (canHandleSelectively(configupdateRequest)) {
            backendRegistry.get().invalidateUserCache(configupdateRequest.getEntityNames());
        } else {
            boolean didReload = configurationRepository.reloadConfiguration(CType.fromStringValues((configupdateRequest.getConfigTypes())));
            if (didReload) {
                backendRegistry.get().invalidateCache();
            }
        }
        return new ConfigUpdateNodeResponse(clusterService.localNode(), configupdateRequest.getConfigTypes(), null);
    }

    private boolean canHandleSelectively(ConfigUpdateRequest request) {
        return request.getConfigTypes() != null
            && request.getEntityNames() != null
            && request.getConfigTypes().length == 1
            && request.getEntityNames().length > 0
            && SELECTIVE_VALIDATION_TYPES.contains(CType.fromString(request.getConfigTypes()[0]));
    }

    @Override
    protected NodeConfigUpdateRequest newNodeRequest(ConfigUpdateRequest request) {
        return new NodeConfigUpdateRequest(request);
    }

}
