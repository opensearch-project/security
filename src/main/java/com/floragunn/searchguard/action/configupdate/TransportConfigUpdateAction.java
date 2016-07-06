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

package com.floragunn.searchguard.action.configupdate;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReferenceArray;

import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.nodes.BaseNodeRequest;
import org.elasticsearch.action.support.nodes.TransportNodesAction;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.common.component.LifecycleListener;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Provider;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TransportService;

import com.floragunn.searchguard.action.configupdate.ConfigUpdateResponse.Node;
import com.floragunn.searchguard.auth.BackendRegistry;
import com.floragunn.searchguard.configuration.ConfigChangeListener;
import com.floragunn.searchguard.configuration.ConfigurationLoader;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.Lists;
import com.google.common.collect.Multimaps;

public class TransportConfigUpdateAction
extends
TransportNodesAction<ConfigUpdateRequest, ConfigUpdateResponse, TransportConfigUpdateAction.NodeConfigUpdateRequest, ConfigUpdateResponse.Node> {

    private final ClusterService clusterService;
    private final ConfigurationLoader cl;
    private final Provider<BackendRegistry> backendRegistry;
    private final ListMultimap<String, ConfigChangeListener> multimap = Multimaps.synchronizedListMultimap(ArrayListMultimap
            .<String, ConfigChangeListener> create());

    @Inject
    public TransportConfigUpdateAction(final Provider<Client> clientProvider, final Settings settings, final ClusterName clusterName,
            final ThreadPool threadPool, final ClusterService clusterService, final TransportService transportService,
            final ConfigurationLoader cl, final ActionFilters actionFilters, final IndexNameExpressionResolver indexNameExpressionResolver,
            Provider<BackendRegistry> backendRegistry) {
        super(settings, ConfigUpdateAction.NAME, clusterName, threadPool, clusterService, transportService, actionFilters,
                indexNameExpressionResolver, ConfigUpdateRequest.class, TransportConfigUpdateAction.NodeConfigUpdateRequest.class,
                ThreadPool.Names.MANAGEMENT);
        this.cl = cl;
        this.clusterService = clusterService;
        this.backendRegistry = backendRegistry;

        clusterService.addLifecycleListener(new LifecycleListener() {

            @Override
            public void afterStart() {

                threadPool.executor(ThreadPool.Names.GET).execute(new Runnable() {

                    @Override
                    public void run() {
                        Client client = clientProvider.get();
                        logger.debug("Node started, try to initialize it. Wait for yellow cluster state....");
                        ClusterHealthResponse response = client.admin().cluster().health(new ClusterHealthRequest("searchguard").waitForYellowStatus()).actionGet();
                        
                        while(response.isTimedOut() || response.getStatus() == ClusterHealthStatus.RED) {
                            logger.warn("searchguard index not healthy (timeout: {})", response.isTimedOut());
                            try {
                                Thread.sleep(3000);
                            } catch (InterruptedException e) {
                                //ignore
                            }
                            response = client.admin().cluster().health(new ClusterHealthRequest("searchguard").waitForYellowStatus()).actionGet();
                            continue;
                        }
                        
                        Map<String, Settings> setn = cl.load(new String[] { "config", "roles", "rolesmapping", "internalusers",
                                "actiongroups" });
                        
                        while(!setn.keySet().containsAll(Lists.newArrayList("config", "roles", "rolesmapping"))) {
                            try {
                                Thread.sleep(1000);
                            } catch (InterruptedException e) {
                                //ignore
                            }
                            setn = cl.load(new String[] { "config", "roles", "rolesmapping", "internalusers",
                            "actiongroups" });
                        }
                        
                        synchronized (TransportConfigUpdateAction.this) {
                            logger.debug("Retrieved config on node startup and will now update config change listeners");
                            for (final String evt : setn.keySet()) {
                                for (final ConfigChangeListener cl : new ArrayList<ConfigChangeListener>(multimap.get(evt))) {
                                    Settings settings = setn.get(evt);
                                    if(settings != null) {
                                        cl.onChange(evt, settings);
                                        logger.debug("Updated {} for {} due to initial configuration on node '{}'", evt, cl.getClass().getSimpleName(), clusterService.localNode().getName());
                                    }
                                }
                            }
                            
                            logger.debug("Node '{}' initialized", clusterService.localNode().getName());                            
                        }                       
                    }
                });
            }
        });

    }

    public static class NodeConfigUpdateRequest extends BaseNodeRequest {

        ConfigUpdateRequest request;

        public NodeConfigUpdateRequest() {
        }

        public NodeConfigUpdateRequest(final String nodeId, final ConfigUpdateRequest request) {
            super(request, nodeId);
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

    @Override
    protected ConfigUpdateResponse newResponse(final ConfigUpdateRequest request, final AtomicReferenceArray nodesResponses) {
        
        final List<ConfigUpdateResponse.Node> nodes = Lists.<ConfigUpdateResponse.Node> newArrayList();
        for (int i = 0; i < nodesResponses.length(); i++) {
            final Object resp = nodesResponses.get(i);
            if (resp instanceof ConfigUpdateResponse.Node) {
                nodes.add((ConfigUpdateResponse.Node) resp);
            }
        }
        return new ConfigUpdateResponse(this.clusterName, nodes.toArray(new ConfigUpdateResponse.Node[nodes.size()]));

    }

    @Override
    protected NodeConfigUpdateRequest newNodeRequest(final String nodeId, final ConfigUpdateRequest request) {
        return new NodeConfigUpdateRequest(nodeId, request);
    }

    @Override
    protected Node newNodeResponse() {
        return new ConfigUpdateResponse.Node(clusterService.localNode(), new String[0]);
    }

    @Override
    protected Node nodeOperation(final NodeConfigUpdateRequest request) {
        backendRegistry.get().invalidateCache();
        final Map<String, Settings> setn = cl.load(request.request.getConfigTypes());
        
        if(setn.size() != request.request.getConfigTypes().length) {
            logger.error("Unable to load all configurations types. Loaded '{}' but should '{}' ", setn.keySet(), Arrays.toString(request.request.getConfigTypes()));
        }

        synchronized (TransportConfigUpdateAction.this) {
            logger.debug("Retrieved config due to config update request and will now update config change listeners");
            for (final String evt : setn.keySet()) {
                for (final ConfigChangeListener cl : new ArrayList<ConfigChangeListener>(multimap.get(evt))) {
                    Settings settings = setn.get(evt);
                    if(settings != null) {
                       cl.onChange(evt, settings);
                       logger.debug("Updated {} for {} due to node operation on node {}", evt, cl.getClass().getSimpleName(), clusterService.localNode().getName());
                    }
                }
            }
            return new ConfigUpdateResponse.Node(clusterService.localNode(), setn.keySet().toArray(new String[0]));
        }
    }

    public void addConfigChangeListener(final String event, final ConfigChangeListener listener) {
        logger.debug("Add config listener {}",listener.getClass());
        multimap.put(event, listener);
    }

    @Override
    protected boolean accumulateExceptions() {
        return false;
    }

}
