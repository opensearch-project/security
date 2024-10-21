/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.sample;

import java.util.*;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.accesscontrol.resources.ResourceService;
import org.opensearch.action.ActionRequest;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.lifecycle.Lifecycle;
import org.opensearch.common.lifecycle.LifecycleComponent;
import org.opensearch.common.lifecycle.LifecycleListener;
import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.settings.IndexScopedSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.settings.SettingsFilter;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.indices.SystemIndexDescriptor;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.ResourcePlugin;
import org.opensearch.plugins.SystemIndexPlugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.sample.actions.create.CreateResourceAction;
import org.opensearch.sample.actions.create.CreateResourceRestAction;
import org.opensearch.sample.actions.list.ListAccessibleResourcesAction;
import org.opensearch.sample.actions.list.ListAccessibleResourcesRestAction;
import org.opensearch.sample.actions.share.ShareResourceAction;
import org.opensearch.sample.actions.share.ShareResourceRestAction;
import org.opensearch.sample.actions.verify.VerifyResourceAccessAction;
import org.opensearch.sample.actions.verify.VerifyResourceAccessRestAction;
import org.opensearch.sample.transport.CreateResourceTransportAction;
import org.opensearch.sample.transport.ListAccessibleResourcesTransportAction;
import org.opensearch.sample.transport.ShareResourceTransportAction;
import org.opensearch.sample.transport.VerifyResourceAccessTransportAction;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

/**
 * Sample Resource plugin.
 * It uses ".sample_resources" index to manage its resources, and exposes a REST API
 *
 */
public class SampleResourcePlugin extends Plugin implements ActionPlugin, SystemIndexPlugin, ResourcePlugin {
    private static final Logger log = LogManager.getLogger(SampleResourcePlugin.class);

    public static final String RESOURCE_INDEX_NAME = ".sample_resource_sharing_plugin";

    public final static Map<String, Object> INDEX_SETTINGS = Map.of("index.number_of_shards", 1, "index.auto_expand_replicas", "0-all");

    private Client client;

    @Override
    public Collection<Object> createComponents(
        Client client,
        ClusterService clusterService,
        ThreadPool threadPool,
        ResourceWatcherService resourceWatcherService,
        ScriptService scriptService,
        NamedXContentRegistry xContentRegistry,
        Environment environment,
        NodeEnvironment nodeEnvironment,
        NamedWriteableRegistry namedWriteableRegistry,
        IndexNameExpressionResolver indexNameExpressionResolver,
        Supplier<RepositoriesService> repositoriesServiceSupplier
    ) {
        this.client = client;
        log.info("Loaded SampleResourcePlugin components.");
        return Collections.emptyList();
    }

    @Override
    public List<RestHandler> getRestHandlers(
        Settings settings,
        RestController restController,
        ClusterSettings clusterSettings,
        IndexScopedSettings indexScopedSettings,
        SettingsFilter settingsFilter,
        IndexNameExpressionResolver indexNameExpressionResolver,
        Supplier<DiscoveryNodes> nodesInCluster
    ) {
        return List.of(
            new CreateResourceRestAction(),
            new ListAccessibleResourcesRestAction(),
            new VerifyResourceAccessRestAction(),
            new ShareResourceRestAction()
        );
    }

    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        return List.of(
            new ActionHandler<>(CreateResourceAction.INSTANCE, CreateResourceTransportAction.class),
            new ActionHandler<>(ListAccessibleResourcesAction.INSTANCE, ListAccessibleResourcesTransportAction.class),
            new ActionHandler<>(ShareResourceAction.INSTANCE, ShareResourceTransportAction.class),
            new ActionHandler<>(VerifyResourceAccessAction.INSTANCE, VerifyResourceAccessTransportAction.class)
        );
    }

    @Override
    public Collection<SystemIndexDescriptor> getSystemIndexDescriptors(Settings settings) {
        final SystemIndexDescriptor systemIndexDescriptor = new SystemIndexDescriptor(RESOURCE_INDEX_NAME, "Example index with resources");
        return Collections.singletonList(systemIndexDescriptor);
    }

    @Override
    public String getResourceType() {
        return "";
    }

    @Override
    public String getResourceIndex() {
        return RESOURCE_INDEX_NAME;
    }

    @Override
    public Collection<Class<? extends LifecycleComponent>> getGuiceServiceClasses() {
        final List<Class<? extends LifecycleComponent>> services = new ArrayList<>(1);
        services.add(GuiceHolder.class);
        return services;
    }

    public static class GuiceHolder implements LifecycleComponent {

        private static ResourceService resourceService;

        @Inject
        public GuiceHolder(final ResourceService resourceService) {
            GuiceHolder.resourceService = resourceService;
        }

        public static ResourceService getResourceService() {
            return resourceService;
        }

        @Override
        public void close() {}

        @Override
        public Lifecycle.State lifecycleState() {
            return null;
        }

        @Override
        public void addLifecycleListener(LifecycleListener listener) {}

        @Override
        public void removeLifecycleListener(LifecycleListener listener) {}

        @Override
        public void start() {}

        @Override
        public void stop() {}

    }
}
