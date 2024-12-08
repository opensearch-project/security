/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.sample;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
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
import org.opensearch.sample.actions.access.list.ListAccessibleResourcesAction;
import org.opensearch.sample.actions.access.list.ListAccessibleResourcesRestAction;
import org.opensearch.sample.actions.access.revoke.RevokeResourceAccessAction;
import org.opensearch.sample.actions.access.revoke.RevokeResourceAccessRestAction;
import org.opensearch.sample.actions.access.share.ShareResourceAction;
import org.opensearch.sample.actions.access.share.ShareResourceRestAction;
import org.opensearch.sample.actions.access.verify.VerifyResourceAccessAction;
import org.opensearch.sample.actions.access.verify.VerifyResourceAccessRestAction;
import org.opensearch.sample.actions.resource.create.CreateResourceAction;
import org.opensearch.sample.actions.resource.create.CreateResourceRestAction;
import org.opensearch.sample.actions.resource.delete.DeleteResourceAction;
import org.opensearch.sample.actions.resource.delete.DeleteResourceRestAction;
import org.opensearch.sample.transport.access.ListAccessibleResourcesTransportAction;
import org.opensearch.sample.transport.access.RevokeResourceAccessTransportAction;
import org.opensearch.sample.transport.access.ShareResourceTransportAction;
import org.opensearch.sample.transport.access.VerifyResourceAccessTransportAction;
import org.opensearch.sample.transport.resource.CreateResourceTransportAction;
import org.opensearch.sample.transport.resource.DeleteResourceTransportAction;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Sample Resource plugin.
 * It uses ".sample_resources" index to manage its resources, and exposes a REST API
 *
 */
public class SampleResourcePlugin extends Plugin implements ActionPlugin, SystemIndexPlugin, ResourcePlugin {
    private static final Logger log = LogManager.getLogger(SampleResourcePlugin.class);

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
            new RevokeResourceAccessRestAction(),
            new ShareResourceRestAction(),
            new DeleteResourceRestAction()
        );
    }

    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        return List.of(
            new ActionHandler<>(CreateResourceAction.INSTANCE, CreateResourceTransportAction.class),
            new ActionHandler<>(ListAccessibleResourcesAction.INSTANCE, ListAccessibleResourcesTransportAction.class),
            new ActionHandler<>(ShareResourceAction.INSTANCE, ShareResourceTransportAction.class),
            new ActionHandler<>(RevokeResourceAccessAction.INSTANCE, RevokeResourceAccessTransportAction.class),
            new ActionHandler<>(VerifyResourceAccessAction.INSTANCE, VerifyResourceAccessTransportAction.class),
            new ActionHandler<>(DeleteResourceAction.INSTANCE, DeleteResourceTransportAction.class)
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
