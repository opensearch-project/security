/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.opensearch.sample;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.ActionRequest;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
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
import org.opensearch.plugins.SystemIndexPlugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.sample.resource.actions.rest.create.CreateResourceAction;
import org.opensearch.sample.resource.actions.rest.create.CreateResourceRestAction;
import org.opensearch.sample.resource.actions.rest.create.UpdateResourceAction;
import org.opensearch.sample.resource.actions.rest.delete.DeleteResourceAction;
import org.opensearch.sample.resource.actions.rest.delete.DeleteResourceRestAction;
import org.opensearch.sample.resource.actions.rest.get.GetResourceAction;
import org.opensearch.sample.resource.actions.rest.get.GetResourceRestAction;
import org.opensearch.sample.resource.actions.rest.revoke.RevokeResourceAccessAction;
import org.opensearch.sample.resource.actions.rest.revoke.RevokeResourceAccessRestAction;
import org.opensearch.sample.resource.actions.rest.share.ShareResourceAction;
import org.opensearch.sample.resource.actions.rest.share.ShareResourceRestAction;
import org.opensearch.sample.resource.actions.transport.CreateResourceTransportAction;
import org.opensearch.sample.resource.actions.transport.DeleteResourceTransportAction;
import org.opensearch.sample.resource.actions.transport.GetResourceTransportAction;
import org.opensearch.sample.resource.actions.transport.RevokeResourceAccessTransportAction;
import org.opensearch.sample.resource.actions.transport.ShareResourceTransportAction;
import org.opensearch.sample.resource.actions.transport.UpdateResourceTransportAction;
import org.opensearch.sample.resource.client.ResourceSharingClientAccessor;
import org.opensearch.script.ScriptService;
import org.opensearch.security.spi.resources.ResourceProvider;
import org.opensearch.security.spi.resources.ResourceSharingExtension;
import org.opensearch.security.spi.resources.client.ResourceSharingClient;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.opensearch.watcher.ResourceWatcherService;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;

/**
 * Sample Resource plugin.
 * It uses ".sample_resource_sharing_plugin" index to manage its resources, and exposes few REST APIs that manage CRUD operations on sample resources.
 *
 */
public class SampleResourcePlugin extends Plugin implements ActionPlugin, SystemIndexPlugin, ResourceSharingExtension {
    private static final Logger log = LogManager.getLogger(SampleResourcePlugin.class);

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
            new GetResourceRestAction(),
            new DeleteResourceRestAction(),
            new ShareResourceRestAction(),
            new RevokeResourceAccessRestAction()
        );
    }

    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        return List.of(
            new ActionHandler<>(CreateResourceAction.INSTANCE, CreateResourceTransportAction.class),
            new ActionHandler<>(GetResourceAction.INSTANCE, GetResourceTransportAction.class),
            new ActionHandler<>(UpdateResourceAction.INSTANCE, UpdateResourceTransportAction.class),
            new ActionHandler<>(DeleteResourceAction.INSTANCE, DeleteResourceTransportAction.class),
            new ActionHandler<>(ShareResourceAction.INSTANCE, ShareResourceTransportAction.class),
            new ActionHandler<>(RevokeResourceAccessAction.INSTANCE, RevokeResourceAccessTransportAction.class)
        );
    }

    @Override
    public Collection<SystemIndexDescriptor> getSystemIndexDescriptors(Settings settings) {
        final SystemIndexDescriptor systemIndexDescriptor = new SystemIndexDescriptor(RESOURCE_INDEX_NAME, "Sample index with resources");
        return Collections.singletonList(systemIndexDescriptor);
    }

    @Override
    public Set<ResourceProvider> getResourceProviders() {
        return Set.of(new ResourceProvider(SampleResource.class.getCanonicalName(), RESOURCE_INDEX_NAME, new SampleResourceParser()));
    }

    @Override
    public void assignResourceSharingClient(ResourceSharingClient resourceSharingClient) {
        ResourceSharingClientAccessor.setResourceSharingClient(resourceSharingClient);
    }
}
