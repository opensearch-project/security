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
import org.opensearch.identity.PluginSubject;
import org.opensearch.indices.SystemIndexDescriptor;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.IdentityAwarePlugin;
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
import org.opensearch.sample.secure.actions.rest.create.SecurePluginAction;
import org.opensearch.sample.secure.actions.rest.create.SecurePluginRestAction;
import org.opensearch.sample.secure.actions.transport.SecurePluginTransportAction;
import org.opensearch.sample.utils.RunAsSubjectClient;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.opensearch.watcher.ResourceWatcherService;

import static org.opensearch.sample.utils.Constants.RESOURCE_INDEX_NAME;
import static org.opensearch.security.spi.resources.FeatureConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED;
import static org.opensearch.security.spi.resources.FeatureConfigConstants.OPENSEARCH_RESOURCE_SHARING_ENABLED_DEFAULT;

/**
 * Sample Resource plugin.
 * It uses ".sample_resource_sharing_plugin" index to manage its resources, and exposes few REST APIs that manage CRUD operations on sample resources.
 *
 */
public class SampleResourcePlugin extends Plugin implements ActionPlugin, SystemIndexPlugin, IdentityAwarePlugin {
    private static final Logger log = LogManager.getLogger(SampleResourcePlugin.class);
    private boolean isResourceSharingEnabled = false;

    private RunAsSubjectClient pluginClient;

    public SampleResourcePlugin(final Settings settings) {
        isResourceSharingEnabled = settings.getAsBoolean(OPENSEARCH_RESOURCE_SHARING_ENABLED, OPENSEARCH_RESOURCE_SHARING_ENABLED_DEFAULT);
    }

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
        this.pluginClient = new RunAsSubjectClient(client);
        return List.of(pluginClient);
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
        List<RestHandler> handlers = new ArrayList<>();
        handlers.add(new CreateResourceRestAction());
        handlers.add(new GetResourceRestAction());
        handlers.add(new DeleteResourceRestAction());
        handlers.add(new SecurePluginRestAction());

        if (isResourceSharingEnabled) {
            handlers.add(new ShareResourceRestAction());
            handlers.add(new RevokeResourceAccessRestAction());
        }
        return handlers;
    }

    @Override
    public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
        List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> actions = new ArrayList<>();
        actions.add(new ActionHandler<>(CreateResourceAction.INSTANCE, CreateResourceTransportAction.class));
        actions.add(new ActionHandler<>(GetResourceAction.INSTANCE, GetResourceTransportAction.class));
        actions.add(new ActionHandler<>(UpdateResourceAction.INSTANCE, UpdateResourceTransportAction.class));
        actions.add(new ActionHandler<>(DeleteResourceAction.INSTANCE, DeleteResourceTransportAction.class));
        if (isResourceSharingEnabled) {
            actions.add(new ActionHandler<>(ShareResourceAction.INSTANCE, ShareResourceTransportAction.class));
            actions.add(new ActionHandler<>(RevokeResourceAccessAction.INSTANCE, RevokeResourceAccessTransportAction.class));
        }
        actions.add(new ActionHandler<>(SecurePluginAction.INSTANCE, SecurePluginTransportAction.class));
        return actions;
    }

    @Override
    public Collection<SystemIndexDescriptor> getSystemIndexDescriptors(Settings settings) {
        final SystemIndexDescriptor systemIndexDescriptor = new SystemIndexDescriptor(RESOURCE_INDEX_NAME, "Sample index with resources");
        return Collections.singletonList(systemIndexDescriptor);
    }

    @Override
    public void assignSubject(PluginSubject pluginSubject) {
        if (this.pluginClient != null) {
            this.pluginClient.setSubject(pluginSubject);
        }
    }
}
