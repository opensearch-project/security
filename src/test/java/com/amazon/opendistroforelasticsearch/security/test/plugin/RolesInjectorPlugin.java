/*
*   Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
*   Licensed under the Apache License, Version 2.0 (the "License").
*   You may not use this file except in compliance with the License.
*   A copy of the License is located at
*
*       http://www.apache.org/licenses/LICENSE-2.0
*
*   or in the "license" file accompanying this file. This file is distributed
*   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
*   express or implied. See the License for the specific language governing
*   permissions and limitations under the License.
*/

package com.amazon.opendistroforelasticsearch.security.test.plugin;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.env.Environment;
import org.elasticsearch.env.NodeEnvironment;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.repositories.RepositoriesService;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.watcher.ResourceWatcherService;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.function.Supplier;

public class RolesInjectorPlugin extends Plugin implements ActionPlugin {
    Settings settings;
    public static String injectedRoles = null;

    public RolesInjectorPlugin(final Settings settings, final Path configPath) {
        this.settings = settings;
    }

    @Override
    public Collection<Object> createComponents(Client client, ClusterService clusterService, ThreadPool threadPool,
                                               ResourceWatcherService resourceWatcherService, ScriptService scriptService,
                                               NamedXContentRegistry xContentRegistry, Environment environment,
                                               NodeEnvironment nodeEnvironment, NamedWriteableRegistry namedWriteableRegistry,
                                               IndexNameExpressionResolver indexNameExpressionResolver,
                                               Supplier<RepositoriesService> repositoriesServiceSupplier) {
            if(injectedRoles != null)
                threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES, injectedRoles);
            return new ArrayList<>();
    }
}
