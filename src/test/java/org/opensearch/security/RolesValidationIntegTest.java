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

package org.opensearch.security;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.function.Supplier;

import com.google.common.collect.Lists;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.node.Node;
import org.opensearch.node.PluginAwareNode;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.AbstractSecurityUnitTest;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.Netty4Plugin;
import org.opensearch.watcher.ResourceWatcherService;

public class RolesValidationIntegTest extends SingleClusterTest {

    public static class RolesValidationPlugin extends Plugin implements ActionPlugin {
        Settings settings;
        public static String rolesValidation = null;

        public RolesValidationPlugin(final Settings settings, final Path configPath) {
            this.settings = settings;
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
            if (rolesValidation != null) {
                threadPool.getThreadContext()
                    .putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES, "test|opendistro_security_all_access");
                threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES_VALIDATION, rolesValidation);
            }
            return new ArrayList<>();
        }
    }

    @Test
    public void testRolesValidation() throws Exception {
        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityRoles("roles.yml"), Settings.EMPTY);

        final Settings tcSettings = AbstractSecurityUnitTest.nodeRolesSettings(Settings.builder(), false, false)
            .put(minimumSecuritySettings(Settings.EMPTY).get(0))
            .put("cluster.name", clusterInfo.clustername)
            .put("path.data", "./target/data/" + clusterInfo.clustername + "/cert/data")
            .put("path.logs", "./target/data/" + clusterInfo.clustername + "/cert/logs")
            .put("path.home", "./target")
            .put("node.name", "testclient")
            .put("discovery.initial_state_timeout", "8s")
            .put("plugins.security.allow_default_init_securityindex", "true")
            .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost + ":" + clusterInfo.nodePort)
            .build();

        // 1. Without roles validation
        try (
            Node node = new PluginAwareNode(
                false,
                tcSettings,
                Lists.newArrayList(Netty4Plugin.class, OpenSearchSecurityPlugin.class, RolesValidationPlugin.class)
            ).start()
        ) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-1")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
            IndicesExistsResponse ier = node.client().admin().indices().exists(new IndicesExistsRequest("captain-logs-1")).actionGet();
            Assert.assertTrue(ier.isExists());
        }

        OpenSearchSecurityException exception = null;
        // 2. with roles invalid to the user
        RolesValidationPlugin.rolesValidation = "invalid_role";
        try (
            Node node = new PluginAwareNode(
                false,
                tcSettings,
                Lists.newArrayList(Netty4Plugin.class, OpenSearchSecurityPlugin.class, RolesValidationPlugin.class)
            ).start()
        ) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-2")).actionGet();
        } catch (OpenSearchSecurityException ex) {
            exception = ex;
        }
        Assert.assertNotNull(exception);
        Assert.assertTrue(exception.getMessage().contains("No mapping for"));

        // 3. with roles valid to the user
        RolesValidationPlugin.rolesValidation = "opendistro_security_all_access";
        try (
            Node node = new PluginAwareNode(
                false,
                tcSettings,
                Lists.newArrayList(Netty4Plugin.class, OpenSearchSecurityPlugin.class, RolesValidationPlugin.class)
            ).start()
        ) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-3")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
        }
    }
}
