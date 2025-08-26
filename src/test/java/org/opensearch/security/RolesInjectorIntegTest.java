/*
 *   Copyright OpenSearch Contributors
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

package org.opensearch.security;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.function.Supplier;

import com.google.common.collect.Lists;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.admin.indices.refresh.RefreshResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.rest.RestStatus;
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
import org.opensearch.transport.Netty4ModulePlugin;
import org.opensearch.transport.client.Client;
import org.opensearch.watcher.ResourceWatcherService;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;

public class RolesInjectorIntegTest extends SingleClusterTest {
    public static class RolesInjectorPlugin extends Plugin implements ActionPlugin {
        Settings settings;
        public static String injectedRoles = null;
        public static Map<String, String> injectedCustomAttributes = null;

        public RolesInjectorPlugin(final Settings settings, final Path configPath) {
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
            if (injectedRoles != null) threadPool.getThreadContext()
                .putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES, injectedRoles);
            if (injectedCustomAttributes != null) threadPool.getThreadContext()
                .putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER_CUSTOM_ATTRIBUTES, injectedCustomAttributes);
            return new ArrayList<>();
        }
    }

    @Test
    public void testRolesInject() throws Exception {
        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityRoles("roles.yml"), Settings.EMPTY);

        assertThat(
            clusterInfo.numNodes,
            is(
                clusterHelper.nodeClient()
                    .admin()
                    .cluster()
                    .health(new ClusterHealthRequest().waitForGreenStatus())
                    .actionGet()
                    .getNumberOfNodes()
            )
        );
        assertThat(
            ClusterHealthStatus.GREEN,
            is(clusterHelper.nodeClient().admin().cluster().health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus())
        );

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

        // 1. Without roles injection.
        try (
            Node node = new PluginAwareNode(
                false,
                tcSettings,
                Lists.newArrayList(Netty4ModulePlugin.class, OpenSearchSecurityPlugin.class, RolesInjectorPlugin.class)
            ).start()
        ) {
            waitForInit(node.client());

            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-1")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
            IndicesExistsResponse ier = node.client().admin().indices().exists(new IndicesExistsRequest("captain-logs-1")).actionGet();
            Assert.assertTrue(ier.isExists());
        }

        // 2. With invalid roles, must throw security exception.
        RolesInjectorPlugin.injectedRoles = "invalid_user|invalid_role";
        Exception exception = null;
        try (
            Node node = new PluginAwareNode(
                false,
                tcSettings,
                Lists.newArrayList(Netty4ModulePlugin.class, OpenSearchSecurityPlugin.class, RolesInjectorPlugin.class)
            ).start()
        ) {
            waitForInit(node.client());

            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-2")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
        } catch (OpenSearchSecurityException ex) {
            exception = ex;
            log.warn(ex.toString());
        }
        Assert.assertNotNull(exception);
        Assert.assertTrue(exception.getMessage().contains("indices:admin/create"));

        // 3. With valid roles - which has permission to create index.
        RolesInjectorPlugin.injectedRoles = "valid_user|opendistro_security_all_access";
        try (
            Node node = new PluginAwareNode(
                false,
                tcSettings,
                Lists.newArrayList(Netty4ModulePlugin.class, OpenSearchSecurityPlugin.class, RolesInjectorPlugin.class)
            ).start()
        ) {
            waitForInit(node.client());

            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-3")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());

            IndicesExistsResponse ier = node.client().admin().indices().exists(new IndicesExistsRequest("captain-logs-3")).actionGet();
            Assert.assertTrue(ier.isExists());
        }

        // 4. With a role using DLS and attribute substitution, but with no attributes specified in the thread context
        RolesInjectorPlugin.injectedRoles = "valid_user|role_with_dls";
        try (
            Node node = new PluginAwareNode(
                false,
                tcSettings,
                Lists.newArrayList(Netty4ModulePlugin.class, OpenSearchSecurityPlugin.class, RolesInjectorPlugin.class)
            ).start()
        ) {
            waitForInit(node.client());

            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-4")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
        } catch (OpenSearchSecurityException ex) {
            exception = ex;
            log.warn(ex.toString());
        }
        Assert.assertNotNull(exception);
        Assert.assertTrue(exception.getMessage().contains("Error while evaluating DLS/FLS privileges"));

        // 5. With a role using DLS and attribute substitution and with attributes specified in the thread context
        // First we need to use a role without DLS to write data to the index. Roles with DLS restrictions cannot perform writes.
        RolesInjectorPlugin.injectedRoles = "valid_user|role_without_dls_write";
        try (
            Node node = new PluginAwareNode(
                false,
                tcSettings,
                Lists.newArrayList(Netty4ModulePlugin.class, OpenSearchSecurityPlugin.class, RolesInjectorPlugin.class)
            ).start()
        ) {
            waitForInit(node.client());

            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-5")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());

            IndicesExistsResponse ier = node.client().admin().indices().exists(new IndicesExistsRequest("captain-logs-5")).actionGet();
            Assert.assertTrue(ier.isExists());

            Map<String, String> document = Map.of("starship", "enterprise");
            Map<String, String> document2 = Map.of("starship", "voyager");

            IndexResponse idr = node.client()
                .index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index("captain-logs-5").id("1").source(document))
                .actionGet();
            Assert.assertEquals(idr.status(), RestStatus.CREATED);

            IndexResponse idr2 = node.client()
                .index(new IndexRequest().setRefreshPolicy(IMMEDIATE).index("captain-logs-5").id("2").source(document2))
                .actionGet();
            Assert.assertEquals(idr2.status(), RestStatus.CREATED);

            RefreshResponse rer = node.client().admin().indices().prepareRefresh("captain-logs-5").get();
            Assert.assertEquals(rer.getStatus(), RestStatus.OK);

            SearchResponse ser = clusterHelper.nodeClient().search(new SearchRequest("captain-logs-5")).actionGet();
            Assert.assertEquals(RestStatus.OK, ser.status());
            Assert.assertEquals(2, ser.getHits().getTotalHits().value());
            Assert.assertTrue(ser.toString().contains("enterprise"));
            Assert.assertTrue(ser.toString().contains("voyager"));

            // Now use a role with DLS and custom attributes to test that attribute substitution works
            // and searched documents are filtered correctly.
            ThreadPool tp = clusterHelper.nodeClient().threadPool();
            try (ThreadContext.StoredContext ignored = tp.getThreadContext().stashContext()) {
                ThreadContext tc = tp.getThreadContext();
                tc.putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES, "valid_user|role_with_dls");
                tc.putTransient(
                    ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER_CUSTOM_ATTRIBUTES,
                    Map.of("attr.proxy.starship", "enterprise")
                );

                SearchResponse serDls = clusterHelper.nodeClient().search(new SearchRequest("captain-logs-5")).actionGet();
                Assert.assertEquals(RestStatus.OK, serDls.status());
                Assert.assertEquals(1, serDls.getHits().getTotalHits().value());
                Assert.assertTrue(serDls.toString().contains("enterprise"));
            }
        }
    }
}
