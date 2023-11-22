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
import java.util.List;
import java.util.function.Supplier;

import com.google.common.collect.Lists;
import org.junit.Assert;
import org.junit.Test;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.Strings;
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

public class TransportUserInjectorIntegTest extends SingleClusterTest {

    public static final String TEST_INJECTED_USER = "test_injected_user";

    public static class UserInjectorPlugin extends Plugin implements ActionPlugin {
        Settings settings;

        public UserInjectorPlugin(final Settings settings, final Path configPath) {
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
            if (!Strings.isNullOrEmpty(settings.get(TEST_INJECTED_USER))) threadPool.getThreadContext()
                .putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, settings.get(TEST_INJECTED_USER));
            return new ArrayList<>();
        }

        @Override
        public List<Setting<?>> getSettings() {
            List<Setting<?>> settings = new ArrayList<Setting<?>>();
            settings.add(Setting.simpleString(TEST_INJECTED_USER, Setting.Property.NodeScope, Setting.Property.Filtered));
            return settings;
        }
    }

    @Test
    public void testSecurityUserInjection() throws Exception {
        final Settings clusterNodeSettings = Settings.builder().put(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, true).build();
        setup(clusterNodeSettings, new DynamicSecurityConfig().setSecurityRolesMapping("roles_transport_inject_user.yml"), Settings.EMPTY);
        final Settings.Builder tcSettings = AbstractSecurityUnitTest.nodeRolesSettings(Settings.builder(), false, false)
            .put(minimumSecuritySettings(Settings.EMPTY).get(0))
            .put("cluster.name", clusterInfo.clustername)
            .put("path.data", "./target/data/" + clusterInfo.clustername + "/cert/data")
            .put("path.logs", "./target/data/" + clusterInfo.clustername + "/cert/logs")
            .put("path.home", "./target")
            .put("node.name", "testclient")
            .put("discovery.initial_state_timeout", "8s")
            .put("plugins.security.allow_default_init_securityindex", "true")
            .put(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, true)
            .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost + ":" + clusterInfo.nodePort);

        // 1. without user injection
        try (
            Node node = new PluginAwareNode(
                false,
                tcSettings.build(),
                Lists.newArrayList(Netty4Plugin.class, OpenSearchSecurityPlugin.class, UserInjectorPlugin.class)
            ).start()
        ) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-1")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
        }

        // 2. with invalid backend roles
        Exception exception = null;
        try (
            Node node = new PluginAwareNode(
                false,
                tcSettings.put(TEST_INJECTED_USER, "ttt|kkk").build(),
                Lists.newArrayList(Netty4Plugin.class, OpenSearchSecurityPlugin.class, UserInjectorPlugin.class)
            ).start()
        ) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-2")).actionGet();
            Assert.fail("Expecting exception");
        } catch (OpenSearchSecurityException ex) {
            exception = ex;
            log.debug(ex.toString());
            Assert.assertNotNull(exception);
            Assert.assertTrue(exception.getMessage().toString().contains("no permissions for [indices:admin/create]"));
        }

        // 3. with valid backend roles for injected user
        try (
            Node node = new PluginAwareNode(
                false,
                tcSettings.put(TEST_INJECTED_USER, "injectedadmin|injecttest").build(),
                Lists.newArrayList(Netty4Plugin.class, OpenSearchSecurityPlugin.class, UserInjectorPlugin.class)
            ).start()
        ) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-2")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
        }
    }

    @Test
    public void testSecurityUserInjectionWithConfigDisabled() throws Exception {
        final Settings clusterNodeSettings = Settings.builder()
            .put(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, false)
            .build();
        setup(clusterNodeSettings, new DynamicSecurityConfig().setSecurityRolesMapping("roles_transport_inject_user.yml"), Settings.EMPTY);
        final Settings.Builder tcSettings = AbstractSecurityUnitTest.nodeRolesSettings(Settings.builder(), false, false)
            .put(minimumSecuritySettings(Settings.EMPTY).get(0))
            .put("cluster.name", clusterInfo.clustername)
            .put("path.data", "./target/data/" + clusterInfo.clustername + "/cert/data")
            .put("path.logs", "./target/data/" + clusterInfo.clustername + "/cert/logs")
            .put("path.home", "./target")
            .put("node.name", "testclient")
            .put("discovery.initial_state_timeout", "8s")
            .put("plugins.security.allow_default_init_securityindex", "true")
            .put(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, false)
            .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost + ":" + clusterInfo.nodePort);

        // 1. without user injection
        try (
            Node node = new PluginAwareNode(
                false,
                tcSettings.build(),
                Lists.newArrayList(Netty4Plugin.class, OpenSearchSecurityPlugin.class, UserInjectorPlugin.class)
            ).start()
        ) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-1")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
        }

        // with invalid backend roles
        try (
            Node node = new PluginAwareNode(
                false,
                tcSettings.put(TEST_INJECTED_USER, "ttt|kkk").build(),
                Lists.newArrayList(Netty4Plugin.class, OpenSearchSecurityPlugin.class, UserInjectorPlugin.class)
            ).start()
        ) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-2")).actionGet();
            // Should pass as the user injection is disabled
            Assert.assertTrue(cir.isAcknowledged());
        }
    }
}
