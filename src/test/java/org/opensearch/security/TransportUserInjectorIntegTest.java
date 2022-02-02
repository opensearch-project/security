package org.opensearch.security;

import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.io.stream.NamedWriteableRegistry;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.node.Node;
import org.opensearch.node.PluginAwareNode;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.Netty4Plugin;
import org.opensearch.watcher.ResourceWatcherService;
import org.junit.Assert;
import org.junit.Test;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.function.Supplier;

public class TransportUserInjectorIntegTest extends SingleClusterTest {

    public static class UserInjectorPlugin extends Plugin implements ActionPlugin {
        Settings settings;
        public static String injectedUser = null;

        public UserInjectorPlugin(final Settings settings, final Path configPath) {
            this.settings = settings;
        }

        @Override
        public Collection<Object> createComponents(Client client, ClusterService clusterService, ThreadPool threadPool,
                                                   ResourceWatcherService resourceWatcherService, ScriptService scriptService,
                                                   NamedXContentRegistry xContentRegistry, Environment environment,
                                                   NodeEnvironment nodeEnvironment, NamedWriteableRegistry namedWriteableRegistry,
                                                   IndexNameExpressionResolver indexNameExpressionResolver,
                                                   Supplier<RepositoriesService> repositoriesServiceSupplier) {
            if(injectedUser != null)
                threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_USER, injectedUser);
            return new ArrayList<>();
        }
    }

    //Wait for the security plugin to load roles.
    private void waitForInit(Client client) throws Exception {
        try {
            client.admin().cluster().health(new ClusterHealthRequest()).actionGet();
        } catch (OpenSearchSecurityException ex) {
            if(ex.getMessage().contains("OpenSearch Security not initialized")) {
                Thread.sleep(500);
                waitForInit(client);
            }
        }
    }

    @Test
    public void testSecurityUserInjection() throws Exception {
        final Settings clusterNodeSettings = Settings.builder()
                .put(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, true)
                .build();
        setup(clusterNodeSettings, new DynamicSecurityConfig().setSecurityRolesMapping("roles_transport_inject_user.yml"), Settings.EMPTY);
        final Settings tcSettings = Settings.builder()
                .put(minimumSecuritySettings(Settings.EMPTY).get(0))
                .put("cluster.name", clusterInfo.clustername)
                .put("node.data", false)
                .put("node.master", false)
                .put("node.ingest", false)
                .put("path.data", "./target/data/" + clusterInfo.clustername + "/cert/data")
                .put("path.logs", "./target/data/" + clusterInfo.clustername + "/cert/logs")
                .put("path.home", "./target")
                .put("node.name", "testclient")
                .put("discovery.initial_state_timeout", "8s")
                .put("plugins.security.allow_default_init_securityindex", "true")
                .put(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, true)
                .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost + ":" + clusterInfo.nodePort)
                .build();


        // 1. without user injection
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenSearchSecurityPlugin.class, UserInjectorPlugin.class).start()) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-1")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
        }


        // 2. with invalid backend roles
        UserInjectorPlugin.injectedUser = "ttt|kkk";
        Exception exception = null;
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenSearchSecurityPlugin.class, UserInjectorPlugin.class).start()) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-2")).actionGet();
            Assert.fail("Expecting exception");
        } catch (OpenSearchSecurityException ex) {
            exception = ex;
            log.warn(ex.toString());
            Assert.assertNotNull(exception);
            Assert.assertTrue(exception.getMessage().contains("indices:admin/create"));
        }

        // 3. with valid backend roles for injected user
        UserInjectorPlugin.injectedUser = "injectedadmin|injecttest";
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenSearchSecurityPlugin.class, UserInjectorPlugin.class).start()) {
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
        final Settings tcSettings = Settings.builder()
                .put(minimumSecuritySettings(Settings.EMPTY).get(0))
                .put("cluster.name", clusterInfo.clustername)
                .put("node.data", false)
                .put("node.master", false)
                .put("node.ingest", false)
                .put("path.data", "./target/data/" + clusterInfo.clustername + "/cert/data")
                .put("path.logs", "./target/data/" + clusterInfo.clustername + "/cert/logs")
                .put("path.home", "./target")
                .put("node.name", "testclient")
                .put("discovery.initial_state_timeout", "8s")
                .put("plugins.security.allow_default_init_securityindex", "true")
                .put(ConfigConstants.SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, false)
                .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost + ":" + clusterInfo.nodePort)
                .build();

        // 1. without user injection
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenSearchSecurityPlugin.class, UserInjectorPlugin.class).start()) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-1")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
        }
        
        // with invalid backend roles
        UserInjectorPlugin.injectedUser = "ttt|kkk";
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenSearchSecurityPlugin.class, UserInjectorPlugin.class).start()) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-2")).actionGet();
            // Should pass as the user injection is disabled
            Assert.assertTrue(cir.isAcknowledged());
        }

    }
}
