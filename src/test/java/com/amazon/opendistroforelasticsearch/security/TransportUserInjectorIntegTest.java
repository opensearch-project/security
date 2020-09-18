package com.amazon.opendistroforelasticsearch.security;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.env.Environment;
import org.elasticsearch.env.NodeEnvironment;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.PluginAwareNode;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.repositories.RepositoriesService;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Netty4Plugin;
import org.elasticsearch.watcher.ResourceWatcherService;
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
        } catch (ElasticsearchSecurityException ex) {
            if(ex.getMessage().contains("Open Distro Security not initialized")) {
                Thread.sleep(500);
                waitForInit(client);
            }
        }
    }

    @Test
    public void testOpendistroSecurityUserInjection() throws Exception {
        final Settings clusterNodeSettings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, true)
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
                .put("opendistro_security.allow_default_init_securityindex", "true")
                .put(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, true)
                .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost + ":" + clusterInfo.nodePort)
                .build();


        // 1. without user injection
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenDistroSecurityPlugin.class, UserInjectorPlugin.class).start()) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-1")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
        }


        // 2. with invalid backend roles
        UserInjectorPlugin.injectedUser = "ttt|kkk";
        Exception exception = null;
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenDistroSecurityPlugin.class, UserInjectorPlugin.class).start()) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-2")).actionGet();
            Assert.fail("Expecting exception");
        } catch (ElasticsearchSecurityException ex) {
            exception = ex;
            log.warn(ex);
            Assert.assertNotNull(exception);
            Assert.assertTrue(exception.getMessage().contains("indices:admin/create"));
        }

        // 3. with valid backend roles for injected user
        UserInjectorPlugin.injectedUser = "injectedadmin|injecttest";
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenDistroSecurityPlugin.class, UserInjectorPlugin.class).start()) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-2")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
        }
    }

    @Test
    public void testOpendistroSecurityUserInjectionWithConfigDisabled() throws Exception {
        final Settings clusterNodeSettings = Settings.builder()
                .put(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, false)
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
                .put("opendistro_security.allow_default_init_securityindex", "true")
                .put(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_INJECT_USER_ENABLED, false)
                .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost + ":" + clusterInfo.nodePort)
                .build();

        // 1. without user injection
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenDistroSecurityPlugin.class, UserInjectorPlugin.class).start()) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-1")).actionGet();
            Assert.assertTrue(cir.isAcknowledged());
        }
        
        // with invalid backend roles
        UserInjectorPlugin.injectedUser = "ttt|kkk";
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class,
                OpenDistroSecurityPlugin.class, UserInjectorPlugin.class).start()) {
            waitForInit(node.client());
            CreateIndexResponse cir = node.client().admin().indices().create(new CreateIndexRequest("captain-logs-2")).actionGet();
            // Should pass as the user injection is disabled
            Assert.assertTrue(cir.isAcknowledged());
        }

    }
}
