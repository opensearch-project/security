/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package org.opensearch.security.dlic.dlsfls;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.function.Supplier;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.junit.Assert;
import org.junit.Test;
import org.opensearch.action.ActionListener;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.action.ActionResponse;
import org.opensearch.action.ActionType;
import org.opensearch.action.IndicesRequest;
import org.opensearch.action.IndicesRequest.Replaceable;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.action.support.WriteRequest.RefreshPolicy;
import org.opensearch.action.support.master.AcknowledgedRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.client.transport.TransportClient;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.io.stream.NamedWriteableRegistry;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.NamedXContentRegistry;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.node.Node;
import org.opensearch.node.PluginAwareNode;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.security.OpenSearchSecurityPlugin;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.test.DynamicSecurityConfig;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.Netty4Plugin;
import org.opensearch.transport.TransportService;
import org.opensearch.watcher.ResourceWatcherService;

public class CCReplicationTest extends AbstractDlsFlsTest {
    public static class MockReplicationPlugin extends Plugin implements ActionPlugin {
        public static String injectedRoles = null;

        public MockReplicationPlugin() {
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

        @Override
        public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
            return Arrays.asList(new ActionHandler<>(MockReplicationAction.INSTANCE, TransportMockReplicationAction.class));
        }
    }

    public static class MockReplicationAction extends ActionType<AcknowledgedResponse> {
        public static final MockReplicationAction INSTANCE = new MockReplicationAction();
        public static final String NAME = "indices:admin/plugins/replication/file_chunk";
        private MockReplicationAction() {
            super(NAME, AcknowledgedResponse::new);
        }
    }

    public static class MockReplicationRequest extends AcknowledgedRequest<MockReplicationRequest> implements Replaceable {
        private String index;
        public MockReplicationRequest(String index) {
            this.index = index;
        }

        public MockReplicationRequest(StreamInput inp) throws IOException {
            super(inp);
            index = inp.readString();
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeString(index);
        }

        @Override
        public ActionRequestValidationException validate() {
            return null;
        }

        @Override
        public IndicesRequest indices(String... strings) {
            return this;
        }

        @Override
        public String[] indices() {
            return new String[]{index};
        }

        @Override
        public IndicesOptions indicesOptions() {
            return IndicesOptions.strictSingleIndexNoExpandForbidClosed();
        }

        @Override
        public boolean includeDataStreams() {
            return false;
        }
    }

    public static class TransportMockReplicationAction extends HandledTransportAction<MockReplicationRequest, AcknowledgedResponse> {

        @Inject
        public TransportMockReplicationAction(TransportService transportService,
            ActionFilters actionFilters) {
            super(MockReplicationAction.NAME, transportService, actionFilters, MockReplicationRequest::new);
        }

        @Override
        protected void doExecute(Task task, MockReplicationRequest request, ActionListener<AcknowledgedResponse> actionListener) {
            actionListener.onResponse(new AcknowledgedResponse(true));
        }
    }

    //Wait for the security plugin to load roles.
    private void waitOrThrow(Client client, String index) throws Exception {
        int failures = 0;
        while(failures < 5) {
            try {
                client.execute(MockReplicationAction.INSTANCE, new MockReplicationRequest(index)).actionGet();
                break;
            } catch (OpenSearchSecurityException ex) {
                if (ex.getMessage().contains("OpenSearch Security not initialized")) {
                    Thread.sleep(500);
                    failures++;
                } else {
                    throw ex;
                }
            }
        }
    }

    void populateData(TransportClient tc) {
        tc.index(new IndexRequest("hr-dls").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .source("{\"User\": \"testuser\",\"Date\":\"2021-01-18T17:27:20Z\",\"Designation\":\"HR\"}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("hr-fls").type("config").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .source("{\"User\": \"adminuser\",\"Date\":\"2021-01-18T17:27:20Z\",\"Designation\":\"CEO\"}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("hr-masking").type("config").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .source("{\"User\": \"maskeduser\",\"Date\":\"2021-01-18T17:27:20Z\",\"Designation\":\"CEO\"}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("hr-normal").type("config").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .source("{\"User\": \"employee1\",\"Date\":\"2021-01-18T17:27:20Z\",\"Designation\":\"EMPLOYEE\"}", XContentType.JSON)).actionGet();
    }

    @Test
    public void testReplication() throws Exception {
        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityRoles("roles_ccreplication.yml"), Settings.EMPTY);

        Assert.assertEquals(clusterInfo.numNodes, clusterHelper.nodeClient().admin().cluster().health(
            new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, clusterHelper.nodeClient().admin().cluster().
            health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());

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
            .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost + ":" + clusterInfo.nodePort)
            .build();

        // Set roles for the user
        MockReplicationPlugin.injectedRoles = "ccr_user|opendistro_security_human_resources_trainee";
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class, OpenSearchSecurityPlugin.class, MockReplicationPlugin.class).start()) {
            waitOrThrow(node.client(), "hr-dls");
            Assert.fail("Expecting exception");
        } catch (OpenSearchSecurityException ex) {
            log.warn(ex.getMessage());
            Assert.assertNotNull(ex);
            Assert.assertTrue(ex.getMessage().contains("Cross Cluster Replication is not supported when FLS or DLS or Fieldmasking is activated"));
        }

        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class, OpenSearchSecurityPlugin.class, MockReplicationPlugin.class).start()) {
            waitOrThrow(node.client(), "hr-fls");
            Assert.fail("Expecting exception");
        } catch (OpenSearchSecurityException ex) {
            log.warn(ex.getMessage());
            Assert.assertNotNull(ex);
            Assert.assertTrue(ex.getMessage().contains("Cross Cluster Replication is not supported when FLS or DLS or Fieldmasking is activated"));
        }

        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class, OpenSearchSecurityPlugin.class, MockReplicationPlugin.class).start()) {
            waitOrThrow(node.client(), "hr-masking");
            Assert.fail("Expecting exception");
        } catch (OpenSearchSecurityException ex) {
            log.warn(ex.getMessage());
            Assert.assertNotNull(ex);
            Assert.assertTrue(ex.getMessage().contains("Cross Cluster Replication is not supported when FLS or DLS or Fieldmasking is activated"));
        }

        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class, OpenSearchSecurityPlugin.class, MockReplicationPlugin.class).start()) {
            waitOrThrow(node.client(), "hr-normal");
            AcknowledgedResponse res = node.client().execute(MockReplicationAction.INSTANCE, new MockReplicationRequest("hr-normal")).actionGet();
            Assert.assertTrue(res.isAcknowledged());
        }
    }
}
