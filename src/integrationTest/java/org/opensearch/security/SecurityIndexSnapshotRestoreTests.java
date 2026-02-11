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

import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.admin.cluster.repositories.delete.DeleteRepositoryRequest;
import org.opensearch.action.admin.cluster.repositories.put.PutRepositoryRequest;
import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotRequest;
import org.opensearch.action.admin.cluster.snapshots.restore.RestoreSnapshotResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.security.api.AbstractApiIntegrationTest;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.InternalUserV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.LocalOpenSearchCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.opensearch.security.CrossClusterSearchTests.TYPE_ATTRIBUTE;
import static org.opensearch.security.SearchOperationTest.TEST_SNAPSHOT_REPOSITORY_NAME;
import static org.opensearch.security.support.ConfigConstants.SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;
import static org.opensearch.test.framework.matcher.GetResponseMatchers.containDocument;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SecurityIndexSnapshotRestoreTests extends AbstractApiIntegrationTest {
    private static final Logger log = LogManager.getLogger(SecurityIndexSnapshotRestoreTests.class);

    private static final String TEST_INDEX_NAME = "my_index_001";
    private static final String DOC_ID = "doc_id";

    private static final TestSecurityConfig.User ADMIN_USER = new TestSecurityConfig.User("admin").roles(ALL_ACCESS)
        .attr(TYPE_ATTRIBUTE, "administrative");

    private static final TestSecurityConfig.User LIMITED_READ_USER_1 = new TestSecurityConfig.User("limited_read_user").roles(
        new TestSecurityConfig.Role("limited-reader").indexPermissions("indices:data/read*").on(TEST_INDEX_NAME)
    );

    private static final TestSecurityConfig.User LIMITED_READ_USER_2 = new TestSecurityConfig.User("user2");

    private static final TestSecurityConfig.Role LIMITED_READ_USER_2_ROLE = new TestSecurityConfig.Role("limited-reader_2")
        .indexPermissions("indices:data/read*")
        .on(TEST_INDEX_NAME);

    private String securityIndex;

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER, LIMITED_READ_USER_1)
        .anonymousAuth(false)
        .nodeSettings(
            Map.of(
                SECURITY_RESTAPI_ROLES_ENABLED,
                List.of("user_" + USER_ADMIN.getName() + "__" + ALL_ACCESS.getName()),
                SECURITY_BACKGROUND_INIT_IF_SECURITYINDEX_NOT_EXIST,
                false
            )
        )
        .build();

    @Before
    public void setUp() throws Exception {
        securityIndex = ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX;

        try (Client client = cluster.getInternalNodeClient()) {
            client.admin()
                .cluster()
                .putRepository(
                    new PutRepositoryRequest(TEST_SNAPSHOT_REPOSITORY_NAME).type("fs")
                        .settings(Map.of("location", cluster.getSnapshotDirPath()))
                )
                .actionGet();

            CreateIndexResponse createIndexResponse = client.admin().indices().create(new CreateIndexRequest(TEST_INDEX_NAME)).actionGet();
            assertTrue(createIndexResponse.isAcknowledged());

            client.index(
                new IndexRequest(TEST_INDEX_NAME).id(DOC_ID)
                    .source("{\"message\": \"test document 1\"}", XContentType.JSON)
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
            ).actionGet();
        }
    }

    @After
    public void cleanData() throws ExecutionException, InterruptedException {
        try (Client client = cluster.getInternalNodeClient()) {
            client.admin().indices().delete(new DeleteIndexRequest(TEST_INDEX_NAME)).actionGet();

            client.admin().cluster().deleteRepository(new DeleteRepositoryRequest(TEST_SNAPSHOT_REPOSITORY_NAME)).actionGet();
        }
    }

    @Test
    public void testSecurityCacheReloadAfterRestore() throws Exception {
        // 1. Read data in custom index with LIMITED_READ_USER_1
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER_1)) {
            GetResponse response = restHighLevelClient.get(new GetRequest(TEST_INDEX_NAME, DOC_ID), RequestOptions.DEFAULT);
            assertThat(response, containDocument(TEST_INDEX_NAME, DOC_ID));
        }

        // 2. Create snapshot of security index
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(ADMIN_USER)) {
            SnapshotSteps steps = new SnapshotSteps(restHighLevelClient);
            steps.createSnapshot(TEST_SNAPSHOT_REPOSITORY_NAME, "test-snap", securityIndex);
            steps.waitForSnapshotCreation(TEST_SNAPSHOT_REPOSITORY_NAME, "test-snap");
        }

        // 3. Add new role and user to security index (This is not in snapshot created above)
        try (TestRestClient client = cluster.getRestClient(ADMIN_USER)) {
            client.createRole(LIMITED_READ_USER_2_ROLE.getName(), LIMITED_READ_USER_2_ROLE).assertStatusCode(201);
            client.createUser(LIMITED_READ_USER_2.getName(), LIMITED_READ_USER_2).assertStatusCode(201);
            client.assignRoleToUser(LIMITED_READ_USER_2.getName(), "limited-reader_2").assertStatusCode(200);
        }

        // 4. Read data in custom index with LIMITED_READ_USER_2
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER_2)) {
            GetResponse response = restHighLevelClient.get(new GetRequest(TEST_INDEX_NAME, DOC_ID), RequestOptions.DEFAULT);
            assertThat(response, containDocument(TEST_INDEX_NAME, DOC_ID));
        }

        // 5. Delete security index
        try (Client client = cluster.getInternalNodeClient()) {
            DeleteIndexRequest deleteRequest = new DeleteIndexRequest(securityIndex);
            client.admin().indices().delete(deleteRequest).actionGet();
        }

        // 6. Restore security index
        try (Client client = cluster.getInternalNodeClient()) {
            RestoreSnapshotRequest restoreRequest = new RestoreSnapshotRequest(TEST_SNAPSHOT_REPOSITORY_NAME, "test-snap")
                .waitForCompletion(true)
                .indices(securityIndex);  // restore security index

            RestoreSnapshotResponse restoreResponse = client.admin().cluster().restoreSnapshot(restoreRequest).actionGet();

            // Verify restore was successful
            assertEquals(RestStatus.OK, restoreResponse.status());
        }

        // 7. Read data in custom index with LIMITED_READ_USER_1 because it was in snapshot
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER_1)) {
            GetResponse response = restHighLevelClient.get(new GetRequest(TEST_INDEX_NAME, DOC_ID), RequestOptions.DEFAULT);
            assertThat(response, containDocument(TEST_INDEX_NAME, DOC_ID));
        }

        // 8. Should get 401 error to read custom index with LIMITED_READ_USER_2 because it was not in snapshot
        try (RestHighLevelClient restHighLevelClient = cluster.getRestHighLevelClient(LIMITED_READ_USER_2)) {
            restHighLevelClient.get(new GetRequest(TEST_INDEX_NAME, DOC_ID), RequestOptions.DEFAULT);
        } catch (OpenSearchStatusException exception) {
            assertEquals(RestStatus.UNAUTHORIZED, exception.status());  // Verify it's a 401
        }

        // 9. Verify all nodes have reloaded the security configuration by directly checking ConfigurationRepository
        // This ensures the ConfigUpdateAction was broadcast to all nodes (cluster managers + data nodes)
        for (LocalOpenSearchCluster.Node node : cluster.nodes()) {
            log.info("Verifying security config reload on node: {}", node.getNodeName());

            ConfigurationRepository configRepository = node.getInjectable(ConfigurationRepository.class);
            assertThat("ConfigurationRepository should not be null on node " + node.getNodeName(), configRepository, is(notNullValue()));

            // Verify LIMITED_READ_USER_1 exists in the config (was in snapshot)
            SecurityDynamicConfiguration<InternalUserV7> internalUsersConfig = configRepository.getConfiguration(CType.INTERNALUSERS);
            assertThat(
                "LIMITED_READ_USER_1 should exist in config on node " + node.getNodeName(),
                internalUsersConfig.getCEntry(LIMITED_READ_USER_1.getName()),
                is(notNullValue())
            );

            // Verify LIMITED_READ_USER_2 does NOT exist in the config (was not in snapshot)
            assertThat(
                "LIMITED_READ_USER_2 should NOT exist in config on node " + node.getNodeName(),
                internalUsersConfig.getCEntry(LIMITED_READ_USER_2.getName()),
                is(nullValue())
            );

            // Verify the role for LIMITED_READ_USER_2 does NOT exist (was not in snapshot)
            SecurityDynamicConfiguration<RoleV7> rolesConfig = configRepository.getConfiguration(CType.ROLES);
            assertThat(
                "LIMITED_READ_USER_2_ROLE should NOT exist in config on node " + node.getNodeName(),
                rolesConfig.getCEntry(LIMITED_READ_USER_2_ROLE.getName()),
                is(nullValue())
            );
        }
    }
}
