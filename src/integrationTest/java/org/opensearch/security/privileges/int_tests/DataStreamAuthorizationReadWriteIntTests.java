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

package org.opensearch.security.privileges.int_tests;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.annotation.concurrent.NotThreadSafe;

import com.carrotsearch.randomizedtesting.annotations.ParametersFactory;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.google.common.collect.ImmutableList;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.indices.refresh.RefreshRequest;
import org.opensearch.test.framework.TestComponentTemplate;
import org.opensearch.test.framework.TestDataStream;
import org.opensearch.test.framework.TestIndex;
import org.opensearch.test.framework.TestIndexOrAliasOrDatastream;
import org.opensearch.test.framework.TestIndexTemplate;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.cluster.TestRestClient.json;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.OnResponseIndexMatcher.containsExactly;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.OnUserIndexMatcher.limitedTo;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.OnUserIndexMatcher.limitedToNone;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.OnUserIndexMatcher.unlimited;
import static org.opensearch.test.framework.matcher.IndexApiResponseMatchers.OnUserIndexMatcher.unlimitedIncludingOpenSearchSecurityIndex;
import static org.opensearch.test.framework.matcher.RestMatchers.isBadRequest;
import static org.opensearch.test.framework.matcher.RestMatchers.isCreated;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;
import static org.junit.Assert.assertEquals;

/**
 * This class defines a huge test matrix for index related access controls. This class is especially for read/write operations on data streams.
 * It uses the following dimensions:
 * <ul>
 *     <li>ClusterConfig: At the moment, we test without and with system index permission enabled. New semantics will follow later.</li>
 *     <li>TestSecurityConfig.User: We have quite a few of different users with different privileges configurations.</li>
 *     <li>The test methods represent different operations with different options that are tested</li>
 * </ul>
 * To cope with the huge space of tests, this class uses test oracles to verify the result of the operations.
 * These are defined with the "indexMatcher()" method of TestSecurityConfig.User. See there and the class IndexApiMatchers.
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@NotThreadSafe
public class DataStreamAuthorizationReadWriteIntTests {

    // -------------------------------------------------------------------------------------------------------
    // Test indices used by this test suite. We use the following naming scheme:
    // - index_*r*, ds_*r*: This test will not write to this index or data stream
    // - index_*w*, ds_*w*: This test can write to this index or data stream; the test won't delete and recreate it
    // - index_*wx*, ds_*wx*: The index is not initially created; the test can create it on demand and delete it again
    // -------------------------------------------------------------------------------------------------------

    static TestDataStream ds_ar1 = TestDataStream.name("ds_ar1").documentCount(22).rolloverAfter(10).build();
    static TestDataStream ds_ar2 = TestDataStream.name("ds_ar2").documentCount(22).rolloverAfter(10).build();
    static TestDataStream ds_aw1 = TestDataStream.name("ds_aw1").documentCount(22).rolloverAfter(10).build();
    static TestDataStream ds_aw2 = TestDataStream.name("ds_aw2").documentCount(22).rolloverAfter(10).build();
    static TestDataStream ds_br1 = TestDataStream.name("ds_br1").documentCount(22).rolloverAfter(10).build();
    static TestDataStream ds_br2 = TestDataStream.name("ds_br2").documentCount(22).rolloverAfter(10).build();
    static TestDataStream ds_bw1 = TestDataStream.name("ds_bw1").documentCount(22).rolloverAfter(10).build();
    static TestDataStream ds_bw2 = TestDataStream.name("ds_bw2").documentCount(22).rolloverAfter(10).build();
    static TestIndex index_cr1 = TestIndex.name("index_cr1").documentCount(10).build();
    static TestIndex index_cw1 = TestIndex.name("index_cw1").documentCount(10).build();
    static TestDataStream ds_hidden = TestDataStream.name("ds_hidden").documentCount(10).rolloverAfter(3).seed(8).build();

    static TestDataStream ds_bwx1 = TestDataStream.name("ds_bwx1").documentCount(0).build(); // not initially created
    static TestDataStream ds_bwx2 = TestDataStream.name("ds_bwx2").documentCount(0).build(); // not initially created

    // -------------------------------------------------------------------------------------------------------
    // Test users with which the tests will be executed; the users need to be added to the list USERS below
    // The users have two redundant versions or privilege configuration, which needs to be kept in sync:
    // - The standard role configuration defined with .roles()
    // - IndexMatchers which act as test oracles, defined with the indexMatcher() methods
    // -------------------------------------------------------------------------------------------------------

    /**
     * A simple user that can read from ds_a* and write to ds_aw*; the user as no privileges to create or manage data streams
     */
    static TestSecurityConfig.User LIMITED_USER_A = new TestSecurityConfig.User("limited_user_A")//
        .description("ds_a*")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "indices_monitor")
                .on("ds_a*")//
                .indexPermissions("write")
                .on("ds_aw*")
        )//
        .indexMatcher("read", limitedTo(ds_ar1, ds_ar2, ds_aw1, ds_aw2))//
        .indexMatcher("write", limitedTo(ds_aw1, ds_aw2))//
        .indexMatcher("create_data_stream", limitedToNone())//
        .indexMatcher("manage_data_stream", limitedToNone());

    /**
     * A simple user that can read from ds_b* and write to ds_bw*; the user as no privileges to create or manage data streams
     */
    static TestSecurityConfig.User LIMITED_USER_B = new TestSecurityConfig.User("limited_user_B")//
        .description("ds_b*")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "indices_monitor")
                .on("ds_b*")//
                .indexPermissions("write")
                .on("ds_bw*")
        )//
        .indexMatcher("read", limitedTo(ds_br1, ds_br2, ds_bw1, ds_bw2, ds_bwx1, ds_bwx2))//
        .indexMatcher("write", limitedTo(ds_bw1, ds_bw2, ds_bwx1, ds_bwx2))//
        .indexMatcher("create_data_stream", limitedToNone())//
        .indexMatcher("manage_data_stream", limitedToNone());

    /**
     * A simple user that can read from ds_b* and write to ds_bw*; the user as no privileges to create or manage data streams.
     * Additionally, they can read from ds_a*
     */
    static TestSecurityConfig.User LIMITED_USER_B_READ_ONLY_A = new TestSecurityConfig.User("limited_user_B_read_only_A")//
        .description("ds_b*; read only on ds_a*")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "indices_monitor")
                .on("ds_a*", "ds_b*")//
                .indexPermissions("write")
                .on("ds_bw*")
        )//
        .indexMatcher("read", limitedTo(ds_ar1, ds_ar2, ds_aw1, ds_aw2, ds_br1, ds_br2, ds_bw1, ds_bw2, ds_bwx1, ds_bwx2))//
        .indexMatcher("write", limitedTo(ds_bw1, ds_bw2, ds_bwx1, ds_bwx2))//
        .indexMatcher("create_data_stream", limitedToNone())//
        .indexMatcher("manage_data_stream", limitedToNone());

    /**
     * This is an artificial user - in the sense that in real life it would likely not exist this way.
     * It has privileges to write on ds_b*, but privileges for indices:admin/mapping/auto_put on all data streams.
     * The reason is that some indexing operations are two phase - first auto put, then indexing. To be able to test both
     * phases, we need which user which always allows the first phase to pass.
     */
    static TestSecurityConfig.User LIMITED_USER_B_AUTO_PUT_ON_ALL = new TestSecurityConfig.User("limited_user_B_auto_put_on_all")//
        .description("ds_b* with full auto put")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "indices_monitor")
                .on("ds_b*")//
                .indexPermissions("write")
                .on("ds_bw*")//
                .indexPermissions("indices:admin/mapping/auto_put")
                .on("*")
        )//
        .indexMatcher("read", limitedTo(ds_br1, ds_br2, ds_bw1, ds_bw2, ds_bwx1, ds_bwx2))//
        .indexMatcher("write", limitedTo(ds_bw1, ds_bw2, ds_bwx1, ds_bwx2))//
        .indexMatcher("create_data_stream", limitedToNone())//
        .indexMatcher("manage_data_stream", limitedToNone());

    /**
     * A simple user that can read from ds_b* and write to ds_bw*; they can also create data streams with the name ds_bw*
     */
    static TestSecurityConfig.User LIMITED_USER_B_CREATE_DS = new TestSecurityConfig.User("limited_user_B_create_ds")//
        .description("ds_b* with create ds privs")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "indices_monitor")
                .on("ds_b*")//
                .indexPermissions("write")
                .on("ds_bw*")//
                .indexPermissions("indices:admin/data_stream/create")
                .on("ds_bw*")
        )//
        .indexMatcher("read", limitedTo(ds_br1, ds_br2, ds_bw1, ds_bw2, ds_bwx1, ds_bwx2))//
        .indexMatcher("write", limitedTo(ds_bw1, ds_bw2, ds_bwx1, ds_bwx2))//
        .indexMatcher("create_data_stream", limitedTo(ds_bw1, ds_bw2, ds_bwx1, ds_bwx2))//
        .indexMatcher("manage_data_stream", limitedToNone());

    /**
     * A simple user that can read from ds_b* and write to ds_bw*; they can also create and manage data streams with the name ds_bw*
     */
    static TestSecurityConfig.User LIMITED_USER_B_MANAGE_DS = new TestSecurityConfig.User("limited_user_B_manage_ds")//
        .description("ds_b* with manage privs")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "indices_monitor")
                .on("ds_b*")//
                .indexPermissions("write")
                .on("ds_bw*")//
                .indexPermissions("manage")
                .on("ds_bw*")
        )//
        .indexMatcher("read", limitedTo(ds_br1, ds_br2, ds_bw1, ds_bw2, ds_bwx1, ds_bwx2))//
        .indexMatcher("write", limitedTo(ds_bw1, ds_bw2, ds_bwx1, ds_bwx2))//
        .indexMatcher("create_data_stream", limitedTo(ds_bw1, ds_bw2, ds_bwx1, ds_bwx2))//
        .indexMatcher("manage_data_stream", limitedTo(ds_bw1, ds_bw2, ds_bwx1, ds_bwx2));

    /**
     * A user that can read from ds_a* and ds_b* and write/create/manage ds_aw*, ds_bw*
     */
    static TestSecurityConfig.User LIMITED_USER_AB_MANAGE_INDEX = new TestSecurityConfig.User("limited_user_AB_manage_index")//
        .description("ds_a*, ds_b* with manage index privs")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "indices_monitor")
                .on("ds_a*", "ds_b*")//
                .indexPermissions("write")
                .on("ds_aw*", "ds_bw*")//
                .indexPermissions("manage")
                .on("ds_aw*", "ds_bw*")
        )//
        .indexMatcher("read", limitedTo(ds_ar1, ds_ar2, ds_aw1, ds_aw2, ds_br1, ds_br2, ds_bw1, ds_bw2, ds_bwx1, ds_bwx2))//
        .indexMatcher("write", limitedTo(ds_aw1, ds_aw2, ds_bw1, ds_bw2, ds_bwx1, ds_bwx2))//
        .indexMatcher("create_data_stream", limitedTo(ds_aw1, ds_aw2, ds_bw1, ds_bw2, ds_bwx1, ds_bwx2))//
        .indexMatcher("manage_data_stream", limitedTo(ds_aw1, ds_aw2, ds_bw1, ds_bw2, ds_bwx1, ds_bwx2));

    /**
     * A simple user that can read from index_c*
     */
    static TestSecurityConfig.User LIMITED_USER_C = new TestSecurityConfig.User("limited_user_C")//
        .description("index_c*")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "indices_monitor")
                .on("index_c*")//
                .indexPermissions("write")
                .on("index_cw*")
        )//
        .indexMatcher("read", limitedTo(index_cr1, index_cw1))//
        .indexMatcher("write", limitedTo(index_cw1))//
        .indexMatcher("create_data_stream", limitedToNone())//
        .indexMatcher("manage_data_stream", limitedToNone());

    /**
     * A simple user that can read all indices and data streams, but cannot write anything
     */
    static TestSecurityConfig.User LIMITED_READ_ONLY_ALL = new TestSecurityConfig.User("limited_read_only_all")//
        .description("read/only on *")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read")
                .on("*")
        )//
        .indexMatcher("read", unlimited())//
        .indexMatcher("write", limitedToNone())//
        .indexMatcher("create_data_stream", limitedToNone())//
        .indexMatcher("manage_data_stream", limitedToNone());

    /**
     * A simple user that can read from ds_a*, but cannot write anything
     */
    static TestSecurityConfig.User LIMITED_READ_ONLY_A = new TestSecurityConfig.User("limited_read_only_A")//
        .description("read/only on ds_a*")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read")
                .on("ds_a*")
        )//
        .indexMatcher("read", limitedTo(ds_ar1, ds_ar2, ds_aw1, ds_aw2))//
        .indexMatcher("write", limitedToNone())//
        .indexMatcher("create_data_stream", limitedToNone())//
        .indexMatcher("manage_data_stream", limitedToNone());

    /**
     * A simple test user that only has index privileges for indices that are not used by this test.
     */
    static TestSecurityConfig.User LIMITED_USER_OTHER_PRIVILEGES = new TestSecurityConfig.User("limited_user_other_privileges")//
        .description("no privileges for existing indices")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("crud", "indices_monitor")
                .on("ds_does_not_exist_*")
        )//
        .indexMatcher("read", limitedToNone())//
        .indexMatcher("write", limitedToNone())//
        .indexMatcher("create_data_stream", limitedToNone())//
        .indexMatcher("manage_data_stream", limitedToNone());

    /**
     * A simple test user that has no index privileges at all.
     */
    static final TestSecurityConfig.User LIMITED_USER_NONE = new TestSecurityConfig.User("limited_user_none")//
        .description("no index privileges")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
        )//
        .indexMatcher("read", limitedToNone())//
        .indexMatcher("write", limitedToNone())//
        .indexMatcher("create_data_stream", limitedToNone())//
        .indexMatcher("manage_data_stream", limitedToNone());

    /**
     * This user has only privileges on backing indices for data streams, but not on the data streams themselves
     */
    static TestSecurityConfig.User LIMITED_USER_PERMISSIONS_ON_BACKING_INDICES = new TestSecurityConfig.User(
        "limited_user_permissions_on_backing_indices"
    )//
        .description("ds_a* on backing indices")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "indices_monitor")
                .on(".ds-ds_a*")//
                .indexPermissions("write")
                .on(".ds-ds_aw*")
        )//
        .indexMatcher("read", limitedTo(ds_ar1, ds_ar2, ds_aw1, ds_aw2))//
        .indexMatcher("write", limitedTo(ds_aw1, ds_aw2))//
        .indexMatcher("create_data_stream", limitedToNone())//
        .indexMatcher("manage_data_stream", limitedToNone());

    /**
     * A user with "*" privileges on "*"; as it is a regular user, they are still subject to system index
     * restrictions and similar things.
     */
    static TestSecurityConfig.User UNLIMITED_USER = new TestSecurityConfig.User("unlimited_user")//
        .description("unlimited")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("*")
                .on("*")
        )//
        .indexMatcher("read", unlimited())//
        .indexMatcher("write", unlimited())//
        .indexMatcher("create_data_stream", unlimited())//
        .indexMatcher("manage_data_stream", unlimited());

    /**
     * The SUPER_UNLIMITED_USER authenticates with an admin cert, which will cause all access control code to be skipped.
     * This serves as a base for comparison with the default behavior.
     */
    static TestSecurityConfig.User SUPER_UNLIMITED_USER = new TestSecurityConfig.User("super_unlimited_user")//
        .description("super unlimited (admin cert)")//
        .adminCertUser()//
        .indexMatcher("read", unlimitedIncludingOpenSearchSecurityIndex())//
        .indexMatcher("write", unlimitedIncludingOpenSearchSecurityIndex())//
        .indexMatcher("create_data_stream", unlimitedIncludingOpenSearchSecurityIndex())//
        .indexMatcher("manage_data_stream", unlimitedIncludingOpenSearchSecurityIndex());

    static List<TestSecurityConfig.User> USERS = ImmutableList.of(
        LIMITED_USER_A,
        LIMITED_USER_B,
        LIMITED_USER_B_READ_ONLY_A,
        LIMITED_USER_B_AUTO_PUT_ON_ALL,
        LIMITED_USER_B_CREATE_DS,
        LIMITED_USER_B_MANAGE_DS,
        LIMITED_USER_AB_MANAGE_INDEX,
        LIMITED_USER_C,
        LIMITED_READ_ONLY_ALL,
        LIMITED_READ_ONLY_A,
        LIMITED_USER_OTHER_PRIVILEGES,
        LIMITED_USER_NONE,
        LIMITED_USER_PERMISSIONS_ON_BACKING_INDICES,
        UNLIMITED_USER,
        SUPER_UNLIMITED_USER
    );

    static LocalCluster.Builder clusterBuilder() {
        return new LocalCluster.Builder().singleNode()
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(USERS)//
            .indexTemplates(new TestIndexTemplate("ds_test", "ds_*").dataStream().composedOf(TestComponentTemplate.DATA_STREAM_MINIMAL))//
            .indices(index_cr1, index_cw1)//
            .dataStreams(ds_ar1, ds_ar2, ds_aw1, ds_aw2, ds_br1, ds_br2, ds_bw1, ds_bw2, ds_hidden)//
            .plugin(IndexAuthorizationReadOnlyIntTests.SystemIndexTestPlugin.class);
    }

    @AfterClass
    public static void stopClusters() {
        for (ClusterConfig clusterConfig : ClusterConfig.values()) {
            clusterConfig.shutdown();
        }
    }

    final TestSecurityConfig.User user;
    final LocalCluster cluster;
    final ClusterConfig clusterConfig;

    @Test
    public void createDocument() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            HttpResponse httpResponse = restClient.post("ds_bw1/_doc/", json("a", 1, "@timestamp", Instant.now().toString()));
            assertThat(httpResponse, containsExactly(ds_bw1).at("_index").reducedBy(user.indexMatcher("write")).whenEmpty(isForbidden()));
        }
    }

    @Test
    public void deleteByQuery_indexPattern() throws Exception {
        String testName = "deleteByQuery_indexPattern";

        try (TestRestClient restClient = cluster.getRestClient(user)) {
            try (TestRestClient adminRestClient = cluster.getAdminCertRestClient()) {
                // Init test data
                HttpResponse httpResponse = adminRestClient.put(
                    "ds_bw1/_create/put_delete_delete_by_query_b1?refresh=true",
                    json("test", testName, "delete_by_query_test_delete", "yes", "@timestamp", Instant.now().toString())
                );
                assertThat(httpResponse, isCreated());
                httpResponse = adminRestClient.put(
                    "ds_bw1/_create/put_delete_delete_by_query_b2?refresh=true",
                    json("test", testName, "delete_by_query_test_delete", "no", "@timestamp", Instant.now().toString())
                );
                assertThat(httpResponse, isCreated());
                httpResponse = adminRestClient.put(
                    "ds_aw1/_create/put_delete_delete_by_query_a1?refresh=true",
                    json("test", testName, "delete_by_query_test_delete", "yes", "@timestamp", Instant.now().toString())
                );
                assertThat(httpResponse, isCreated());
                httpResponse = adminRestClient.put(
                    "ds_aw1/_create/put_delete_delete_by_query_a2?refresh=true",
                    json("test", testName, "delete_by_query_test_delete", "no", "@timestamp", Instant.now().toString())
                );
                assertThat(httpResponse, isCreated());
            }

            HttpResponse httpResponse = restClient.postJson("ds_aw*,ds_bw*/_delete_by_query?wait_for_completion=true", """
                {
                  "query": {
                    "term": {
                      "delete_by_query_test_delete": "yes"
                    }
                  }
                }
                """);

            if (clusterConfig.legacyPrivilegeEvaluation) {
                // dnfof is not applicable to indices:data/write/delete/byquery, so we need privileges for all indices
                if (user.indexMatcher("write").coversAll(ds_aw1, ds_aw2, ds_bw1, ds_bw2)) {
                    assertThat(httpResponse, isOk());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            } else {
                if (user != LIMITED_USER_NONE && user != LIMITED_READ_ONLY_ALL && user != LIMITED_READ_ONLY_A) {
                    assertThat(httpResponse, isOk());
                    int expectedDeleteCount = containsExactly(ds_aw1, ds_bw1).at("_index").reducedBy(user.indexMatcher("write")).size();
                    assertEquals(httpResponse.getBody(), expectedDeleteCount, httpResponse.bodyAsMap().get("deleted"));
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            }
        } finally {
            deleteTestDocs(testName, "ds_aw*,ds_bw*");
        }
    }

    @Test
    public void putDocument_bulk() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            HttpResponse httpResponse = restClient.putJson("_bulk", """
                { "create": { "_index": "ds_aw1", "_id": "d1" } }
                { "a": 1, "test": "putDocument_bulk", "@timestamp": "2025-09-15T12:00:00Z" }
                { "create": { "_index": "ds_bw1", "_id": "d1" } }
                { "b": 1, "test": "putDocument_bulk", "@timestamp": "2025-09-15T12:00:01Z" }
                """);

            if (user == LIMITED_USER_PERMISSIONS_ON_BACKING_INDICES) {
                // IndexResolverReplacer won't resolve data stream names to member index names, because it does not
                // specify the includeDataStream option and thus just stumbles over an IndexNotFoundException
                // Thus, in contrast to aliases, privileges on backing index names won't work
                assertThat(httpResponse, isOk());
                assertThat(httpResponse, containsExactly().at("items[*].create[?(@.result == 'created')]._index"));
            } else if (user != LIMITED_USER_NONE) {
                assertThat(
                    httpResponse,
                    containsExactly(ds_aw1, ds_bw1).at("items[*].create[?(@.result == 'created')]._index")
                        .reducedBy(user.indexMatcher("write"))
                        .whenEmpty(isOk())
                );
            } else {
                assertThat(httpResponse, isForbidden());
            }
        } finally {
            deleteTestDocs("putDocument_bulk", "ds_aw*,ds_bw*");
        }
    }

    @Test
    public void createDataStream() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            HttpResponse httpResponse = restClient.put("_data_stream/ds_bwx1");

            if (containsExactly(ds_bwx1).reducedBy(user.indexMatcher("create_data_stream")).isEmpty()) {
                assertThat(httpResponse, isForbidden());
            } else {
                assertThat(httpResponse, isOk());
            }
        } finally {
            delete(ds_bwx1);
        }
    }

    @Test
    public void putDataStream() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            HttpResponse httpResponse = restClient.putJson("ds_bwx1/", "{}");

            if (user == UNLIMITED_USER
                || user == SUPER_UNLIMITED_USER
                || user == LIMITED_USER_B_MANAGE_DS
                || user == LIMITED_USER_AB_MANAGE_INDEX) {
                // This will fail because we try to create an index under a name of a data stream
                assertThat(httpResponse, isBadRequest());
            } else {
                assertThat(httpResponse, isForbidden());
            }
        } finally {
            delete(ds_bwx1);
        }
    }

    @Test
    public void deleteDataStream() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            createInitialTestObjects(ds_bwx1);

            HttpResponse httpResponse = restClient.delete("_data_stream/ds_bwx1");

            if (user.indexMatcher("manage_data_stream").isEmpty()) {
                assertThat(httpResponse, isForbidden());
            } else {
                assertThat(httpResponse, isOk());
            }
        } finally {
            delete(ds_bwx1);
        }
    }

    @After
    public void refresh() {
        cluster.getInternalNodeClient().admin().indices().refresh(new RefreshRequest("*")).actionGet();
    }

    @ParametersFactory(shuffle = false, argumentFormatting = "%1$s, %3$s")
    public static Collection<Object[]> params() {
        List<Object[]> result = new ArrayList<>();

        for (ClusterConfig clusterConfig : ClusterConfig.values()) {
            for (TestSecurityConfig.User user : USERS) {
                result.add(new Object[] { clusterConfig, user, user.getDescription() });
            }
        }
        return result;
    }

    public DataStreamAuthorizationReadWriteIntTests(ClusterConfig clusterConfig, TestSecurityConfig.User user, String description)
        throws Exception {
        this.user = user;
        this.cluster = clusterConfig.cluster(DataStreamAuthorizationReadWriteIntTests::clusterBuilder);
        this.clusterConfig = clusterConfig;
    }

    private void createInitialTestObjects(TestIndexOrAliasOrDatastream... testIndexOrAliasOrDatastreamArray) {
        TestIndexOrAliasOrDatastream.createInitialTestObjects(cluster, testIndexOrAliasOrDatastreamArray);
    }

    private void delete(TestIndexOrAliasOrDatastream... testIndexOrAliasOrDatastreamArray) {
        TestIndexOrAliasOrDatastream.delete(cluster, testIndexOrAliasOrDatastreamArray);
    }

    private void deleteTestDocs(String testName, String indices) {
        try (TestRestClient adminRestClient = cluster.getAdminCertRestClient()) {
            adminRestClient.post(indices + "/_refresh");
            adminRestClient.postJson(indices + "/_delete_by_query?refresh=true&wait_for_completion=true", """
                {
                  "query": {
                    "term": {
                      "test.keyword": "%s"
                    }
                  }
                }
                """.formatted(testName));
        } catch (Exception e) {
            throw new RuntimeException("Error while cleaning up test docs", e);
        }
    }

}
