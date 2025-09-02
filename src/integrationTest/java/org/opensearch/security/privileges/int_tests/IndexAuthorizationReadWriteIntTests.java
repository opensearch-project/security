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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import javax.annotation.concurrent.NotThreadSafe;

import com.carrotsearch.randomizedtesting.annotations.ParametersFactory;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.google.common.collect.ImmutableList;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.indices.open.OpenIndexRequest;
import org.opensearch.action.admin.indices.refresh.RefreshRequest;
import org.opensearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.framework.data.TestAlias;
import org.opensearch.test.framework.data.TestIndex;
import org.opensearch.test.framework.data.TestIndexOrAliasOrDatastream;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;
import org.opensearch.test.framework.data.TestAlias;
import org.opensearch.test.framework.data.TestIndex;
import org.opensearch.test.framework.data.TestIndexOrAliasOrDatastream;
import org.opensearch.test.framework.matcher.RestIndexMatchers;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.cluster.TestRestClient.json;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnResponseIndexMatcher.containsExactly;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnUserIndexMatcher.limitedTo;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnUserIndexMatcher.limitedToNone;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnUserIndexMatcher.unlimited;
import static org.opensearch.test.framework.matcher.RestIndexMatchers.OnUserIndexMatcher.unlimitedIncludingOpenSearchSecurityIndex;
import static org.opensearch.test.framework.matcher.RestMatchers.isBadRequest;
import static org.opensearch.test.framework.matcher.RestMatchers.isCreated;
import static org.opensearch.test.framework.matcher.RestMatchers.isForbidden;
import static org.opensearch.test.framework.matcher.RestMatchers.isNotFound;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;
import static org.junit.Assert.assertEquals;

/**
 * This class defines a huge test matrix for index related access controls. This class is especially for read/write operations on indices and aliases.
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
public class IndexAuthorizationReadWriteIntTests {

    // -------------------------------------------------------------------------------------------------------
    // Test indices used by this test suite. We use the following naming scheme:
    // - index_*r*: This test will not write to this index
    // - index_*w*: This test can write to this index; the test won't delete and recreate it
    // - index_*wx*: The index is not initially created; the test can create it on demand and delete it again
    // -------------------------------------------------------------------------------------------------------

    static final TestIndex index_ar1 = TestIndex.name("index_ar1").documentCount(10).build();
    static final TestIndex index_ar2 = TestIndex.name("index_ar2").documentCount(10).build();
    static final TestIndex index_aw1 = TestIndex.name("index_aw1").documentCount(10).build();
    static final TestIndex index_aw2 = TestIndex.name("index_aw2").documentCount(10).build();
    static final TestIndex index_br1 = TestIndex.name("index_br1").documentCount(10).build();
    static final TestIndex index_br2 = TestIndex.name("index_br2").documentCount(10).build();
    static final TestIndex index_bw1 = TestIndex.name("index_bw1").documentCount(10).build();
    static final TestIndex index_bw2 = TestIndex.name("index_bw2").documentCount(10).build();
    static final TestIndex index_cr1 = TestIndex.name("index_cr1").documentCount(10).build();
    static final TestIndex index_cw1 = TestIndex.name("index_cw1").documentCount(10).build();
    static final TestIndex index_hidden = TestIndex.name("index_hidden").hidden().documentCount(1).seed(8).build();
    static final TestIndex system_index_plugin = TestIndex.name(".system_index_plugin").hidden().documentCount(1).seed(8).build();
    static final TestIndex system_index_plugin_not_existing = TestIndex.name(".system_index_plugin_not_existing")
        .hidden()
        .documentCount(0)
        .build(); // not initially created

    static final TestAlias alias_ab1r = new TestAlias("alias_ab1r").on(index_ar1, index_ar2, index_aw1, index_aw2, index_br1, index_bw1);
    static final TestAlias alias_ab1w = new TestAlias("alias_ab1w").on(index_aw1, index_aw2, index_bw1).writeIndex(index_aw1);
    static final TestAlias alias_ab1w_nowriteindex = new TestAlias("alias_ab1w_nowriteindex").on(index_aw1, index_aw2, index_bw1);

    static final TestAlias alias_c1 = new TestAlias("alias_c1", index_cr1, index_cw1);

    static final TestIndex index_bwx1 = TestIndex.name("index_bwx1").documentCount(0).build(); // not initially created
    static final TestIndex index_bwx2 = TestIndex.name("index_bwx2").documentCount(0).build(); // not initially created

    static final TestAlias alias_bwx = new TestAlias("alias_bwx"); // not initially created

    static final List<TestIndexOrAliasOrDatastream> ALL_NON_HIDDEN_INDICES = List.of(
        index_ar1,
        index_ar2,
        index_aw1,
        index_aw2,
        index_br1,
        index_br2,
        index_bw1,
        index_bw2,
        index_cr1,
        index_cw1
    );

    static final List<TestIndexOrAliasOrDatastream> ALL_INDICES_AND_ALIASES_EXCEPT_SYSTEM_INDICES = List.of(
        index_ar1,
        index_ar2,
        index_aw1,
        index_aw2,
        index_br1,
        index_br2,
        index_bw1,
        index_bw2,
        index_cr1,
        index_cw1,
        alias_ab1w,
        alias_ab1r,
        alias_c1,
        alias_ab1w_nowriteindex,
        index_hidden
    );

    /**
     * This key identifies assertion reference data for index search/read permissions of individual users.
     */
    static final TestSecurityConfig.User.MetadataKey<RestIndexMatchers.IndexMatcher> READ = new TestSecurityConfig.User.MetadataKey<>(
        "read",
        RestIndexMatchers.IndexMatcher.class
    );

    /**
     * This key identifies assertion reference data for index write permissions of individual users. This does
     * not include index creation permissions.
     */
    static final TestSecurityConfig.User.MetadataKey<RestIndexMatchers.IndexMatcher> WRITE = new TestSecurityConfig.User.MetadataKey<>(
        "write",
        RestIndexMatchers.IndexMatcher.class
    );

    /**
     * This key identifies assertion reference data for create index permissions of individual users.
     */
    static final TestSecurityConfig.User.MetadataKey<RestIndexMatchers.IndexMatcher> CREATE_INDEX =
        new TestSecurityConfig.User.MetadataKey<>("create_index", RestIndexMatchers.IndexMatcher.class);

    /**
     * This key identifies assertion reference data for manage index permissions of individual users.
     */
    static final TestSecurityConfig.User.MetadataKey<RestIndexMatchers.IndexMatcher> MANAGE_INDEX =
        new TestSecurityConfig.User.MetadataKey<>("manage_index", RestIndexMatchers.IndexMatcher.class);

    /**
     * This key identifies assertion reference data for alias management permissions of individual users.
     */
    static final TestSecurityConfig.User.MetadataKey<RestIndexMatchers.IndexMatcher> MANAGE_ALIAS =
        new TestSecurityConfig.User.MetadataKey<>("manage_alias", RestIndexMatchers.IndexMatcher.class);

    // -------------------------------------------------------------------------------------------------------
    // Test users with which the tests will be executed; the users need to be added to the list USERS below
    // The users have two redundant versions or privilege configuration, which needs to be kept in sync:
    // - The standard role configuration defined with .roles()
    // - IndexMatchers which act as test oracles, defined with the indexMatcher() methods
    // -------------------------------------------------------------------------------------------------------

    /**
     * A simple user that can read from index_a* and write to index_aw*; the user as no privileges to create or manage indices
     */
    static TestSecurityConfig.User LIMITED_USER_A = new TestSecurityConfig.User("limited_user_A")//
        .description("index_a*")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "indices_monitor")
                .on("index_a*")//
                .indexPermissions("write")
                .on("index_aw*")
        )//
        .reference(READ, limitedTo(index_ar1, index_ar2, index_aw1, index_aw2))//
        .reference(WRITE, limitedTo(index_aw1, index_aw2))//
        .reference(CREATE_INDEX, limitedToNone())//
        .reference(MANAGE_INDEX, limitedToNone())//
        .reference(MANAGE_ALIAS, limitedToNone());

    /**
     * A simple user that can read from index_b* and write to index_bw*; the user as no privileges to create or manage indices
     */
    static TestSecurityConfig.User LIMITED_USER_B = new TestSecurityConfig.User("limited_user_B")//
        .description("index_b*")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "indices_monitor")
                .on("index_b*")//
                .indexPermissions("write")
                .on("index_bw*")
        )//
        .reference(READ, limitedTo(index_br1, index_br2, index_bw1, index_bw2, index_bwx1, index_bwx2))//
        .reference(WRITE, limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2))//
        .reference(CREATE_INDEX, limitedToNone())//
        .reference(MANAGE_INDEX, limitedToNone())//
        .reference(MANAGE_ALIAS, limitedToNone());

    /**
     * A simple user that can read from index_b* and write to index_bw*; additionally, they can create index_bw* indices
     */
    static TestSecurityConfig.User LIMITED_USER_B_CREATE_INDEX = new TestSecurityConfig.User("limited_user_B_create_index")//
        .description("index_b* with create index privs")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "indices_monitor")
                .on("index_b*")//
                .indexPermissions("write")
                .on("index_bw*")//
                .indexPermissions("create_index")
                .on("index_bw*")
        )//
        .reference(READ, limitedTo(index_br1, index_br2, index_bw1, index_bw2, index_bwx1, index_bwx2))//
        .reference(WRITE, limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2))//
        .reference(CREATE_INDEX, limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2))//
        .reference(MANAGE_INDEX, limitedToNone())//
        .reference(MANAGE_ALIAS, limitedToNone());

    /**
     * A simple user that can read from index_b* and write to index_bw*; additionally, they can create and manage index_bw* indices
     */
    static TestSecurityConfig.User LIMITED_USER_B_MANAGE_INDEX = new TestSecurityConfig.User("limited_user_B_manage_index")//
        .description("index_b* with manage privs")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "indices_monitor")
                .on("index_b*")//
                .indexPermissions("write")
                .on("index_bw*")//
                .indexPermissions("manage")
                .on("index_bw*")
        )//
        .reference(READ, limitedTo(index_br1, index_br2, index_bw1, index_bw2, index_bwx1, index_bwx2))//
        .reference(WRITE, limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2))//
        .reference(CREATE_INDEX, limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2))//
        .reference(MANAGE_INDEX, limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2))//
        .reference(MANAGE_ALIAS, limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2));

    /**
     * A user that can read from index_b* and write to index_bw*; they can create and manage index_bw* indices and manage alias_bwx* aliases.
     * For users with such alias permissions, keep in mind that alias permissions are inherited by the member indices.
     * Thus, indices can gain or lose privileges when they are added/removed from the alias.
     */
    static TestSecurityConfig.User LIMITED_USER_B_MANAGE_INDEX_ALIAS = new TestSecurityConfig.User("limited_user_B_manage_index_alias")//
        .description("index_b*, alias_bwx* with manage privs")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "indices_monitor")
                .on("index_b*")//
                .indexPermissions("write")
                .on("index_bw*")//
                .indexPermissions("manage")
                .on("index_bw*")//
                .indexPermissions("crud", "manage", "manage_aliases")
                .on("alias_bwx*")
        )//
        .reference(READ, limitedTo(index_br1, index_br2, index_bw1, index_bw2, index_bwx1, index_bwx2))//
        .reference(WRITE, limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2))//
        .reference(CREATE_INDEX, limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2))//
        .reference(MANAGE_INDEX, limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2, alias_bwx))//
        .reference(MANAGE_ALIAS, limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2, alias_bwx));

    /**
     * This user differs from LIMITED_USER_B_MANAGE_INDEX_ALIAS the way that it does not give any direct
     * write privileges to index_bw*; rather, it gives write privileges to alias_bxw. Any index which happens
     * to be member of that alias then gains these write privileges.
     */
    static TestSecurityConfig.User LIMITED_USER_B_READ_ONLY_MANAGE_INDEX_ALIAS = new TestSecurityConfig.User(
        "limited_user_B_index_read_only_manage_index_alias"
    )//
        .description("index_b* r/o, alias_bwx* r/w with manage privs")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "indices_monitor")
                .on("index_b*")//
                .indexPermissions("crud", "manage", "manage_aliases")
                .on("alias_bwx*")
        )//
        .reference(READ, limitedTo(index_br1, index_br2))//
        .reference(WRITE, limitedToNone())//
        .reference(CREATE_INDEX, limitedToNone())//
        .reference(MANAGE_INDEX, limitedTo(alias_bwx))//
        .reference(MANAGE_ALIAS, limitedTo(alias_bwx));

    /**
     * Same as LIMITED_USER_B_MANAGE_INDEX_ALIAS with the addition of read/write/manage privileges on index_hidden*
     */
    static TestSecurityConfig.User LIMITED_USER_B_HIDDEN_MANAGE_INDEX_ALIAS = new TestSecurityConfig.User(
        "limited_user_B_hidden_manage_index_alias"
    )//
        .description("index_b*, index_hidden*, alias_bwx* with manage privs, index_a* read only")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "indices_monitor")
                .on("index_a*", "index_b*", "index_hidden*")//
                .indexPermissions("write")
                .on("index_bw*", "index_hidden*")//
                .indexPermissions("manage")
                .on("index_bw*", "index_hidden*")//
                .indexPermissions("crud", "manage", "manage_aliases")
                .on("alias_bwx*")
        )//
        .reference(
            READ,
            limitedTo(
                index_ar1,
                index_ar2,
                index_aw1,
                index_aw2,
                index_br1,
                index_br2,
                index_bw1,
                index_bw2,
                index_bwx1,
                index_bwx2,
                index_hidden
            )
        )//
        .reference(WRITE, limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2, index_hidden))//
        .reference(CREATE_INDEX, limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2, index_hidden))//
        .reference(MANAGE_INDEX, limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2, alias_bwx, index_hidden))//
        .reference(MANAGE_ALIAS, limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2, alias_bwx, index_hidden));

    /**
     * Same as LIMITED_USER_B with the addition of read/write/manage privileges for ".system_index_plugin", ".system_index_plugin_*"
     * including the explicit "system:admin/system_index" privilege.
     */
    static TestSecurityConfig.User LIMITED_USER_B_SYSTEM_INDEX_MANAGE = new TestSecurityConfig.User("limited_user_B_system_index_manage")//
        .description("index_b*, .system_index_plugin with manage privs")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "indices_monitor", "system:admin/system_index")
                .on("index_b*", "index_hidden*", ".system_index_plugin")//
                .indexPermissions("write", "system:admin/system_index")
                .on("index_bw*", ".system_index_plugin", ".system_index_plugin_*")//
                .indexPermissions("manage", "system:admin/system_index")
                .on("index_bw*", ".system_index_plugin", ".system_index_plugin_*")
        )//
        .reference(
            READ,
            limitedTo(
                index_br1,
                index_br2,
                index_bw1,
                index_bw2,
                index_bwx1,
                index_bwx2,
                system_index_plugin,
                system_index_plugin_not_existing
            )
        )//
        .reference(WRITE, limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2, system_index_plugin, system_index_plugin_not_existing))//
        .reference(
            CREATE_INDEX,
            limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2, system_index_plugin, system_index_plugin_not_existing)
        )//
        .reference(
            MANAGE_INDEX,
            limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2, system_index_plugin, system_index_plugin_not_existing)
        )//
        .reference(
            MANAGE_ALIAS,
            limitedTo(index_bw1, index_bw2, index_bwx1, index_bwx2, system_index_plugin, system_index_plugin_not_existing)
        );

    /**
     * A simple test user that has read privileges on alias_ab1r and write privileges on alias_ab1w*. The user
     * has no direct privileges on indices; all privileges are gained via the aliases.
     */
    static TestSecurityConfig.User LIMITED_USER_AB1_ALIAS = new TestSecurityConfig.User("limited_user_alias_AB1")//
        .description("alias_ab1")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "indices_monitor", "indices:admin/aliases/get")
                .on("alias_ab1r")//
                .indexPermissions("read", "indices_monitor", "indices:admin/aliases/get", "write")
                .on("alias_ab1w*")
        )//
        .reference(
            READ,
            limitedTo(index_ar1, index_ar2, index_aw1, index_aw2, index_br1, index_bw1, alias_ab1r, alias_ab1w, alias_ab1w_nowriteindex)
        )//
        .reference(WRITE, limitedTo(index_aw1, index_aw2, index_bw1, alias_ab1w, alias_ab1w_nowriteindex))//
        .reference(CREATE_INDEX, limitedTo(index_aw1, index_aw2, index_bw1))//
        .reference(MANAGE_INDEX, limitedToNone())//
        .reference(MANAGE_ALIAS, limitedToNone());
    /**
     * A simple test user that has read/only privileges on alias_ab1r and alias_ab1w*. However, they have write
     * privileges for the member index index_aw1.
     */
    static TestSecurityConfig.User LIMITED_USER_AB1_ALIAS_READ_ONLY = new TestSecurityConfig.User("limited_user_alias_AB1_read_only")//
        .description("read/only on alias_ab1w, but with write privs in write index index_aw1")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read", "write", "indices:admin/refresh")
                .on("index_aw1")//
                .indexPermissions("read")
                .on("alias_ab1w")
        )//
        .reference(READ, limitedTo(index_aw1, index_aw2, index_bw1, alias_ab1w))//
        .reference(WRITE, limitedTo(index_aw1))//
        .reference(CREATE_INDEX, limitedToNone())//
        .reference(MANAGE_INDEX, limitedToNone())//
        .reference(MANAGE_ALIAS, limitedToNone());

    /**
     * A simple test user which has read/only privileges for "*"
     */
    static TestSecurityConfig.User LIMITED_READ_ONLY_ALL = new TestSecurityConfig.User("limited_read_only_all")//
        .description("read/only on *")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read")
                .on("*")
        )//
        .reference(READ, unlimited())//
        .reference(WRITE, limitedToNone())//
        .reference(CREATE_INDEX, limitedToNone())//
        .reference(MANAGE_INDEX, limitedToNone())//
        .reference(MANAGE_ALIAS, limitedToNone());

    /**
     * A simple test user which has read/only privileges for "index_a*"
     */
    static TestSecurityConfig.User LIMITED_READ_ONLY_A = new TestSecurityConfig.User("limited_read_only_A")//
        .description("read/only on index_a*")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("read")
                .on("index_a*")
        )//
        .reference(READ, limitedTo(index_ar1, index_ar2, index_aw1, index_aw2))//
        .reference(WRITE, limitedToNone())//
        .reference(CREATE_INDEX, limitedToNone())//
        .reference(MANAGE_INDEX, limitedToNone())//
        .reference(MANAGE_ALIAS, limitedToNone());

    /**
     * A simple test user that only has index privileges for indices that are not used by this test.
     */
    static TestSecurityConfig.User LIMITED_USER_OTHER_PRIVILEGES = new TestSecurityConfig.User("limited_user_other_privileges")//
        .description("no privileges for existing indices")//
        .roles(
            new Role("r1")//
                .clusterPermissions("cluster_composite_ops", "cluster_monitor")//
                .indexPermissions("crud", "indices_monitor")
                .on("index_does_not_exist_*")
        )//
        .reference(READ, limitedToNone())//
        .reference(WRITE, limitedToNone())//
        .reference(CREATE_INDEX, limitedToNone())//
        .reference(MANAGE_INDEX, limitedToNone())//
        .reference(MANAGE_ALIAS, limitedToNone());

    /**
     * A simple test user that has no index privileges at all.
     */
    static final TestSecurityConfig.User LIMITED_USER_NONE = new TestSecurityConfig.User("limited_user_none")//
        .description("no index privileges")//
        .roles(
            new TestSecurityConfig.Role("r1")//
                .clusterPermissions("cluster_composite_ops_ro", "cluster_monitor")
        )//
        .reference(READ, limitedToNone())//
        .reference(WRITE, limitedToNone())//
        .reference(CREATE_INDEX, limitedToNone())//
        .reference(MANAGE_INDEX, limitedToNone())//
        .reference(MANAGE_ALIAS, limitedToNone());

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
                .on("*")//
                .indexPermissions("*")
                .on("*")
        )//
        .reference(READ, limitedTo(ALL_INDICES_AND_ALIASES_EXCEPT_SYSTEM_INDICES).and(index_bwx1, index_bwx2, alias_bwx))//
        .reference(WRITE, limitedTo(ALL_INDICES_AND_ALIASES_EXCEPT_SYSTEM_INDICES).and(index_bwx1, index_bwx2, alias_bwx))//
        .reference(CREATE_INDEX, limitedTo(ALL_INDICES_AND_ALIASES_EXCEPT_SYSTEM_INDICES).and(index_bwx1, index_bwx2, alias_bwx))//
        .reference(MANAGE_INDEX, limitedTo(ALL_INDICES_AND_ALIASES_EXCEPT_SYSTEM_INDICES).and(index_bwx1, index_bwx2, alias_bwx))//
        .reference(MANAGE_ALIAS, limitedTo(ALL_INDICES_AND_ALIASES_EXCEPT_SYSTEM_INDICES).and(index_bwx1, index_bwx2, alias_bwx));

    /**
     * The SUPER_UNLIMITED_USER authenticates with an admin cert, which will cause all access control code to be skipped.
     * This serves as a base for comparison with the default behavior.
     */
    static TestSecurityConfig.User SUPER_UNLIMITED_USER = new TestSecurityConfig.User("super_unlimited_user")//
        .description("super unlimited (admin cert)")//
        .adminCertUser()//
        .reference(READ, unlimitedIncludingOpenSearchSecurityIndex())//
        .reference(WRITE, unlimitedIncludingOpenSearchSecurityIndex())//
        .reference(CREATE_INDEX, unlimitedIncludingOpenSearchSecurityIndex())//
        .reference(MANAGE_INDEX, unlimitedIncludingOpenSearchSecurityIndex())//
        .reference(MANAGE_ALIAS, unlimitedIncludingOpenSearchSecurityIndex());

    static List<TestSecurityConfig.User> USERS = ImmutableList.of(
        LIMITED_USER_A,
        LIMITED_USER_B,
        LIMITED_USER_B_CREATE_INDEX,
        LIMITED_USER_B_MANAGE_INDEX,
        LIMITED_USER_B_MANAGE_INDEX_ALIAS,
        LIMITED_USER_B_READ_ONLY_MANAGE_INDEX_ALIAS,
        LIMITED_USER_B_HIDDEN_MANAGE_INDEX_ALIAS,
        LIMITED_USER_B_SYSTEM_INDEX_MANAGE,
        LIMITED_USER_AB1_ALIAS,
        LIMITED_USER_AB1_ALIAS_READ_ONLY,
        LIMITED_READ_ONLY_ALL,
        LIMITED_READ_ONLY_A,
        LIMITED_USER_OTHER_PRIVILEGES,
        LIMITED_USER_NONE,
        UNLIMITED_USER,
        SUPER_UNLIMITED_USER
    );

    static LocalCluster.Builder clusterBuilder() {
        return new LocalCluster.Builder().singleNode()
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .users(USERS)//
            .indices(
                index_ar1,
                index_ar2,
                index_aw1,
                index_aw2,
                index_br1,
                index_br2,
                index_bw1,
                index_bw2,
                index_cr1,
                index_cw1,
                index_hidden,
                system_index_plugin
            )//
            .aliases(alias_ab1r, alias_ab1w, alias_ab1w_nowriteindex, alias_c1)//
            .nodeSettings(Map.of("action.destructive_requires_name", false))
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
    public void putDocument() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.put("index_bw1/_doc/put_test_1", json("a", 1));
            assertThat(httpResponse, containsExactly(index_bw1).at("_index").reducedBy(user.reference(WRITE)).whenEmpty(isForbidden()));
        } finally {
            delete("index_bw1/_doc/put_test_1");
        }
    }

    @Test
    public void putDocument_systemIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            TestRestClient.HttpResponse httpResponse = restClient.put(".system_index_plugin/_doc/put_test_1", json("a", 1));
            if (clusterConfig.systemIndexPrivilegeEnabled && user.reference(WRITE).covers(system_index_plugin)) {
                assertThat(httpResponse, isCreated());
            } else if (user == SUPER_UNLIMITED_USER) {
                assertThat(httpResponse, isCreated());
            } else {
                assertThat(httpResponse, isForbidden());
            }
        } finally {
            delete(".system_index_plugin/_doc/put_test_1");
        }
    }

    @Test
    public void deleteDocument() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user); TestRestClient adminRestClient = cluster.getAdminCertRestClient()) {

            // Initialization
            {
                HttpResponse httpResponse = adminRestClient.put("index_bw1/_doc/put_delete_test_1?refresh=true", json("a", 1));
                assertThat(httpResponse, isCreated());
            }

            HttpResponse httpResponse = restClient.delete("index_bw1/_doc/put_delete_test_1");
            assertThat(httpResponse, containsExactly(index_bw1).at("_index").reducedBy(user.reference(WRITE)).whenEmpty(isForbidden()));
        } finally {
            delete("index_bw1/_doc/put_delete_test_1");
        }
    }

    @Test
    public void deleteByQuery_indexPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user); TestRestClient adminRestClient = cluster.getAdminCertRestClient()) {

            HttpResponse httpResponse = adminRestClient.put(
                "index_bw1/_doc/put_delete_delete_by_query_b1?refresh=true",
                json("delete_by_query_test", "yes")
            );
            assertThat(httpResponse, isCreated());
            httpResponse = adminRestClient.put(
                "index_bw1/_doc/put_delete_delete_by_query_b2?refresh=true",
                json("delete_by_query_test", "no")
            );
            assertThat(httpResponse, isCreated());
            httpResponse = adminRestClient.put(
                "index_aw1/_doc/put_delete_delete_by_query_a1?refresh=true",
                json("delete_by_query_test", "yes")
            );
            assertThat(httpResponse, isCreated());
            httpResponse = adminRestClient.put(
                "index_aw1/_doc/put_delete_delete_by_query_a2?refresh=true",
                json("delete_by_query_test", "no")
            );
            assertThat(httpResponse, isCreated());

            httpResponse = restClient.postJson("index_aw*,index_bw*/_delete_by_query?wait_for_completion=true", """
                {
                  "query": {
                    "term": {
                      "delete_by_query_test": "yes"
                    }
                  }
                }""");

            if (clusterConfig.legacyPrivilegeEvaluation) {
                // dnfof is not applicable to indices:data/write/delete/byquery, so we need privileges for all indices
                if (user.reference(WRITE).coversAll(index_aw1, index_aw2, index_bw1, index_bw2)) {
                    assertThat(httpResponse, isOk());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            } else {
                if (user != LIMITED_USER_NONE && user != LIMITED_READ_ONLY_ALL && user != LIMITED_READ_ONLY_A) {
                    assertThat(httpResponse, isOk());
                    int expectedDeleteCount = containsExactly(index_aw1, index_bw1).at("_index").reducedBy(user.reference(WRITE)).size();
                    assertEquals(httpResponse.getBody(), expectedDeleteCount, httpResponse.bodyAsMap().get("deleted"));
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            }

        } finally {
            delete(
                "index_bw1/_doc/put_delete_delete_by_query_b1",
                "index_bw1/_doc/put_delete_delete_by_query_b2",
                "index_aw1/_doc/put_delete_delete_by_query_a1",
                "index_aw1/_doc/put_delete_delete_by_query_a2"
            );
        }
    }

    @Test
    public void putDocument_bulk() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            RestIndexMatchers.IndexMatcher writePrivileges = user.reference(WRITE);

            HttpResponse httpResponse = restClient.putJson("_bulk", """
                {"index": {"_index": "index_aw1", "_id": "new_doc_aw1"}}
                {"a": 1}
                {"index": {"_index": "index_bw1", "_id": "new_doc_bw1"}}
                {"a": 1}
                {"index": {"_index": "index_cw1", "_id": "new_doc_cw1"}}
                {"a": 1}
                """);
            if (user != LIMITED_USER_NONE) {
                assertThat(
                    httpResponse,
                    containsExactly(index_aw1, index_bw1, index_cw1).at("items[*].index[?(@.result == 'created')]._index")
                        .reducedBy(writePrivileges)
                        .whenEmpty(isOk())
                );
            } else {
                assertThat(httpResponse, isForbidden());
            }
        } finally {
            delete("index_aw1/_doc/new_doc_aw1", "index_bw1/_doc/new_doc_bw1", "index_cw1/_doc/new_doc_cw1");
        }
    }

    @Test
    public void putDocument_alias() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            HttpResponse httpResponse = restClient.put("alias_ab1w/_doc/put_doc_alias_test_1", json("a, 1"));
            if (clusterConfig.legacyPrivilegeEvaluation) {
                if (user.reference(WRITE).coversAll(index_aw1, index_aw2, index_bw1)) {
                    assertThat(httpResponse, isCreated());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            } else {
                if (user.reference(WRITE).coversAll(alias_ab1w)) {
                    assertThat(httpResponse, isCreated());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            }
        } finally {
            delete("alias_ab1w/_doc/put_doc_alias_test_1");
        }
    }

    @Test
    public void putDocument_alias_noWriteIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            HttpResponse httpResponse = restClient.put("alias_ab1w_nowriteindex/_doc/put_doc_alias_test_1", json("a, 1"));

            if (containsExactly(alias_ab1w_nowriteindex).reducedBy(user.reference(WRITE)).isEmpty()) {
                assertThat(httpResponse, isForbidden());
            } else {
                assertThat(httpResponse, isBadRequest());
            }
        }
    }

    @Test
    public void putDocument_bulk_alias() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            HttpResponse httpResponse = restClient.putJson("_bulk", """
                {"index": {"_index": "alias_ab1w", "_id": "put_doc_alias_bulk_test_1"}}
                {"a": 1}
                """);

            if (user != LIMITED_USER_NONE) {
                assertThat(
                    httpResponse,
                    containsExactly(index_aw1).at("items[*].index[?(@.result == 'created')]._index")
                        .reducedBy(user.reference(WRITE))
                        .whenEmpty(isOk())
                );
            } else {
                assertThat(httpResponse, isForbidden());
            }

        } finally {
            delete("index_aw1/_doc/put_doc_alias_bulk_test_1");
        }
    }

    @Test
    public void putDocument_noExistingIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            HttpResponse httpResponse = restClient.put("index_bwx1/_doc/put_doc_non_existing_index_test_1", json("a, 1"));
            assertThat(
                httpResponse,
                containsExactly(index_bwx1).at("_index").reducedBy(user.reference(CREATE_INDEX)).whenEmpty(isForbidden())
            );
        } finally {
            delete(index_bwx1);
        }
    }

    @Test
    public void createIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            HttpResponse httpResponse = restClient.putJson("index_bwx1", "{}");
            assertThat(
                httpResponse,
                containsExactly(index_bwx1).at("index").reducedBy(user.reference(CREATE_INDEX)).whenEmpty(isForbidden())
            );
        } finally {
            delete(index_bwx1);
        }
    }

    @Test
    public void createIndex_systemIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            HttpResponse httpResponse = restClient.putJson(".system_index_plugin_not_existing", "{}");

            if (clusterConfig.systemIndexPrivilegeEnabled && user.reference(CREATE_INDEX).covers(system_index_plugin_not_existing)) {
                assertThat(httpResponse, isOk());
            } else if (user == SUPER_UNLIMITED_USER
                || (clusterConfig == ClusterConfig.LEGACY_PRIVILEGES_EVALUATION
                    && (user == UNLIMITED_USER || user == LIMITED_USER_B_SYSTEM_INDEX_MANAGE))) {
                        assertThat(httpResponse, isOk());
                    } else {
                        assertThat(httpResponse, isForbidden());
                    }
        } finally {
            delete(system_index_plugin_not_existing);
        }
    }

    @Test
    public void deleteIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            createInitialTestObjects(index_bwx1);

            HttpResponse httpResponse = restClient.delete("index_bwx1");
            if (user.reference(MANAGE_INDEX).covers(index_bwx1)) {
                assertThat(httpResponse, isOk());
            } else {
                assertThat(httpResponse, isForbidden());
            }
        } finally {
            delete(index_bwx1);
        }
    }

    @Test
    public void deleteIndex_systemIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            createInitialTestObjects(system_index_plugin_not_existing);

            HttpResponse httpResponse = restClient.delete(".system_index_plugin_not_existing");

            if (clusterConfig.systemIndexPrivilegeEnabled && user.reference(MANAGE_INDEX).covers(system_index_plugin_not_existing)) {
                assertThat(httpResponse, isOk());
            } else if (user == SUPER_UNLIMITED_USER) {
                assertThat(httpResponse, isOk());
            } else {
                assertThat(httpResponse, isForbidden());
            }
        } finally {
            delete(system_index_plugin_not_existing);
        }
    }

    @Test
    public void createIndex_withAlias() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            HttpResponse httpResponse = restClient.putJson("index_bwx1", """
                {
                  "aliases": {
                    "alias_bwx": {}
                  }
                }""");

            if (clusterConfig.legacyPrivilegeEvaluation) {
                if (user.reference(MANAGE_ALIAS).covers(index_bwx1)) {
                    assertThat(httpResponse, isOk());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            } else {
                if (user.reference(MANAGE_ALIAS).coversAll(alias_bwx, index_bwx1)) {
                    assertThat(httpResponse, isOk());
                    assertThat(
                        httpResponse,
                        containsExactly(index_bwx1).at("index").reducedBy(user.reference(CREATE_INDEX)).whenEmpty(isForbidden())
                    );
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            }
        } finally {
            delete(index_bwx1);
        }
    }

    @Test
    public void deleteAlias_staticIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            createInitialTestObjects(alias_bwx.on(index_bw1));

            HttpResponse httpResponse = restClient.delete("index_bw1/_aliases/alias_bwx");

            if (clusterConfig.legacyPrivilegeEvaluation) {
                if (user.reference(MANAGE_ALIAS).covers(index_bw1) || user.reference(MANAGE_ALIAS).covers(alias_bwx)) {
                    assertThat(httpResponse, isOk());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            } else {
                if (user.reference(MANAGE_ALIAS).covers(alias_bwx)) {
                    assertThat(httpResponse, isOk());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            }

        } finally {
            delete(alias_bwx);
        }
    }

    @Test
    public void deleteAlias_wildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            createInitialTestObjects(alias_bwx.on(index_bw1));

            HttpResponse httpResponse = restClient.delete("*/_aliases/alias_bwx");

            if (clusterConfig.legacyPrivilegeEvaluation) {
                // This is only allowed if we have privileges for all indices, even if not all indices are member of alias_bwx
                if (user.reference(MANAGE_ALIAS).coversAll(ALL_NON_HIDDEN_INDICES)) {
                    assertThat(httpResponse, isOk());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            } else {
                if (user.reference(MANAGE_ALIAS).coversAll(alias_bwx)) {
                    assertThat(httpResponse, isOk());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            }
        } finally {
            delete(alias_bwx);
        }
    }

    @Test
    public void aliases_createAlias() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {

            HttpResponse httpResponse = restClient.postJson("_aliases", """
                {
                  "actions": [
                    { "add": { "index": "index_bw1", "alias": "alias_bwx" } }
                  ]
                }""");

            if (clusterConfig.legacyPrivilegeEvaluation) {
                if (user.reference(MANAGE_ALIAS).covers(index_bw1)) {
                    assertThat(httpResponse, isOk());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            } else {
                if (user.reference(MANAGE_ALIAS).coversAll(alias_bwx, index_bw1)) {
                    assertThat(httpResponse, isOk());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            }

        } finally {
            delete(alias_bwx);
        }
    }

    @Test
    public void aliases_createAlias_indexPattern() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            HttpResponse httpResponse = restClient.postJson("_aliases", """
                {
                  "actions": [
                    { "add": { "indices": ["index_bw*"], "alias": "alias_bwx" } }
                  ]
                }""");
            if (clusterConfig.legacyPrivilegeEvaluation) {
                if (user.reference(MANAGE_ALIAS).coversAll(index_bw1, index_bw2)) {
                    assertThat(httpResponse, isOk());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            } else {
                if (user.reference(MANAGE_ALIAS).coversAll(alias_bwx, index_bw1, index_bw2)) {
                    assertThat(httpResponse, isOk());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            }
        } finally {
            delete(alias_bwx);
        }
    }

    @Test
    public void aliases_deleteAlias_staticIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            createInitialTestObjects(alias_bwx.on(index_bw1));

            HttpResponse httpResponse = restClient.postJson("_aliases", """
                {
                  "actions": [
                    { "remove": { "index": "index_bw1", "alias": "alias_bwx" } }
                  ]
                }""");

            if (clusterConfig.legacyPrivilegeEvaluation) {
                if (user.reference(MANAGE_ALIAS).covers(index_bw1) || user.reference(MANAGE_ALIAS).covers(alias_bwx)) {
                    assertThat(httpResponse, isOk());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            } else {
                if (user.reference(MANAGE_ALIAS).covers(alias_bwx)) {
                    assertThat(httpResponse, isOk());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            }
        } finally {
            delete(alias_bwx);
        }
    }

    @Test
    public void aliases_deleteAlias_wildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            createInitialTestObjects(alias_bwx.on(index_bw1, index_bw2));

            HttpResponse httpResponse = restClient.postJson("_aliases", """
                {
                  "actions": [
                    { "remove": { "index": "*", "alias": "alias_bwx" } }
                  ]
                }""");

            if (clusterConfig.legacyPrivilegeEvaluation) {
                // This is only allowed if we have privileges for all indices, even if not all indices are member of alias_bwx
                if (user.reference(MANAGE_ALIAS).coversAll(ALL_NON_HIDDEN_INDICES)) {
                    assertThat(httpResponse, isOk());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            } else {
                if (user.reference(MANAGE_ALIAS).coversAll(alias_bwx)) {
                    assertThat(httpResponse, isOk());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            }

        } finally {
            delete(alias_bwx);
        }
    }

    @Test
    public void aliases_removeIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            createInitialTestObjects(index_bwx1);

            HttpResponse httpResponse = restClient.postJson("_aliases", """
                {
                  "actions": [
                    { "remove_index": { "index": "index_bwx1" } }
                  ]
                }""");

            if (user.reference(MANAGE_INDEX).covers(index_bwx1)) {
                assertThat(httpResponse, isOk());
            } else {
                assertThat(httpResponse, isForbidden());
            }
        } finally {
            delete(index_bwx1);
        }
    }

    @Test
    public void reindex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            HttpResponse httpResponse = restClient.postJson("_reindex", """
                {
                  "source": { "index": "index_br1" },
                  "dest": { "index": "index_bwx1" }
                }""");
            if (containsExactly(index_bwx1).reducedBy(user.reference(CREATE_INDEX)).isEmpty()) {
                assertThat(httpResponse, isForbidden());
                assertThat(cluster.getAdminCertRestClient().get("index_bwx1/_search"), isNotFound());
            } else {
                assertThat(httpResponse, isOk());
                assertThat(cluster.getAdminCertRestClient().get("index_bwx1/_search"), isOk());
            }
        } finally {
            delete(index_bwx1);
        }
    }

    @Test
    public void cloneIndex() throws Exception {
        String sourceIndex = "index_bw1";
        String targetIndex = "index_bwx1";

        Client client = cluster.getInternalNodeClient();
        client.admin()
            .indices()
            .updateSettings(new UpdateSettingsRequest(sourceIndex).settings(Settings.builder().put("index.blocks.write", true).build()))
            .actionGet();

        try (TestRestClient restClient = cluster.getRestClient(user)) {
            HttpResponse httpResponse = restClient.post(sourceIndex + "/_clone/" + targetIndex);
            assertThat(
                httpResponse,
                containsExactly(index_bwx1).at("index").reducedBy(user.reference(MANAGE_INDEX)).whenEmpty(isForbidden())
            );
        } finally {
            cluster.getInternalNodeClient()
                .admin()
                .indices()
                .updateSettings(
                    new UpdateSettingsRequest(sourceIndex).settings(Settings.builder().put("index.blocks.write", false).build())
                )
                .actionGet();
            delete(index_bwx1);
        }
    }

    @Test
    public void closeIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            HttpResponse httpResponse = restClient.post("index_bw1/_close");
            assertThat(
                httpResponse,
                containsExactly(index_bw1).at("indices.keys()").reducedBy(user.reference(MANAGE_INDEX)).whenEmpty(isForbidden())
            );
        } finally {
            cluster.getInternalNodeClient().admin().indices().open(new OpenIndexRequest("index_bw1")).actionGet();
        }
    }

    @Test
    public void closeIndex_wildcard() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            HttpResponse httpResponse = restClient.post("*/_close");

            if (clusterConfig.legacyPrivilegeEvaluation) {
                if (user.reference(MANAGE_INDEX).coversAll(ALL_NON_HIDDEN_INDICES)) {
                    assertThat(httpResponse, isOk());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            } else {
                if (!user.reference(MANAGE_INDEX).isEmpty()) {
                    assertThat(
                        httpResponse,
                        containsExactly(ALL_NON_HIDDEN_INDICES).at("indices.keys()")
                            .reducedBy(user.reference(MANAGE_INDEX))
                            .whenEmpty(isOk())
                    );
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            }
        } finally {
            cluster.getInternalNodeClient().admin().indices().open(new OpenIndexRequest("*")).actionGet();
        }
    }

    @Test
    public void closeIndex_openIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            HttpResponse httpResponse = restClient.post("index_bw1/_close");
            assertThat(
                httpResponse,
                containsExactly(index_bw1).at("indices.keys()").reducedBy(user.reference(MANAGE_INDEX)).whenEmpty(isForbidden())
            );
            httpResponse = restClient.post("index_bw1/_open");

            if (containsExactly(index_bw1).reducedBy(user.reference(MANAGE_INDEX)).isEmpty()) {
                assertThat(httpResponse, isForbidden());
            } else {
                assertThat(httpResponse, isOk());
            }
        } finally {
            cluster.getInternalNodeClient().admin().indices().open(new OpenIndexRequest("index_bw1")).actionGet();
        }
    }

    @Test
    public void rollover_explicitTargetIndex() throws Exception {
        try (TestRestClient restClient = cluster.getRestClient(user)) {
            createInitialTestObjects(alias_bwx.on(index_bw1).writeIndex(index_bw1));

            HttpResponse httpResponse = restClient.postJson("alias_bwx/_rollover/index_bwx1", """
                {
                  "conditions": {
                    "max_age": "0s"
                  }
                }""");

            System.out.println(httpResponse.getBody());

            if (clusterConfig.legacyPrivilegeEvaluation) {
                if (user.reference(MANAGE_ALIAS).covers(index_bw1) && user.reference(MANAGE_INDEX).covers(index_bw2)) {
                    assertThat(httpResponse, isOk());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            } else {
                if (user.reference(MANAGE_ALIAS).covers(alias_bwx) && user.reference(MANAGE_INDEX).covers(index_bw2)) {
                    assertThat(httpResponse, isOk());
                } else {
                    assertThat(httpResponse, isForbidden());
                }
            }
        } finally {
            delete(alias_bwx, index_bwx1);
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

    public IndexAuthorizationReadWriteIntTests(ClusterConfig clusterConfig, TestSecurityConfig.User user, String description)
        throws Exception {
        this.user = user;
        this.cluster = clusterConfig.cluster(IndexAuthorizationReadWriteIntTests::clusterBuilder);
        this.clusterConfig = clusterConfig;
    }

    private void createInitialTestObjects(TestIndexOrAliasOrDatastream... testIndexOrAliasOrDatastreamArray) {
        TestIndexOrAliasOrDatastream.createInitialTestObjects(cluster, testIndexOrAliasOrDatastreamArray);
    }

    private void delete(TestIndexOrAliasOrDatastream... testIndexOrAliasOrDatastreamArray) {
        TestIndexOrAliasOrDatastream.delete(cluster, testIndexOrAliasOrDatastreamArray);
    }

    private void delete(String... paths) {
        try (TestRestClient adminRestClient = cluster.getAdminCertRestClient()) {
            for (String path : paths) {
                HttpResponse response = adminRestClient.delete(path);
                if (response.getStatusCode() != 200 && response.getStatusCode() != 404) {
                    throw new RuntimeException("Error while deleting " + path + "\n" + response.getBody());
                }
            }
        }
    }
}
