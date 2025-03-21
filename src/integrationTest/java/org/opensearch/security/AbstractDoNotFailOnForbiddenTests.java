/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public abstract class AbstractDoNotFailOnForbiddenTests {

    /**
    * Songs accessible for {@link #LIMITED_USER}
    */
    protected static final String MARVELOUS_SONGS = "marvelous_songs";

    /**
    * Songs inaccessible for {@link #LIMITED_USER}
    */
    protected static final String HORRIBLE_SONGS = "horrible_songs";

    protected static final String BOTH_INDEX_PATTERN = "*songs";

    protected static final String ID_1 = "1";
    protected static final String ID_2 = "2";
    protected static final String ID_3 = "3";
    protected static final String ID_4 = "4";

    protected static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS);
    protected static final User LIMITED_USER = new User("limited_user").roles(
        new Role("limited-role").clusterPermissions(
            "indices:data/read/mget",
            "indices:data/read/msearch",
            "indices:data/read/scroll",
            "cluster:monitor/state",
            "cluster:monitor/health"
        )
            .indexPermissions(
                "indices:data/read/search",
                "indices:data/read/mget*",
                "indices:data/read/field_caps",
                "indices:data/read/field_caps*",
                "indices:data/read/msearch",
                "indices:data/read/scroll",
                "indices:monitor/settings/get",
                "indices:monitor/stats",
                "indices:admin/aliases/get"
            )
            .on(MARVELOUS_SONGS)
    );

    protected static final User STATS_USER = new User("stats_user").roles(
        new Role("test_role").clusterPermissions("cluster:monitor/*").indexPermissions("read", "indices:monitor/*").on("hi1")
    );

    protected static final String BOTH_INDEX_ALIAS = "both-indices";
    protected static final String FORBIDDEN_INDEX_ALIAS = "forbidden-index";

    private final LocalCluster cluster;

    protected AbstractDoNotFailOnForbiddenTests(LocalCluster cluster) {
        this.cluster = cluster;
    }
}
