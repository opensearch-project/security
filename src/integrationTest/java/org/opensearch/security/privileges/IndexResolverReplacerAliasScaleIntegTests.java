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

package org.opensearch.security.privileges;

import com.carrotsearch.randomizedtesting.RandomizedRunner;
import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.client.Client;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.action.admin.indices.alias.IndicesAliasesRequest.AliasActions.Type.ADD;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

/**
 * End-to-end check that requests targeting a single exact alias or a simple prefix remain healthy when the cluster
 * holds a very large number of aliases (the SentinelOne V2286487402 shape). This exercises the real transport path
 * through {@link org.opensearch.security.resolver.IndexResolverReplacer} rather than the unit-level helper.
 */
@RunWith(RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class IndexResolverReplacerAliasScaleIntegTests {

    private static final int ALIAS_COUNT = 5_000;
    private static final int EXACT_REQUEST_COUNT = 100;
    private static final int PREFIX_REQUEST_COUNT = 25;
    private static final String INDEX = "alias-scale-index";
    private static final String ALIAS_PREFIX = "alias-scale-";

    private static final TestSecurityConfig.User READER = new TestSecurityConfig.User("alias_scale_reader").roles(
        new Role("alias_scale_reader_role").indexPermissions("read").on(INDEX, ALIAS_PREFIX + "*")
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(READER, TestSecurityConfig.User.USER_ADMIN)
        .build();

    @BeforeClass
    public static void createAliasHeavyClusterState() {
        try (Client client = cluster.getInternalNodeClient()) {
            client.admin().indices().create(new CreateIndexRequest(INDEX)).actionGet();

            // Add all aliases in a single request so cluster state is updated once.
            IndicesAliasesRequest request = new IndicesAliasesRequest();
            for (int i = 0; i < ALIAS_COUNT; i++) {
                request.addAliasAction(new AliasActions(ADD).indices(INDEX).alias(ALIAS_PREFIX + i));
            }
            client.admin().indices().aliases(request).actionGet();
        }
    }

    @Test
    public void repeatedExactConcreteIndexRequestsWithManyAliases() {
        assertRepeatedSearches(INDEX, EXACT_REQUEST_COUNT);
    }

    @Test
    public void repeatedExactAliasRequestsWithManyAliases() {
        assertRepeatedSearches(ALIAS_PREFIX + (ALIAS_COUNT - 1), EXACT_REQUEST_COUNT);
    }

    @Test
    public void repeatedPrefixAliasRequestsWithManyAliases() {
        assertRepeatedSearches(ALIAS_PREFIX + "49*", PREFIX_REQUEST_COUNT);
    }

    private static void assertRepeatedSearches(String indexExpression, int requestCount) {
        try (TestRestClient client = cluster.getRestClient(READER)) {
            for (int i = 0; i < requestCount; i++) {
                TestRestClient.HttpResponse response = client.get(indexExpression + "/_search?size=0");
                assertThat("Request " + i + " for " + indexExpression, response.getStatusCode(), equalTo(200));
            }
        }
    }
}
