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

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.data.TestIndex;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;

public class IndexResolverReplacerAliasScaleIntegTests {

    private static final int ALIAS_COUNT = 5_000;
    private static final int EXACT_REQUEST_COUNT = 100;
    private static final int PREFIX_REQUEST_COUNT = 25;
    private static final String INDEX = "alias-scale-index";
    private static final String ALIAS_PREFIX = "alias-scale-";

    private static final TestIndex TEST_INDEX = TestIndex.name(INDEX).documentCount(1).build();
    private static final TestSecurityConfig.User READER = new TestSecurityConfig.User("alias_scale_reader").roles(
        new Role("alias_scale_reader_role").indexPermissions("read").on(INDEX, ALIAS_PREFIX + "*")
    );

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(READER, TestSecurityConfig.User.USER_ADMIN)
        .indices(TEST_INDEX)
        .build();

    @BeforeClass
    public static void createAliasHeavyClusterState() {
        StringBuilder body = new StringBuilder(ALIAS_COUNT * 80).append("{\"actions\":[");
        for (int i = 0; i < ALIAS_COUNT; i++) {
            if (i != 0) {
                body.append(',');
            }
            body.append("{\"add\":{\"index\":\"").append(INDEX).append("\",\"alias\":\"").append(ALIAS_PREFIX).append(i).append("\"}}");
        }
        body.append("]}");

        try (TestRestClient adminClient = cluster.getAdminCertRestClient()) {
            assertThat(adminClient.postJson("_aliases", body.toString()), isOk());
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
                assertThat("Request " + i + " for " + indexExpression, client.get(indexExpression + "/_search?size=0"), isOk());
            }
        }
    }
}
