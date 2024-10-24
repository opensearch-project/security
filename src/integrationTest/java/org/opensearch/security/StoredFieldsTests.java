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
import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.client.Client;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class StoredFieldsTests {
    static final TestSecurityConfig.User TEST_USER_MASKED_FIELDS = new TestSecurityConfig.User("test_user_masked_fields").roles(
        new TestSecurityConfig.Role("role_masked_fields").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .maskedFields("restricted")
            .on("test_index")
    );

    static final TestSecurityConfig.User TEST_USER_FLS = new TestSecurityConfig.User("test_user_fls").roles(
        new TestSecurityConfig.Role("role_fls").clusterPermissions("cluster_composite_ops_ro")
            .indexPermissions("read")
            .fls("~restricted")
            .on("test_index")
    );

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(TEST_USER_MASKED_FIELDS, TEST_USER_FLS)
        .build();

    @BeforeClass
    public static void createTestData() {
        try (Client client = cluster.getInternalNodeClient()) {
            CreateIndexResponse r = client.admin()
                .indices()
                .prepareCreate("test_index")
                .setMapping("raw", "type=keyword,store=true", "restricted", "type=keyword,store=true")
                .get();

            client.prepareIndex("test_index").setRefreshPolicy(IMMEDIATE).setSource("raw", "hello", "restricted", "boo!").get();
        }
    }

    @Test
    public void testStoredWithWithApplicableMaskedFieldRestrictions() {
        try (TestRestClient client = cluster.getRestClient(TEST_USER_MASKED_FIELDS)) {
            TestRestClient.HttpResponse normalSearchResponse = client.get("test_index/_search");
            Assert.assertFalse(normalSearchResponse.getBody().contains("boo!"));

            TestRestClient.HttpResponse fieldSearchResponse = client.postJson("test_index/_search", """
                {
                  "stored_fields": [
                    "raw",
                    "restricted"
                  ]
                }
                """);
            fieldSearchResponse.assertStatusCode(HttpStatus.SC_OK);
            Assert.assertTrue(fieldSearchResponse.getBody().contains("raw"));
            Assert.assertTrue(fieldSearchResponse.getBody().contains("hello"));
            Assert.assertTrue(fieldSearchResponse.getBody().contains("restricted"));
            Assert.assertFalse(fieldSearchResponse.getBody().contains("boo!"));
        }
    }

    @Test
    public void testStoredWithWithApplicableFlsRestrictions() {
        try (TestRestClient client = cluster.getRestClient(TEST_USER_FLS)) {
            TestRestClient.HttpResponse normalSearchResponse = client.get("test_index/_search");
            Assert.assertFalse(normalSearchResponse.getBody().contains("boo!"));

            TestRestClient.HttpResponse fieldSearchResponse = client.postJson("test_index/_search", """
                {
                  "stored_fields": [
                    "raw",
                    "restricted"
                  ]
                }
                """);
            fieldSearchResponse.assertStatusCode(HttpStatus.SC_OK);
            Assert.assertTrue(fieldSearchResponse.getBody().contains("raw"));
            Assert.assertTrue(fieldSearchResponse.getBody().contains("hello"));
            Assert.assertFalse(fieldSearchResponse.getBody().contains("restricted"));
            Assert.assertFalse(fieldSearchResponse.getBody().contains("boo!"));
        }
    }

}
