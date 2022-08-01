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

package org.opensearch.test;

import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

import org.apache.http.HttpStatus;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensearch.test.framework.TestIndex;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.ClusterConfiguration;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

/**
 * WIP
 * Generic test class that demonstrates how to use the test framework to 
 * set up a test cluster with users, roles, indices and data, and how to
 * implement tests. One main goal here is to make tests self-contained.
 */
@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class GenericIntegrationTest {
	    
    // define indices used in this test
    private final static TestIndex INDEX_A = TestIndex.name("index-a").build();
    private final static TestIndex INDEX_B = TestIndex.name("index-b").build();
    
    private final static TestSecurityConfig.User INDEX_A_USER = new TestSecurityConfig.User("index_a_user")
            .roles(new Role("index_a_role").indexPermissions("*").on(INDEX_A).clusterPermissions("*"));


    // build our test cluster as a ClassRule
    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterConfiguration(ClusterConfiguration.THREE_MASTERS)
    	.authc(AUTHC_HTTPBASIC_INTERNAL)
    	.users(INDEX_A_USER)
    	.indices(INDEX_A, INDEX_B).build();

    @Test
    public void testAdminUserHasAccessToAllIndices() throws Exception {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            HttpResponse response = client.get("*/_search?pretty");
            Assert.assertEquals(response.getStatusCode(), HttpStatus.SC_OK);
        }        
    }

    @Test
    public void testIndexAUserHasOnlyAccessToIndexA() throws Exception {
        try (TestRestClient client = cluster.getRestClient(INDEX_A_USER)) {
            HttpResponse response = client.get("index-a/_search?pretty");
            Assert.assertEquals(response.getStatusCode(), HttpStatus.SC_OK);
            
            // demo: work with JSON response body and check values
            int hits = response.getIntFromJsonBody("/_source/hits/value");
            Assert.assertEquals(0, hits);
            
            response = client.get("index-b/_search?pretty");
            Assert.assertEquals(response.getStatusCode(), HttpStatus.SC_FORBIDDEN);                       
        }
    }    
    
    @AfterClass
    public static void close() {
    	cluster.close();
    }
}
