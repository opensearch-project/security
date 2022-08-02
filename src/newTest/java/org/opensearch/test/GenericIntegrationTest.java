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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

import org.apache.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensearch.test.framework.TestIndex;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

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
    public static LocalCluster cluster = new LocalCluster.Builder().clusterConfiguration(ClusterManager.THREE_MASTERS)
    	.authc(AUTHC_HTTPBASIC_INTERNAL)
    	.users(USER_ADMIN, INDEX_A_USER)
    	.indices(INDEX_A, INDEX_B).build();

    @Test
    public void testAdminUserHasAccessToAllIndices() throws Exception {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
			assertThat(client.get("*/_search?pretty").getStatusCode(), equalTo(HttpStatus.SC_OK));
        }        
    }

    @Test
    public void testIndexAUserHasOnlyAccessToIndexA() throws Exception {
        try (TestRestClient client = cluster.getRestClient(INDEX_A_USER)) {        	
			assertThat(client.get("index-a/_search?pretty").getStatusCode(), equalTo(HttpStatus.SC_OK));            
            // demo: work with JSON response body and check values
			assertThat(client.get("index-a/_search?pretty").getIntFromJsonBody("/_source/hits/value"), equalTo(0));            
			assertThat(client.get("index-b/_search?pretty"), equalTo(HttpStatus.SC_FORBIDDEN));
        }
    }    
    
}
