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

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.http.HttpStatus;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.TestSecurityConfig.Role;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class SecurityRolesTests {

    protected final static TestSecurityConfig.User USER_SR = new TestSecurityConfig.User("sr_user").roles(
        new Role("abc_ber").indexPermissions("*").on("*").clusterPermissions("*"),
        new Role("def_efg").indexPermissions("*").on("*").clusterPermissions("*")
    );

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .anonymousAuth(true)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_SR)
        .build();

    @Test
    public void testSecurityRoles() throws Exception {
        try (TestRestClient client = cluster.getRestClient(USER_SR)) {
            HttpResponse response = client.getAuthInfo();
            response.assertStatusCode(HttpStatus.SC_OK);

            // Check username
            assertThat(response.getTextFromJsonBody("/user_name"), equalTo("sr_user"));

            // Check security roles
            assertThat(response.getTextFromJsonBody("/roles/0"), equalTo("user_sr_user__abc_ber"));
            assertThat(response.getTextFromJsonBody("/roles/1"), equalTo("user_sr_user__def_efg"));

        }
    }

}
