/*
* Copyright OpenSearch Contributors
* SPDX-License-Identifier: Apache-2.0
*
* The OpenSearch Contributors require contributions made to
* this file be licensed under the Apache-2.0 license or a
* compatible open source license.
*
*/
package org.opensearch.security.http;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.apache.http.HttpStatus.SC_UNAUTHORIZED;
import static org.opensearch.security.http.BasicAuthTests.TEST_USER;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.DISABLED_AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.JWT_AUTH_DOMAIN;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class DisabledBasicAuthTests {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(DISABLED_AUTHC_HTTPBASIC_INTERNAL)
        .users(TEST_USER)
        .authc(JWT_AUTH_DOMAIN)
        .build();

    @Test
    public void shouldRespondWith401WhenCredentialsAreCorrectButBasicAuthIsDisabled() {
        try (TestRestClient client = cluster.getRestClient(TEST_USER)) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(SC_UNAUTHORIZED);
        }
    }
}
