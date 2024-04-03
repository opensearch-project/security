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
import org.apache.http.HttpHeaders;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.test.framework.cluster.TestRestClient.HttpResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL_WITHOUT_CHALLENGE;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class BasicAuthWithoutChallengeTests {

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL_WITHOUT_CHALLENGE)
        .build();

    @Test
    public void browserShouldNotRequestUserForCredentials() {
        try (TestRestClient client = cluster.getRestClient()) {

            HttpResponse response = client.getAuthInfo();

            response.assertStatusCode(401);
            assertThatBrowserDoesNotAskUserForCredentials(response);
        }
    }

    private void assertThatBrowserDoesNotAskUserForCredentials(HttpResponse response) {
        String reason = "Browser asked user for credentials which is not expected";
        assertThat(reason, response.containHeader(HttpHeaders.WWW_AUTHENTICATE), equalTo(false));
    }
}
