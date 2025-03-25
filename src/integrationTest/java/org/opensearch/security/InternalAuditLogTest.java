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

import java.time.Duration;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.test.framework.AuditCompliance;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class InternalAuditLogTest {

    private static final Logger log = LogManager.getLogger(InternalAuditLogTest.class);

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .anonymousAuth(false)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(USER_ADMIN)
        .internalAudit(
            new AuditConfiguration(true).compliance(new AuditCompliance().enabled(true))
                .filters(new AuditFilters().enabledRest(true).enabledTransport(true))
        )
        .build();

    @Test
    public void testAuditLogShouldBeGreenInSingleNodeCluster() throws InterruptedException {
        try (TestRestClient client = cluster.getRestClient(USER_ADMIN)) {
            client.get(""); // demo request for insuring audit-log index is created beforehand
            int retriesLeft = 5;
            while (retriesLeft > 0) {
                retriesLeft = retriesLeft - 1;
                try {
                    TestRestClient.HttpResponse indicesResponse = client.get("_cat/indices");
                    assertThat(indicesResponse.getBody(), containsString("security-auditlog"));
                    assertThat(indicesResponse.getBody(), containsString("green"));
                    break;
                } catch (AssertionError e) {
                    if (retriesLeft == 0) {
                        throw e;
                    }
                    Thread.sleep(Duration.ofSeconds(1));
                }
            }
        }
    }
}
