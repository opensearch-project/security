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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.awaitility.Awaitility;
import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.test.framework.AuditCompliance;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;

import static org.hamcrest.Matchers.containsString;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.User.USER_ADMIN;

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
            Awaitility.await()
                .alias("Load configuration")
                .until(() -> client.get("_cat/indices").getBody(), containsString("green open security-auditlog"));
        }
    }
}
