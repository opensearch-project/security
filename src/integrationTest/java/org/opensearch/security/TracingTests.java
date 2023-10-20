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

import java.io.IOException;
import java.util.Map;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.common.util.FeatureFlags;
import org.opensearch.telemetry.TelemetrySettings;
import org.opensearch.test.framework.AuditCompliance;
import org.opensearch.test.framework.AuditConfiguration;
import org.opensearch.test.framework.AuditFilters;
import org.opensearch.test.framework.TestSecurityConfig.User;
import org.opensearch.test.framework.audit.AuditLogsRule;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.action.support.WriteRequest.RefreshPolicy.IMMEDIATE;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class TracingTests {

    private static final User ADMIN_USER = new User("admin").roles(ALL_ACCESS);

    @ClassRule
    public static final LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(ADMIN_USER)
        .nodeSettings(
            Map.of(
                FeatureFlags.TELEMETRY_SETTING.getKey(),
                true,
                TelemetrySettings.TRACER_FEATURE_ENABLED_SETTING.getKey(),
                true,
                TelemetrySettings.METRICS_FEATURE_ENABLED_SETTING.getKey(),
                true
            )
        )
        .build();

    @Rule
    public AuditLogsRule auditLogsRule = new AuditLogsRule();

    @Test
    public void indexDocumentAndSearch() throws IOException {
        try (Client internalClient = cluster.getInternalNodeClient()) {
            // Create a document to search
            internalClient.prepareIndex("index-1").setRefreshPolicy(IMMEDIATE).setSource(Map.of("foo", "bar")).get();
        }

        try (final RestHighLevelClient restClient = cluster.getRestHighLevelClient(ADMIN_USER)) {
            final SearchResponse response = restClient.search(new SearchRequest(), DEFAULT);
            assertThat(response.getHits().getTotalHits().value, equalTo(1L));
        }
    }
}
